/* Interleaved A/B harness for two builds of engine.c (development tool).
 *
 * The same workload is run alternately through two engines linked into one
 * process:
 *
 *   A = the engine under test (core/src/engine.c, canonical symbols)
 *   B = a reference build of engine.c, compiled with
 *       -include bench/engine_v2_rename.h so its API is suffixed _v2
 *
 * Rounds alternate A/B at 1M-packet granularity, so both variants observe the
 * same host conditions (a noisy hypervisor neighbour inflates whole seconds of
 * measurements, which makes cross-process A/B only reproducible to tens of
 * percent).  Each round is timed with the invariant TSC; the per-round paired
 * ratios are what the report quotes.
 *
 *   make -C core ab AB_BASELINE=/path/to/reference/engine.c
 *   TR_AB_BLOCKS=1000 taskset -c 0 core/../../build/core/engine_ab
 *
 * With TR_AB_DROP=1 the packets are built and freed without touching an
 * engine, which measures the harness floor (packet construction plus free)
 * so engine-only costs can be derived from the totals.  With TR_AB_SINGLE=1
 * each packet is submitted through the single-packet API instead of the
 * 32-packet burst API (the shape used by engine_bench's "single" mode).
 *
 * Both engines process the same 64-byte IPv4 frames with an ARP-resolved next
 * hop in 32-packet bursts, exactly like engine_bench's burst mode.
 */
#include "config.h"
#include "engine.h"
#include "tunnel.h"
#include "util.h"

#include <arpa/inet.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The reference variant.  Prototypes mirror engine.h with the _v2 suffix;
 * keep in sync with bench/engine_v2_rename.h. */
struct tr_engine_params_v2 {
    int n_ports;
    int workers;
    struct rte_mempool *mp;
};
void tr_engine_set_tx_v2(void *e, tr_tx_fn tx, void *arg);
struct tr_engine *tr_engine_create_v2(const struct tr_engine_params_v2 *p,
                                      char *err, size_t errlen);
void tr_engine_destroy_v2(struct tr_engine *e);
int tr_engine_apply_v2(struct tr_engine *e, const struct tr_config *cfg,
                       char *err, size_t errlen);
int tr_engine_config_copy_v2(struct tr_engine *e, struct tr_config *out);
int tr_engine_input_v2(struct tr_engine *e, int worker, int if_slot,
                       struct rte_mbuf *m);
int tr_engine_input_burst_v2(struct tr_engine *e, int worker, int if_slot,
                             struct rte_mbuf **mbufs, uint16_t n);

#define AB_BLOCKS 200
#define AB_BATCH 32
#define AB_BURSTS_PER_BLOCK 1000   /* 32k packets ~ 4 ms of work */
#define AB_FRAME_LEN 64

struct tx_acc {
    uint64_t packets;
};

static uint8_t frame_template[AB_FRAME_LEN];

static void tx_count(void *arg, int worker, int if_slot, struct rte_mbuf *m)
{
    (void)worker;
    (void)if_slot;
    ((struct tx_acc *)arg)->packets++;
    rte_pktmbuf_free(m);
}

static int apply(struct tr_config *cfg, const struct tr_config_env *env,
                 const char *line)
{
    char buf[256];
    char *argv[32];
    char err[256];
    int argc;

    snprintf(buf, sizeof(buf), "%s", line);
    argc = tr_split(buf, argv, 32);
    if (tr_config_apply(cfg, env, argc, argv, err, sizeof(err))) {
        fprintf(stderr, "%s: %s\n", line, err);
        return -1;
    }
    return 0;
}

static void fill_frame(uint8_t *p)
{
    static const uint8_t dmac[6] = {0x02, 0, 0, 0, 0, 1};
    static const uint8_t smac[6] = {0x02, 0, 0, 0, 0, 2};
    uint16_t sum;

    memset(p, 0, AB_FRAME_LEN);
    memcpy(p, dmac, 6);
    memcpy(p + 6, smac, 6);
    p[12] = 0x08;
    p[13] = 0;
    p[14] = 0x45;
    p[16] = 0;
    p[17] = 44;
    p[22] = 64;
    p[23] = 17;
    p[26] = 192;
    p[27] = 0;
    p[28] = 2;
    p[29] = 2;
    p[30] = 198;
    p[31] = 51;
    p[32] = 100;
    p[33] = 2;
    sum = tr_checksum16(p + 14, 20, 0);
    p[24] = (uint8_t)(sum >> 8);
    p[25] = (uint8_t)sum;
}

static inline struct rte_mbuf *make_packet(struct rte_mempool *mp)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(mp);

    if (!m)
        return NULL;
    if (!rte_pktmbuf_append(m, AB_FRAME_LEN)) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    memcpy(rte_pktmbuf_mtod(m, uint8_t *), frame_template, AB_FRAME_LEN);
    return m;
}

static inline uint64_t tsc_read(void)
{
    uint32_t lo, hi;

    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* Teach the neighbour cache 198.51.100.2 -> peer MAC by injecting an ARP
 * reply on the eth1 side, exactly like engine_bench does. */
static int teach_arp(struct tr_engine *e, struct rte_mempool *mp, int eth1,
                     int ref)
{
    const uint8_t eth1_mac[6] = {0x02, 0, 0, 0, 0, 2};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0xbb};
    struct rte_mbuf *arp = rte_pktmbuf_alloc(mp);
    uint8_t *p;

    if (!arp || !rte_pktmbuf_append(arp, 42))
        return -1;
    p = rte_pktmbuf_mtod(arp, uint8_t *);
    memset(p, 0, 42);
    memcpy(p, eth1_mac, 6);
    memcpy(p + 6, peer_mac, 6);
    p[12] = 0x08;
    p[13] = 0x06;
    p[15] = 1;
    p[16] = 0x08;
    p[18] = 6;
    p[19] = 4;
    p[21] = 2;
    memcpy(p + 22, peer_mac, 6);
    inet_pton(AF_INET, "198.51.100.2", p + 28);
    memcpy(p + 32, eth1_mac, 6);
    inet_pton(AF_INET, "198.51.100.1", p + 38);
    return ref ? tr_engine_input_v2(e, 0, eth1, arp)
               : tr_engine_input(e, 0, eth1, arp);
}

static int run_bursts(struct tr_engine *e, int ref, struct rte_mempool *mp,
                      int eth0, int bursts, bool single, uint64_t *cycles)
{
    uint64_t t0 = tsc_read();

    for (int i = 0; i < bursts; i++) {
        struct rte_mbuf *bufs[AB_BATCH];
        for (int j = 0; j < AB_BATCH; j++) {
            bufs[j] = make_packet(mp);
            if (!bufs[j])
                return -1;
        }
        if (ref == 2) {
            for (int j = 0; j < AB_BATCH; j++)
                rte_pktmbuf_free(bufs[j]);
        } else if (ref) {
            if (single) {
                for (int j = 0; j < AB_BATCH; j++)
                    tr_engine_input_v2(e, 0, eth0, bufs[j]);
            } else {
                tr_engine_input_burst_v2(e, 0, eth0, bufs, AB_BATCH);
            }
        } else if (single) {
            for (int j = 0; j < AB_BATCH; j++)
                tr_engine_input(e, 0, eth0, bufs[j]);
        } else {
            tr_engine_input_burst(e, 0, eth0, bufs, AB_BATCH);
        }
    }
    *cycles = tsc_read() - t0;
    return 0;
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;

    return x < y ? -1 : x > y;
}

int main(void)
{
    char *eal_argv[] = {"engine_ab", "--no-huge", "--no-pci", "--lcores",
                        "0",         "-m",        "512",        NULL};
    char err[256];
    struct rte_mempool *mp;
    struct tr_config cfg;
    struct tr_config env_cfg;
    struct tr_config_env env;
    struct tx_acc tx_a = {0}, tx_b = {0};
    int blocks = AB_BLOCKS;
    int bursts = AB_BURSTS_PER_BLOCK;
    const char *e;
    bool drop_mode = getenv("TR_AB_DROP") && atoi(getenv("TR_AB_DROP")) != 0;
    bool single = getenv("TR_AB_SINGLE") && atoi(getenv("TR_AB_SINGLE")) != 0;
    uint64_t pkts_per_variant, cyc_a_total = 0, cyc_b_total = 0;

    if ((e = getenv("TR_AB_BLOCKS")) && atoi(e) > 0)
        blocks = atoi(e);
    if ((e = getenv("TR_AB_BURSTS")) && atoi(e) > 0)
        bursts = atoi(e);
    pkts_per_variant = (uint64_t)blocks * (uint64_t)bursts * AB_BATCH;
    double *a_cpp = calloc((size_t)blocks, sizeof(double));
    double *b_cpp = calloc((size_t)blocks, sizeof(double));
    double *ratio = calloc((size_t)blocks, sizeof(double));
    if (!a_cpp || !b_cpp || !ratio)
        return 1;

    if (rte_eal_init(7, eal_argv) < 0) {
        fprintf(stderr, "EAL init failed\n");
        return 1;
    }
    if (tr_tunnel_drivers_init())
        return 1;
    mp = rte_pktmbuf_pool_create("ab_pool", 16384, 256, 0, 2048,
                                 rte_socket_id());
    if (!mp) {
        fprintf(stderr, "mempool: %s\n", rte_strerror(rte_errno));
        return 1;
    }
    fill_frame(frame_template);
    tr_config_init(&cfg);
    env.n_ports = 2;
    env.port_valid = NULL;
    env.port_names = NULL;
    const char *cmds[] = {
        "set interfaces ethernet eth0 port 0",
        "set interfaces ethernet eth0 address 192.0.2.1/24",
        "set interfaces ethernet eth1 port 1",
        "set interfaces ethernet eth1 address 198.51.100.1/24",
        NULL,
    };
    for (int i = 0; cmds[i]; i++)
        if (apply(&cfg, &env, cmds[i]))
            return 1;
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t eth1_mac[6] = {0x02, 0, 0, 0, 0, 2};
    memcpy(tr_config_find(&cfg, "eth0")->mac, eth0_mac, 6);
    memcpy(tr_config_find(&cfg, "eth1")->mac, eth1_mac, 6);

    struct tr_engine_params params = {.n_ports = 2, .workers = 1, .mp = mp};
    struct tr_engine_params_v2 params_v2 = {.n_ports = 2, .workers = 1,
                                            .mp = mp};
    struct tr_engine *ea = tr_engine_create(&params, err, sizeof(err));
    struct tr_engine *eb = tr_engine_create_v2(&params_v2, err, sizeof(err));
    if (!ea || !eb) {
        fprintf(stderr, "engine: %s\n", err);
        return 1;
    }
    tr_engine_set_tx(ea, tx_count, &tx_a);
    tr_engine_set_tx_v2(eb, tx_count, &tx_b);
    if (tr_engine_apply(ea, &cfg, err, sizeof(err)) ||
        tr_engine_apply_v2(eb, &cfg, err, sizeof(err))) {
        fprintf(stderr, "apply: %s\n", err);
        return 1;
    }
    tr_engine_config_copy(ea, &env_cfg);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;
    int eth1 = tr_config_find_const(&env_cfg, "eth1")->slot;
    if (teach_arp(ea, mp, eth1, 0) || teach_arp(eb, mp, eth1, 1))
        return 1;

    /* Warm both variants (code paths, caches, branch predictors). */
    for (int i = 0; i < 100000; i++) {
        struct rte_mbuf *m = make_packet(mp);
        if (!m)
            return 1;
        tr_engine_input(ea, 0, eth0, m);
        m = make_packet(mp);
        if (!m)
            return 1;
        tr_engine_input_v2(eb, 0, eth0, m);
    }

    const uint64_t block_pkts = (uint64_t)bursts * AB_BATCH;

    for (int r = 0; r < blocks; r++) {
        uint64_t ca, cb;

        /* Flip the order every block so position-in-pair bias cancels. */
        int mode_b = drop_mode ? 2 : 1;
        if (r % 2 == 0) {
            if (run_bursts(ea, 0, mp, eth0, bursts, single, &ca) ||
                run_bursts(eb, mode_b, mp, eth0, bursts, single, &cb))
                return 1;
        } else {
            if (run_bursts(eb, mode_b, mp, eth0, bursts, single, &cb) ||
                run_bursts(ea, 0, mp, eth0, bursts, single, &ca))
                return 1;
        }
        cyc_a_total += ca;
        cyc_b_total += cb;
        a_cpp[r] = (double)ca / block_pkts;
        b_cpp[r] = (double)cb / block_pkts;
        ratio[r] = b_cpp[r] / a_cpp[r];
    }

    double *sorted = calloc((size_t)blocks, sizeof(double));
    memcpy(sorted, a_cpp, sizeof(double) * (size_t)blocks);
    qsort(sorted, (size_t)blocks, sizeof(double), cmp_double);
    double a_min = sorted[0], a_med = sorted[blocks / 2];
    memcpy(sorted, b_cpp, sizeof(double) * (size_t)blocks);
    qsort(sorted, (size_t)blocks, sizeof(double), cmp_double);
    double b_min = sorted[0], b_med = sorted[blocks / 2];
    memcpy(sorted, ratio, sizeof(double) * (size_t)blocks);
    qsort(sorted, (size_t)blocks, sizeof(double), cmp_double);
    double r_min = sorted[0], r_med = sorted[blocks / 2];
    double r_p20 = sorted[blocks / 5], r_p80 = sorted[(blocks * 4) / 5];

    printf("A (under test): min %.1f  median %.1f cyc/pkt\n", a_min, a_med);
    printf("B (reference) : min %.1f  median %.1f cyc/pkt\n", b_min, b_med);
    printf("B/A per-block ratio: median %.4f  p20 %.4f  p80 %.4f  "
           "min %.4f  max %.4f\n",
           r_med, r_p20, r_p80, r_min, sorted[blocks - 1]);
    printf("B/A over %llu pkts per variant: %.4f  "
           "(A %.1f, B %.1f tsc-cyc/pkt)\n",
           (unsigned long long)pkts_per_variant,
           (double)cyc_b_total / (double)cyc_a_total,
           (double)cyc_a_total / (double)pkts_per_variant,
           (double)cyc_b_total / (double)pkts_per_variant);
    printf("tx packets: A %llu  B %llu\n", (unsigned long long)tx_a.packets,
           (unsigned long long)tx_b.packets);
    free(a_cpp);
    free(b_cpp);
    free(ratio);
    free(sorted);
    tr_engine_destroy(ea);
    tr_engine_destroy_v2(eb);
    rte_mempool_free(mp);
    tr_tunnel_drivers_fini();
    rte_eal_cleanup();
    return 0;
}
