/* Synthetic single-worker forwarding benchmark.
 *
 * It measures the engine with an already-resolved IPv4 next hop:
 *
 *   1,000,000 packets per round: eth0 -> route lookup -> eth1
 *
 * Two modes are measured:
 *
 *   single : tr_engine_input() per packet (one mbuf built per packet)
 *   burst  : tr_engine_input_burst() in groups of 32, the shape used by the
 *            DPDK worker loop (mbufs still built per packet)
 *
 * The packet construction cost is identical in both modes, so the burst mode
 * is the one that reflects the data plane; the difference between the two is
 * the per-call overhead of the single-packet API.
 *
 * Measurement notes
 * -----------------
 * This runs on shared/virtualised hardware where the core clock drifts, so
 * wall-clock Mpps alone is not comparable between runs.  Cycles/packet are
 * taken from the invariant TSC, and the modes are interleaved over several
 * rounds with the best round reported, which discards rounds perturbed by
 * external interference.  Compare builds with "cyc/pkt".
 *
 * This is not a NIC benchmark.  Run it after `make` with `make bench`.
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

#define BENCH_TOTAL 1000000
#define BENCH_ROUNDS 5
#define BENCH_WARMUP 100000
#define BENCH_BATCH 32
#define BENCH_FRAME_LEN 64

struct capture_count {
    uint64_t packets;
};

static uint8_t frame_template[BENCH_FRAME_LEN];

static void tx_count(void *arg, int worker, int if_slot, struct rte_mbuf *m)
{
    (void)worker;
    (void)if_slot;
    ((struct capture_count *)arg)->packets++;
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

/* Fill a 64-byte frame: 192.0.2.2 -> 198.51.100.2, UDP.  The IPv4 header
 * checksum is valid, so the engine's RX verification exercises the real
 * path. */
static void fill_frame(uint8_t *p)
{
    static const uint8_t dmac[6] = {0x02, 0, 0, 0, 0, 1};
    static const uint8_t smac[6] = {0x02, 0, 0, 0, 0, 2};
    uint16_t sum;

    memset(p, 0, BENCH_FRAME_LEN);
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

static struct rte_mbuf *make_packet(struct rte_mempool *mp)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
    if (!m)
        return NULL;
    if (!rte_pktmbuf_append(m, BENCH_FRAME_LEN)) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    memcpy(rte_pktmbuf_mtod(m, uint8_t *), frame_template, BENCH_FRAME_LEN);
    return m;
}

static double mono_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static inline uint64_t tsc_read(void)
{
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static void report(const char *tag, int total, double dt, uint64_t cycles,
                   double *best)
{
    double cpp = (double)cycles / total;
    if (*best == 0 || cpp < *best)
        *best = cpp;
    printf("%s %d pkts  %.3f s  %6.2f Mpps  %6.1f cyc/pkt\n", tag, total, dt,
           total / dt / 1e6, cpp);
}

static int run_single(struct tr_engine *e, int if_slot, struct rte_mempool *mp,
                      int total, double *best)
{
    uint64_t t0 = tsc_read();
    double w0 = mono_seconds();
    for (int i = 0; i < total; i++) {
        struct rte_mbuf *m = make_packet(mp);
        if (!m)
            return -1;
        tr_engine_input(e, 0, if_slot, m);
    }
    double dt = mono_seconds() - w0;
    report("single:", total, dt, tsc_read() - t0, best);
    return 0;
}

static int run_burst(struct tr_engine *e, int if_slot, struct rte_mempool *mp,
                     int total, double *best)
{
    uint64_t t0 = tsc_read();
    double w0 = mono_seconds();
    for (int i = 0; i < total; i += BENCH_BATCH) {
        struct rte_mbuf *bufs[BENCH_BATCH];
        for (int j = 0; j < BENCH_BATCH; j++) {
            bufs[j] = make_packet(mp);
            if (!bufs[j])
                return -1;
        }
        tr_engine_input_burst(e, 0, if_slot, bufs, BENCH_BATCH);
    }
    double dt = mono_seconds() - w0;
    report("burst: ", total, dt, tsc_read() - t0, best);
    return 0;
}

int main(void)
{
    char *eal_argv[] = {"engine_bench", "--no-huge", "--no-pci", "--lcores",
                        "0",            "-m",         "512",       NULL};
    char err[256];
    struct rte_mempool *mp;
    struct tr_config cfg;
    struct tr_config env_cfg;
    struct tr_config_env env;
    struct capture_count cap = {0};
    double best_single = 0, best_burst = 0;

    if (rte_eal_init(7, eal_argv) < 0) {
        fprintf(stderr, "EAL init failed\n");
        return 1;
    }
    if (tr_tunnel_drivers_init())
        return 1;
    mp = rte_pktmbuf_pool_create("bench_pool", 16384, 256, 0, 2048,
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
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0xbb};
    memcpy(tr_config_find(&cfg, "eth0")->mac, eth0_mac, 6);
    memcpy(tr_config_find(&cfg, "eth1")->mac, eth1_mac, 6);

    struct tr_engine *engine =
        tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    if (!engine) {
        fprintf(stderr, "engine: %s\n", err);
        return 1;
    }
    tr_engine_set_tx(engine, tx_count, &cap);
    if (tr_engine_apply(engine, &cfg, err, sizeof(err))) {
        fprintf(stderr, "apply: %s\n", err);
        return 1;
    }
    tr_engine_config_copy(engine, &env_cfg);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;
    int eth1 = tr_config_find_const(&env_cfg, "eth1")->slot;

    /* Teach the neighbor cache 198.51.100.2 -> peer_mac. */
    struct rte_mbuf *arp = rte_pktmbuf_alloc(mp);
    if (!arp || !rte_pktmbuf_append(arp, 42))
        return 1;
    uint8_t *p = rte_pktmbuf_mtod(arp, uint8_t *);
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
    tr_engine_input(engine, 0, eth1, arp);

    for (int i = 0; i < BENCH_WARMUP; i++) {
        struct rte_mbuf *m = make_packet(mp);
        if (!m)
            return 1;
        tr_engine_input(engine, 0, eth0, m);
    }

    /* Interleave the modes so that frequency drift and external interference
     * are shared between them; report the best round of each. */
    for (int round = 0; round < BENCH_ROUNDS; round++) {
        printf("-- round %d/%d\n", round + 1, BENCH_ROUNDS);
        if (run_single(engine, eth0, mp, BENCH_TOTAL, &best_single))
            return 1;
        if (run_burst(engine, eth0, mp, BENCH_TOTAL, &best_burst))
            return 1;
    }
    printf("== best of %d interleaved rounds (cyc/pkt, lower is better)\n",
           BENCH_ROUNDS);
    printf("single: %.1f\n", best_single);
    printf("burst:  %.1f\n", best_burst);
    printf("tx packets: %llu\n", (unsigned long long)cap.packets);

    tr_engine_destroy(engine);
    rte_mempool_free(mp);
    tr_tunnel_drivers_fini();
    rte_eal_cleanup();
    return 0;
}
