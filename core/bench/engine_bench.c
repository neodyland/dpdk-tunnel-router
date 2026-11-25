/* Synthetic single-worker forwarding benchmark.
 *
 * It measures the engine (including per-packet mbuf construction) with an
 * already-resolved IPv4 next hop:
 *
 *   2,000,000 packets: eth0 -> route lookup -> eth1
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

struct capture_count {
    uint64_t packets;
};

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

static struct rte_mbuf *make_packet(struct rte_mempool *mp)
{
    static const uint8_t dmac[6] = {0x02, 0, 0, 0, 0, 1};
    static const uint8_t smac[6] = {0x02, 0, 0, 0, 0, 2};
    struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
    if (!m)
        return NULL;
    if (!rte_pktmbuf_append(m, 64)) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    uint8_t *p = rte_pktmbuf_mtod(m, uint8_t *);
    memset(p, 0, 64);
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
    uint32_t sum = 0;
    for (int i = 14; i < 34; i += 2)
        sum += (uint32_t)(p[i] << 8) | p[i + 1];
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum;
    p[24] = (uint8_t)(sum >> 8);
    p[25] = (uint8_t)sum;
    return m;
}

static double mono_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
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
    const int total = 2000000;
    const int warmup = 100000;

    if (rte_eal_init(7, eal_argv) < 0) {
        fprintf(stderr, "EAL init failed\n");
        return 1;
    }
    if (tr_tunnel_drivers_init())
        return 1;
    mp = rte_pktmbuf_pool_create("bench_pool", 8192, 256, 0, 2048,
                                 rte_socket_id());
    if (!mp) {
        fprintf(stderr, "mempool: %s\n", rte_strerror(rte_errno));
        return 1;
    }
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

    double t0, dt;
    for (int i = 0; i < warmup; i++) {
        struct rte_mbuf *m = make_packet(mp);
        if (!m)
            return 1;
        tr_engine_input(engine, 0, eth0, m);
    }
    cap.packets = 0;
    t0 = mono_seconds();
    for (int i = 0; i < total; i++) {
        struct rte_mbuf *m = make_packet(mp);
        if (!m)
            return 1;
        tr_engine_input(engine, 0, eth0, m);
    }
    dt = mono_seconds() - t0;
    printf("single: %d packets in %.3f s -> %.2f Mpps\n", total, dt,
           total / dt / 1e6);

    for (int i = 0; i < warmup; i++) {
        struct rte_mbuf *m = make_packet(mp);
        if (!m)
            return 1;
        tr_engine_input(engine, 0, eth0, m);
    }
    const int batch = 32;
    cap.packets = 0;
    t0 = mono_seconds();
    for (int i = 0; i < total; i += batch) {
        struct rte_mbuf *bufs[batch];
        for (int j = 0; j < batch; j++) {
            bufs[j] = make_packet(mp);
            if (!bufs[j])
                return 1;
        }
        tr_engine_input_burst(engine, 0, eth0, bufs, batch);
    }
    dt = mono_seconds() - t0;
    printf("burst:  %d packets in %.3f s -> %.2f Mpps\n", total, dt,
           total / dt / 1e6);
    printf("tx packets: %llu\n", (unsigned long long)cap.packets);

    tr_engine_destroy(engine);
    rte_mempool_free(mp);
    tr_tunnel_drivers_fini();
    rte_eal_cleanup();
    return 0;
}
