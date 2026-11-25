#include "test_common.h"

#include "capture.h"
#include "engine.h"

#include <arpa/inet.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static uint8_t *mtod(struct rte_mbuf *m)
{
    return rte_pktmbuf_mtod(m, uint8_t *);
}

static struct rte_mbuf *make_arp(struct rte_mempool *mp,
                                 const uint8_t eth_dst[6],
                                 const uint8_t eth_src[6],
                                 const struct in_addr *spa,
                                 const struct in_addr *tpa)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
    if (!m)
        return NULL;
    if (!rte_pktmbuf_append(m, 42)) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    uint8_t *p = mtod(m);
    static const uint8_t zero[6] = {0};
    memset(p, 0, 42);
    memcpy(p, eth_dst, 6);
    memcpy(p + 6, eth_src, 6);
    p[12] = 0x08;
    p[13] = 0x06;
    p[14] = 0;
    p[15] = 1;
    p[16] = 0x08;
    p[17] = 0;
    p[18] = 6;
    p[19] = 4;
    p[20] = 0;
    p[21] = 1;
    memcpy(p + 22, eth_src, 6);
    memcpy(p + 28, spa, 4);
    memcpy(p + 32, zero, 6);
    memcpy(p + 38, tpa, 4);
    return m;
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

static int pcap_arp_records(const char *path, int expect)
{
    FILE *f = fopen(path, "rb");
    uint8_t h[24];
    int n = 0;

    CHECK(f != NULL);
    CHECK(fread(h, 1, sizeof(h), f) == sizeof(h));
    CHECK(rd32(h) == 0xa1b2c3d4u);
    CHECK(h[4] == 2 && h[5] == 0 && h[6] == 4 && h[7] == 0);
    CHECK(rd32(h + 20) == 1);
    for (;;) {
        uint8_t rh[16];
        size_t got = fread(rh, 1, sizeof(rh), f);
        if (got == 0)
            break;
        CHECK(got == sizeof(rh));
        uint32_t incl = rd32(rh + 8);
        CHECK(incl >= 14);
        uint8_t *pkt = malloc(incl);
        CHECK(pkt != NULL);
        CHECK(fread(pkt, 1, incl, f) == incl);
        CHECK((pkt[12] << 8 | pkt[13]) == 0x0806);
        free(pkt);
        n++;
    }
    fclose(f);
    CHECK(n == expect);
    return 0;
}

int main(void)
{
    char *eal_argv[] = {"test_capture", "--no-huge", "--no-pci",
                        "--lcores",     "0",        "-m",
                        "512",          NULL};
    if (rte_eal_init(7, eal_argv) < 0)
        return 1;
    if (tr_tunnel_drivers_init())
        return 1;
    struct rte_mempool *mp =
        rte_pktmbuf_pool_create("cap_pool", 2048, 256, 0, 10240,
                                rte_socket_id());
    CHECK(mp != NULL);

    struct tr_config cfg;
    struct tr_config_env env;
    char err[256];
    tr_config_init(&cfg);
    env.n_ports = 2;
    env.port_valid = NULL;
    env.port_names = NULL;
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 address 192.0.2.1/24") == 0);
    struct tr_iface *iface = tr_config_find(&cfg, "eth0");
    CHECK(iface != NULL);
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 2};
    const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(iface->mac, eth0_mac, 6);
    struct tr_engine *e =
        tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    struct tr_config env_cfg;
    CHECK(tr_engine_config_copy(e, &env_cfg) == 0);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;

    const char *path = "test_capture.pcap";
    unlink(path);
    CHECK(tr_engine_capture_start(e, "eth0", path, TR_CAP_RX, TR_CAP_SNAPLEN_MAX, 2, "arp",
                                  err, sizeof(err)) == 0);
    struct in_addr spa, tpa;
    inet_pton(AF_INET, "192.0.2.2", &spa);
    inet_pton(AF_INET, "192.0.2.1", &tpa);
    for (int i = 0; i < 2; i++) {
        struct rte_mbuf *m =
            make_arp(mp, bcast, peer_mac, &spa, &tpa);
        CHECK(m != NULL);
        CHECK(tr_engine_input(e, 0, eth0, m) == 0);
    }
    char *status = NULL;
    CHECK(tr_engine_capture_status(e, &status) == 0);
    CHECK(strstr(status, "packets: 2") != NULL);
    CHECK(strstr(status, "count reached") != NULL);
    free(status);
    CHECK(tr_engine_capture_stop(e, err, sizeof(err)) == 0);
    CHECK(pcap_arp_records(path, 2) == 0);

    /* A filter that cannot match must not write packet records. */
    unlink(path);
    CHECK(tr_engine_capture_start(e, "eth0", path, TR_CAP_RX, TR_CAP_SNAPLEN_MAX, 0,
                                  "tcp", err, sizeof(err)) == 0);
    struct rte_mbuf *m = make_arp(mp, bcast, peer_mac, &spa, &tpa);
    CHECK(m != NULL);
    CHECK(tr_engine_input(e, 0, eth0, m) == 0);
    status = NULL;
    CHECK(tr_engine_capture_status(e, &status) == 0);
    CHECK(strstr(status, "packets: 0") != NULL);
    free(status);
    CHECK(tr_engine_capture_stop(e, err, sizeof(err)) == 0);
    CHECK(pcap_arp_records(path, 0) == 0);
    unlink(path);

    tr_engine_destroy(e);
    rte_mempool_free(mp);
    tr_tunnel_drivers_fini();
    rte_eal_cleanup();
    printf("test_capture: ok\n");
    return 0;
}
