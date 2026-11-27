#include "test_common.h"

#include "engine.h"
#include "reasm.h"

#include <arpa/inet.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#define CAP_MAX 512

struct capture {
    struct rte_mbuf *m[CAP_MAX];
    int slot[CAP_MAX];
    int worker[CAP_MAX];
    int n;
};

static void capture_tx(void *arg, int worker, int slot, struct rte_mbuf *m)
{
    struct capture *c = arg;
    if (c->n < CAP_MAX) {
        c->m[c->n] = m;
        c->slot[c->n] = slot;
        c->worker[c->n] = worker;
        c->n++;
    } else {
        rte_pktmbuf_free(m);
    }
}

static void capture_reset(struct capture *c)
{
    for (int i = 0; i < c->n; i++)
        rte_pktmbuf_free(c->m[i]);
    c->n = 0;
}

static uint8_t *mtod(struct rte_mbuf *m)
{
    return rte_pktmbuf_mtod(m, uint8_t *);
}

static uint16_t ip_checksum(const uint8_t *p, size_t n)
{
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < n; i += 2)
        sum += (uint32_t)(p[i] << 8 | p[i + 1]);
    if (n & 1)
        sum += (uint32_t)p[n - 1] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint32_t csum_add(uint32_t sum, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i + 1 < n; i += 2)
        sum += (uint32_t)(p[i] << 8 | p[i + 1]);
    if (n & 1)
        sum += (uint32_t)p[n - 1] << 8;
    return sum;
}

static uint16_t tcp_checksum4(const uint8_t *ip, uint32_t tcp_len)
{
    uint32_t sum = 0;
    sum = csum_add(sum, ip + 12, 4);
    sum = csum_add(sum, ip + 16, 4);
    sum += 6;
    sum += (uint16_t)tcp_len;
    sum = csum_add(sum, ip + 20, tcp_len);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static struct rte_mbuf *alloc_frame(struct rte_mempool *mp, uint32_t len)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
    if (!m)
        return NULL;
    if (!rte_pktmbuf_append(m, (uint16_t)len)) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    memset(mtod(m), 0, len);
    return m;
}

static void eth_fill(uint8_t *p, const uint8_t dst[6], const uint8_t src[6],
                     uint16_t type)
{
    memcpy(p, dst, 6);
    memcpy(p + 6, src, 6);
    p[12] = (uint8_t)(type >> 8);
    p[13] = (uint8_t)type;
}

static struct rte_mbuf *build_ipv4(struct rte_mempool *mp,
                                   const uint8_t eth_dst[6],
                                   const uint8_t eth_src[6],
                                   const struct tr_ip *src,
                                   const struct tr_ip *dst, uint8_t ttl,
                                   uint8_t proto, const uint8_t *payload,
                                   uint32_t payload_len, uint16_t id)
{
    uint32_t total = 20 + payload_len;
    struct rte_mbuf *m = alloc_frame(mp, 14 + total);
    if (!m)
        return NULL;
    uint8_t *p = mtod(m);
    eth_fill(p, eth_dst, eth_src, 0x0800);
    uint8_t *ip = p + 14;
    ip[0] = 0x45;
    ip[2] = (uint8_t)(total >> 8);
    ip[3] = (uint8_t)total;
    ip[4] = (uint8_t)(id >> 8);
    ip[5] = (uint8_t)id;
    ip[6] = 0x40;
    ip[8] = ttl;
    ip[9] = proto;
    memcpy(ip + 12, &src->u.v4, 4);
    memcpy(ip + 16, &dst->u.v4, 4);
    memcpy(ip + 20, payload, payload_len);
    uint16_t c = ip_checksum(ip, 20);
    ip[10] = (uint8_t)(c >> 8);
    ip[11] = (uint8_t)c;
    return m;
}

static struct rte_mbuf *build_ipv6(struct rte_mempool *mp,
                                   const uint8_t eth_dst[6],
                                   const uint8_t eth_src[6],
                                   const struct in6_addr *src,
                                   const struct in6_addr *dst, uint8_t hop,
                                   uint8_t next, const uint8_t *payload,
                                   uint32_t payload_len)
{
    struct rte_mbuf *m = alloc_frame(mp, 14 + 40 + payload_len);
    if (!m)
        return NULL;
    uint8_t *p = mtod(m);
    eth_fill(p, eth_dst, eth_src, 0x86dd);
    uint8_t *ip = p + 14;
    ip[0] = 0x60;
    ip[4] = (uint8_t)(payload_len >> 8);
    ip[5] = (uint8_t)payload_len;
    ip[6] = next;
    ip[7] = hop;
    memcpy(ip + 8, src, 16);
    memcpy(ip + 24, dst, 16);
    memcpy(ip + 40, payload, payload_len);
    return m;
}

static struct rte_mbuf *build_tagged_ipv6(struct rte_mempool *mp,
                                         const uint8_t eth_dst[6],
                                         const uint8_t eth_src[6],
                                         uint16_t vid, const struct in6_addr *src,
                                         const struct in6_addr *dst, uint8_t hop,
                                         uint8_t next, const uint8_t *payload,
                                         uint32_t payload_len)
{
    struct rte_mbuf *m = alloc_frame(mp, 14 + 4 + 40 + payload_len);
    if (!m)
        return NULL;
    uint8_t *p = mtod(m);
    eth_fill(p, eth_dst, eth_src, 0x8100);
    p[14] = (uint8_t)(vid >> 8);
    p[15] = (uint8_t)vid;
    p[16] = 0x86;
    p[17] = 0xdd;
    uint8_t *ip = p + 18;
    ip[0] = 0x60;
    ip[4] = (uint8_t)(payload_len >> 8);
    ip[5] = (uint8_t)payload_len;
    ip[6] = next;
    ip[7] = hop;
    memcpy(ip + 8, src, 16);
    memcpy(ip + 24, dst, 16);
    memcpy(ip + 40, payload, payload_len);
    return m;
}

static struct rte_mbuf *build_arp(struct rte_mempool *mp,
                                  const uint8_t eth_dst[6],
                                  const uint8_t eth_src[6], uint16_t op,
                                  const uint8_t sha[6],
                                  const struct in_addr *spa,
                                  const uint8_t tha[6],
                                  const struct in_addr *tpa)
{
    struct rte_mbuf *m = alloc_frame(mp, 42);
    if (!m)
        return NULL;
    uint8_t *p = mtod(m);
    eth_fill(p, eth_dst, eth_src, 0x0806);
    p[14] = 0;
    p[15] = 1;
    p[16] = 0x08;
    p[17] = 0;
    p[18] = 6;
    p[19] = 4;
    p[20] = (uint8_t)(op >> 8);
    p[21] = (uint8_t)op;
    memcpy(p + 22, sha, 6);
    memcpy(p + 28, spa, 4);
    memcpy(p + 32, tha, 6);
    memcpy(p + 38, tpa, 4);
    return m;
}

static int build_ndp_na(struct rte_mempool *mp, const uint8_t eth_dst[6],
                        const uint8_t eth_src[6],
                        const struct in6_addr *src,
                        const struct in6_addr *dst,
                        const struct in6_addr *target,
                        const uint8_t tll[6], struct rte_mbuf **out)
{
    uint8_t icmp[32] = {0};
    icmp[0] = 136;
    icmp[4] = 0x60;
    memcpy(icmp + 8, target, 16);
    icmp[24] = 2;
    icmp[25] = 1;
    memcpy(icmp + 26, tll, 6);
    uint32_t sum = 0;
    sum = csum_add(sum, (const uint8_t *)src, 16);
    sum = csum_add(sum, (const uint8_t *)dst, 16);
    sum += 32;
    sum += 58;
    sum = csum_add(sum, icmp, 32);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    uint16_t c = (uint16_t)~sum;
    icmp[2] = (uint8_t)(c >> 8);
    icmp[3] = (uint8_t)c;
    *out = build_ipv6(mp, eth_dst, eth_src, src, dst, 255, 58, icmp, 32);
    return *out ? 0 : -1;
}

static int build_ndp_ns(struct rte_mempool *mp, const uint8_t eth_dst[6],
                        const uint8_t eth_src[6],
                        const struct in6_addr *src,
                        const struct in6_addr *dst,
                        const struct in6_addr *target,
                        const uint8_t sll[6], struct rte_mbuf **out)
{
    uint8_t icmp[32] = {0};
    icmp[0] = 135;
    memcpy(icmp + 8, target, 16);
    icmp[24] = 1;
    icmp[25] = 1;
    memcpy(icmp + 26, sll, 6);
    uint32_t sum = 0;
    sum = csum_add(sum, (const uint8_t *)src, 16);
    sum = csum_add(sum, (const uint8_t *)dst, 16);
    sum += 32;
    sum += 58;
    sum = csum_add(sum, icmp, 32);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    uint16_t c = (uint16_t)~sum;
    icmp[2] = (uint8_t)(c >> 8);
    icmp[3] = (uint8_t)c;
    *out = build_ipv6(mp, eth_dst, eth_src, src, dst, 255, 58, icmp, 32);
    return *out ? 0 : -1;
}

static int setup_config(struct tr_config *cfg, struct tr_config_env *env)
{
    tr_config_init(cfg);
    env->n_ports = 2;
    env->port_valid = NULL;
    env->port_names = NULL;
    return 0;
}

static int set_mac(struct tr_config *cfg, const char *name, const uint8_t mac[6])
{
    struct tr_iface *iface = tr_config_find(cfg, name);
    if (!iface)
        return -1;
    memcpy(iface->mac, mac, 6);
    return 0;
}

static uint32_t next_rand(uint32_t *state)
{
    uint32_t x = *state;

    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

/* Reference implementation: accumulate one 16-bit big-endian word at a time.
 * The forwarding path uses a wider (32-bit load) accumulator, so the two must
 * agree for every length and seed. */
static uint32_t ref_checksum_add(uint32_t sum, const uint8_t *p, size_t len)
{
    while (len >= 2) {
        sum += (uint32_t)(p[0] << 8 | p[1]);
        p += 2;
        len -= 2;
    }
    if (len)
        sum += (uint32_t)p[0] << 8;
    return sum;
}

static int test_checksum(void)
{
    uint32_t seed = 0x12345678u;
    uint8_t buf[300];

    for (int it = 0; it < 20000; it++) {
        size_t len = (size_t)(next_rand(&seed) % sizeof(buf));
        for (size_t i = 0; i < len; i++)
            buf[i] = (uint8_t)next_rand(&seed);
        uint32_t iseed = next_rand(&seed);
        uint16_t want = tr_checksum16_finish(ref_checksum_add(iseed, buf, len));
        CHECK(tr_checksum16(buf, len, iseed) == want);

        /* Chunked accumulation must match the reference split the same way. */
        size_t cut = len ? (size_t)(next_rand(&seed) % (len + 1)) : 0;
        uint32_t a = tr_checksum_add(iseed, buf, cut);
        a = tr_checksum_add(a, buf + cut, len - cut);
        uint32_t b = ref_checksum_add(iseed, buf, cut);
        b = ref_checksum_add(b, buf + cut, len - cut);
        CHECK(tr_checksum16_finish(a) == tr_checksum16_finish(b));
    }

    /* Incremental update (RFC 1624) must produce the same header checksum as
     * a full re-sum for every TTL, protocol and base checksum combination. */
    for (int it = 0; it < 20000; it++) {
        uint8_t hdr[20];

        for (int i = 0; i < 20; i++)
            hdr[i] = (uint8_t)next_rand(&seed);
        hdr[0] = 0x45;
        hdr[8] = (uint8_t)(1 + next_rand(&seed) % 254);
        hdr[10] = 0;
        hdr[11] = 0;
        uint16_t full = tr_checksum16(hdr, 20, 0);
        hdr[10] = (uint8_t)(full >> 8);
        hdr[11] = (uint8_t)full;

        uint16_t old_word = (uint16_t)((uint16_t)hdr[8] << 8 | hdr[9]);
        uint16_t new_word = (uint16_t)((uint16_t)(hdr[8] - 1) << 8 | hdr[9]);
        uint16_t updated = tr_checksum16_update(full, old_word, new_word);
        hdr[8]--;
        hdr[10] = (uint8_t)(updated >> 8);
        hdr[11] = (uint8_t)updated;
        CHECK(tr_checksum16(hdr, 20, 0) == 0);
    }
    return 0;
}

/* Parse "<name> <count>" out of the per-interface drop breakdown printed by
 * tr_engine_stats_text(). */
static unsigned long long stat_reason(const char *text, const char *name)
{
    const char *p = text;
    size_t nlen = strlen(name);

    while ((p = strstr(p, name)) != NULL) {
        bool start_ok =
            p == text || p[-1] == ' ' || p[-1] == ':' || p[-1] == ',';
        if (start_ok && p[nlen] == ' ')
            return strtoull(p + nlen + 1, NULL, 10);
        p += nlen;
    }
    return 0;
}

/* The aggregate drop counter alone cannot tell an operator whether the
 * underlay is full of unrouteable noise or our own frames are too big, so each
 * reject path must be attributed. */
static int test_drop_reasons(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t eth1_mac[6] = {0x02, 0, 0, 0, 0, 2};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0xbb};
    const uint8_t other_mac[6] = {0x02, 0, 0, 0, 0, 0x99};
    struct tr_ip src, dst, no_route;
    uint8_t payload[1000];
    char *out = NULL;

    memset(payload, 0x5a, sizeof(payload));
    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 address 192.0.2.1/24") == 0);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth1 port 1") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth1 address 198.51.100.1/24") == 0);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth1 mtu 600") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    CHECK(set_mac(&cfg, "eth1", eth1_mac) == 0);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;
    int eth1 = tr_config_find_const(&env_cfg, "eth1")->slot;

    /* Resolve the next hop on eth1 so that only the intended check fires. */
    struct in_addr spa, tpa;
    inet_pton(AF_INET, "198.51.100.2", &spa);
    inet_pton(AF_INET, "198.51.100.1", &tpa);
    CHECK(build_arp(mp, eth1_mac, peer_mac, 2, peer_mac, &spa, eth1_mac,
                    &tpa) != NULL);
    struct rte_mbuf *arp = build_arp(mp, eth1_mac, peer_mac, 2, peer_mac, &spa,
                                     eth1_mac, &tpa);
    CHECK(arp != NULL);
    CHECK(tr_engine_input(e, 0, eth1, arp) == 0);
    capture_reset(cap);

    tr_ip_parse("192.0.2.2", &src);
    tr_ip_parse("198.51.100.2", &dst);
    tr_ip_parse("203.0.113.9", &no_route);

    /* Destination MAC is not ours. */
    struct rte_mbuf *m =
        build_ipv4(mp, other_mac, peer_mac, &src, &dst, 64, 17, payload, 8, 1);
    CHECK(m != NULL);
    CHECK(tr_engine_input(e, 0, eth0, m) == 0);

    /* Broken IPv4 header checksum. */
    m = build_ipv4(mp, eth0_mac, peer_mac, &src, &dst, 64, 17, payload, 8, 1);
    CHECK(m != NULL);
    mtod(m)[14 + 10] ^= 0xff;
    CHECK(tr_engine_input(e, 0, eth0, m) == 0);

    /* Runt frame. */
    m = alloc_frame(mp, 10);
    CHECK(m != NULL);
    CHECK(tr_engine_input(e, 0, eth0, m) == 0);

    /* No route to the destination (ICMP unreachable is generated). */
    m = build_ipv4(mp, eth0_mac, peer_mac, &src, &no_route, 64, 17, payload, 8,
                   1);
    CHECK(m != NULL);
    CHECK(tr_engine_input(e, 0, eth0, m) == 0);

    /* DF set and the packet exceeds the egress MTU (600). */
    m = build_ipv4(mp, eth0_mac, peer_mac, &src, &dst, 64, 17, payload, 1000,
                   1);
    CHECK(m != NULL);
    CHECK(tr_engine_input(e, 0, eth0, m) == 0);

    capture_reset(cap);
    CHECK(tr_engine_stats_text(e, &out) == 0);
    CHECK(out != NULL);
    CHECK(stat_reason(out, "rx-mac") == 1);
    CHECK(stat_reason(out, "rx-cksum") == 1);
    CHECK(stat_reason(out, "rx-short") == 1);
    CHECK(stat_reason(out, "no-route") == 1);
    CHECK(stat_reason(out, "df") == 1);
    /* Every drop must be attributed: the per-reason counts add up. */
    unsigned long long total = 0;
    for (int r = 0; r < TR_DROP_COUNT; r++)
        total += stat_reason(out, tr_drop_reason_name(r));
    CHECK(total >= 5);
    free(out);

    tr_engine_destroy(e);
    return 0;
}

static int test_arp(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0xaa};
    const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 address 192.0.2.1/24") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;

    struct in_addr spa, tpa;
    inet_pton(AF_INET, "192.0.2.2", &spa);
    inet_pton(AF_INET, "192.0.2.1", &tpa);
    struct rte_mbuf *m =
        build_arp(mp, bcast, peer_mac, 1, peer_mac, &spa, (uint8_t[6]){0},
                  &tpa);
    CHECK(m != NULL);
    capture_reset(cap);
    CHECK(tr_engine_input(e, 0, eth0, m) == 0);
    CHECK(cap->n == 1);
    CHECK(cap->slot[0] == eth0);
    uint8_t *p = mtod(cap->m[0]);
    CHECK(rte_pktmbuf_pkt_len(cap->m[0]) == 42);
    CHECK((p[12] << 8 | p[13]) == 0x0806);
    CHECK((p[20] << 8 | p[21]) == 2);
    CHECK(memcmp(p + 22, eth0_mac, 6) == 0);
    CHECK(memcmp(p + 28, &tpa, 4) == 0);
    capture_reset(cap);
    tr_engine_destroy(e);
    return 0;
}

static int test_ipv4_route(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t eth1_mac[6] = {0x02, 0, 0, 0, 0, 2};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0xbb};
    const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 address 192.0.2.1/24") == 0);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth1 port 1") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth1 address 198.51.100.1/24") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    CHECK(set_mac(&cfg, "eth1", eth1_mac) == 0);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;
    int eth1 = tr_config_find_const(&env_cfg, "eth1")->slot;

    struct tr_ip src, dst;
    tr_ip_parse("192.0.2.2", &src);
    tr_ip_parse("198.51.100.2", &dst);
    uint8_t payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    struct rte_mbuf *m =
        build_ipv4(mp, eth0_mac, peer_mac, &src, &dst, 64, 17, payload, 8, 7);
    CHECK(m != NULL);
    capture_reset(cap);
    CHECK(tr_engine_input(e, 0, eth0, m) == 0);
    CHECK(cap->n == 1);
    CHECK(cap->slot[0] == eth1);
    uint8_t *arp = mtod(cap->m[0]);
    CHECK((arp[12] << 8 | arp[13]) == 0x0806);
    CHECK((arp[20] << 8 | arp[21]) == 1);
    struct in_addr expected;
    inet_pton(AF_INET, "198.51.100.2", &expected);
    CHECK(memcmp(arp + 38, &expected, 4) == 0);

    capture_reset(cap);
    struct in_addr spa, tpa;
    inet_pton(AF_INET, "198.51.100.2", &spa);
    inet_pton(AF_INET, "198.51.100.1", &tpa);
    struct rte_mbuf *reply =
        build_arp(mp, eth1_mac, peer_mac, 2, peer_mac, &spa, eth1_mac, &tpa);
    CHECK(reply != NULL);
    CHECK(tr_engine_input(e, 0, eth1, reply) == 0);
    CHECK(cap->n == 1);
    CHECK(cap->slot[0] == eth1);
    uint8_t *p = mtod(cap->m[0]);
    CHECK((p[12] << 8 | p[13]) == 0x0800);
    CHECK(memcmp(p, peer_mac, 6) == 0);
    CHECK(memcmp(p + 6, eth1_mac, 6) == 0);
    CHECK(p[22] == 63); /* TTL decremented */
    CHECK(memcmp(p + 30, &dst.u.v4, 4) == 0);
    CHECK(ip_checksum(p + 14, 20) == 0);

    /* The forwarding path updates the header checksum incrementally after
     * decrementing the TTL, so verify the result is a valid checksum for a
     * range of TTL values and protocols. */
    for (uint8_t ttl = 2; ttl < 128; ttl++) {
        uint8_t proto = (ttl & 1) ? 17 : 6;
        struct rte_mbuf *sm = build_ipv4(mp, eth0_mac, peer_mac, &src, &dst,
                                         ttl, proto, payload, 8, 7);
        CHECK(sm != NULL);
        capture_reset(cap);
        CHECK(tr_engine_input(e, 0, eth0, sm) == 0);
        CHECK(cap->n == 1);
        uint8_t *q = mtod(cap->m[0]);
        CHECK(q[22] == ttl - 1);
        CHECK(q[23] == proto);
        CHECK(ip_checksum(q + 14, 20) == 0);
        CHECK(memcmp(q + 34, payload, 8) == 0);
    }

    /* With hardware IPv4 checksum offload the header checksum is left zero
     * and the PMD is asked to fill it in. */
    tr_engine_set_tx_ipv4_cksum(e, true);
    m = build_ipv4(mp, eth0_mac, peer_mac, &src, &dst, 64, 17, payload, 8, 8);
    CHECK(m != NULL);
    capture_reset(cap);
    CHECK(tr_engine_input(e, 0, eth0, m) == 0);
    CHECK(cap->n == 1);
    p = mtod(cap->m[0]);
    CHECK((cap->m[0]->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) != 0);
    CHECK((cap->m[0]->ol_flags & RTE_MBUF_F_TX_IPV4) != 0);
    CHECK(cap->m[0]->l2_len == 14);
    CHECK(cap->m[0]->l3_len == 20);
    CHECK(p[24] == 0 && p[25] == 0);
    tr_engine_set_tx_ipv4_cksum(e, false);

    char *route = NULL;
    CHECK(tr_engine_show(e, 2, (char *[]){"route", "198.51.100.2"},
                         &route) == 0);
    CHECK(strstr(route, "Matched prefix: 198.51.100.0/24") != NULL);
    CHECK(strstr(route, "Egress: eth1") != NULL);
    CHECK(strstr(route, "Next-hop: directly connected") != NULL);
    free(route);
    capture_reset(cap);
    tr_engine_destroy(e);
    (void)bcast;
    return 0;
}

static int test_ndp(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0xcc};
    struct in6_addr me, peer, sn;

    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 address 2001:db8:1::1/64") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;

    inet_pton(AF_INET6, "2001:db8:1::1", &me);
    inet_pton(AF_INET6, "2001:db8:1::2", &peer);
    tr_ip6_solicited_node(&me, &sn);
    uint8_t sn_mac[6] = {0x33, 0x33, 0xff, 0, 0, 0};
    sn_mac[3] = me.s6_addr[13];
    sn_mac[4] = me.s6_addr[14];
    sn_mac[5] = me.s6_addr[15];
    struct rte_mbuf *ns = NULL;
    CHECK(build_ndp_ns(mp, sn_mac, peer_mac, &peer, &sn, &me, peer_mac,
                       &ns) == 0);
    capture_reset(cap);
    CHECK(tr_engine_input(e, 0, eth0, ns) == 0);
    CHECK(cap->n == 1);
    uint8_t *p = mtod(cap->m[0]);
    CHECK((p[12] << 8 | p[13]) == 0x86dd);
    CHECK(p[14 + 6] == 58);
    CHECK(p[14 + 40] == 136);
    CHECK(memcmp(p + 14 + 40 + 8, &me, 16) == 0);
    CHECK(memcmp(p + 14 + 40 + 26, eth0_mac, 6) == 0);
    capture_reset(cap);
    tr_engine_destroy(e);
    return 0;
}


static struct rte_mbuf *build_outer_etherip6(struct rte_mempool *mp,
                                             const uint8_t eth_dst[6],
                                             const uint8_t eth_src[6],
                                             const struct in6_addr *src,
                                             const struct in6_addr *dst,
                                             struct rte_mbuf *inner)
{
    uint32_t ilen = rte_pktmbuf_pkt_len(inner);
    struct rte_mbuf *m = alloc_frame(mp, 14 + 40 + 2 + ilen);
    if (!m)
        return NULL;
    uint8_t *p = mtod(m);
    eth_fill(p, eth_dst, eth_src, 0x86dd);
    uint8_t *ip = p + 14;
    ip[0] = 0x60;
    uint32_t plen = 2 + ilen;
    ip[4] = (uint8_t)(plen >> 8);
    ip[5] = (uint8_t)plen;
    ip[6] = 97;
    ip[7] = 64;
    memcpy(ip + 8, src, 16);
    memcpy(ip + 24, dst, 16);
    ip[40] = 0x30;
    ip[41] = 0x00;
    memcpy(ip + 42, mtod(inner), ilen);
    return m;
}

/* A TCP SYN-ACK leaving the tunnel must be clamped before it is forwarded to
 * the LAN.  Clamping only on the transmit side would let the far side
 * advertise its 9000-MTU MSS to a LAN host, so the host would send segments
 * that the 1500-MTU underlay has to fragment. */
static int test_mss_clamp_decap(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t tun_mac[6] = {0x02, 0, 0, 0, 0, 0xaa};
    const uint8_t lan_mac[6] = {0x02, 0, 0, 0, 0, 0xee};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0xdd};
    struct in6_addr me6, peer6;

    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 address 192.0.2.1/24") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 address 2001:db8::1/64") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 remote 2001:db8::2") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 local-address 2001:db8::1") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 local-interface eth0") == 0);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces tunnel tun0 mtu 9000") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 encapsulation etherip6") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 tcp-mss auto") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 address 10.0.0.1/30") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    CHECK(set_mac(&cfg, "tun0", tun_mac) == 0);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;

    inet_pton(AF_INET6, "2001:db8::1", &me6);
    inet_pton(AF_INET6, "2001:db8::2", &peer6);

    /* Resolve the LAN next hop 192.0.2.2 -> lan_mac. */
    struct in_addr lan_ip, me_ip;
    inet_pton(AF_INET, "192.0.2.2", &lan_ip);
    inet_pton(AF_INET, "192.0.2.1", &me_ip);
    struct rte_mbuf *arp =
        build_arp(mp, eth0_mac, lan_mac, 2, lan_mac, &lan_ip, eth0_mac, &me_ip);
    CHECK(arp != NULL);
    CHECK(tr_engine_input(e, 0, eth0, arp) == 0);
    capture_reset(cap);

    /* Inner SYN-ACK from the far side (10.0.0.2) to the LAN host, advertising
     * the far side's 9000-MTU MSS. */
    uint32_t tcp_len = 24; /* 20-byte header + MSS option */
    uint32_t ip_total = 20 + tcp_len;
    struct rte_mbuf *inner = alloc_frame(mp, 14 + ip_total);
    CHECK(inner != NULL);
    uint8_t *p = mtod(inner);
    eth_fill(p, tun_mac, lan_mac, 0x0800);
    uint8_t *ip = p + 14;
    ip[0] = 0x45;
    ip[2] = (uint8_t)(ip_total >> 8);
    ip[3] = (uint8_t)ip_total;
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = 6;
    inet_pton(AF_INET, "10.0.0.2", ip + 12);
    inet_pton(AF_INET, "192.0.2.2", ip + 16);
    uint8_t *tcp = ip + 20;
    tcp[0] = 0x00;
    tcp[1] = 0x50; /* source port 80 */
    tcp[2] = 0x30;
    tcp[3] = 0x00; /* destination port 12288 */
    tcp[12] = 6 << 4;
    tcp[13] = 0x12; /* SYN | ACK */
    tcp[20] = 2;
    tcp[21] = 4;
    tcp[22] = 0x23;
    tcp[23] = 0x00; /* MSS 8960 */
    uint16_t c = ip_checksum(ip, 20);
    ip[10] = (uint8_t)(c >> 8);
    ip[11] = (uint8_t)c;
    c = tcp_checksum4(ip, tcp_len);
    tcp[16] = (uint8_t)(c >> 8);
    tcp[17] = (uint8_t)c;

    struct rte_mbuf *outer =
        build_outer_etherip6(mp, eth0_mac, peer_mac, &peer6, &me6, inner);
    CHECK(outer != NULL);
    rte_pktmbuf_free(inner);
    CHECK(tr_engine_input(e, 0, eth0, outer) == 0);
    CHECK(cap->n == 1);
    CHECK(cap->slot[0] == eth0);

    uint8_t *q = mtod(cap->m[0]);
    CHECK((q[12] << 8 | q[13]) == 0x0800);
    CHECK(memcmp(q, lan_mac, 6) == 0);
    CHECK(memcmp(q + 6, eth0_mac, 6) == 0);
    CHECK(q[22] == 63); /* TTL decremented */
    uint8_t *tcp2 = q + 14 + 20;
    CHECK(tcp2[12] == (6 << 4) && tcp2[13] == 0x12);
    CHECK(tcp2[20] == 2 && tcp2[21] == 4);
    /* 1500 - 42 (outer IPv6 + EtherIP) - 14 (inner Ethernet)
     *      - 40 (inner IPv4 + TCP) = 1404 */
    CHECK((tcp2[22] << 8 | tcp2[23]) == 1404);
    uint16_t stored = (uint16_t)(tcp2[16] << 8 | tcp2[17]);
    tcp2[16] = 0;
    tcp2[17] = 0;
    CHECK(tcp_checksum4(q + 14, tcp_len) == stored);

    capture_reset(cap);
    tr_engine_destroy(e);
    return 0;
}

static int test_tunnel_overlay(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t tun_mac[6] = {0x02, 0, 0, 0, 0, 0xaa};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0xdd};
    struct in6_addr me6, peer6, ll;

    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 address 2001:db8::1/64") == 0);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces tunnel tun0 remote 2001:db8::2") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 local-address 2001:db8::1") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 local-interface eth0") == 0);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces tunnel tun0 mtu 9000") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 encapsulation etherip6") == 0);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces tunnel tun0 tcp-mss auto") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 address 10.0.0.1/30") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    CHECK(set_mac(&cfg, "tun0", tun_mac) == 0);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;
    int tun0 = tr_config_find_const(&env_cfg, "tun0")->slot;

    inet_pton(AF_INET6, "2001:db8::1", &me6);
    inet_pton(AF_INET6, "2001:db8::2", &peer6);
    tr_ip6_linklocal(eth0_mac, &ll);

    /* 9000-byte inner frame carrying a TCP SYN. */
    uint32_t inner_len = 9000;
    uint32_t ip_total = inner_len - 14;
    uint32_t tcp_len = ip_total - 20;
    struct rte_mbuf *inner = alloc_frame(mp, inner_len);
    CHECK(inner != NULL);
    uint8_t *p = mtod(inner);
    eth_fill(p, tun_mac, tun_mac, 0x0800);
    uint8_t *ip = p + 14;
    ip[0] = 0x45;
    ip[2] = (uint8_t)(ip_total >> 8);
    ip[3] = (uint8_t)ip_total;
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = 6;
    inet_pton(AF_INET, "10.0.0.1", ip + 12);
    inet_pton(AF_INET, "10.0.0.2", ip + 16);
    uint8_t *tcp = ip + 20;
    tcp[12] = 6 << 4;
    tcp[13] = 0x02;
    tcp[20] = 2;
    tcp[21] = 4;
    tcp[22] = 0x23;
    tcp[23] = 0x00; /* 8960 */
    for (uint32_t i = 20 + 24; i < tcp_len; i++)
        tcp[i] = (uint8_t)i;
    uint16_t c = ip_checksum(ip, 20);
    ip[10] = (uint8_t)(c >> 8);
    ip[11] = (uint8_t)c;
    c = tcp_checksum4(ip, tcp_len);
    tcp[16] = (uint8_t)(c >> 8);
    tcp[17] = (uint8_t)c;

    capture_reset(cap);
    CHECK(tr_engine_input(e, 0, tun0, inner) == 0);
    CHECK(cap->n == 1);
    p = mtod(cap->m[0]);
    CHECK((p[12] << 8 | p[13]) == 0x86dd);
    CHECK(p[14 + 6] == 58);
    CHECK(p[14 + 40] == 135); /* underlay NS for 2001:db8::2 */

    capture_reset(cap);
    struct rte_mbuf *na = NULL;
    CHECK(build_ndp_na(mp, eth0_mac, peer_mac, &peer6, &ll, &peer6,
                       peer_mac, &na) == 0);
    CHECK(tr_engine_input(e, 0, eth0, na) == 0);
    CHECK(cap->n >= 1);
    /* The queued inner ARP request is now encapsulated and transmitted. */
    struct rte_mbuf *ethernet = NULL;
    for (int i = 0; i < cap->n; i++) {
        uint8_t *q = mtod(cap->m[i]);
        if (rte_pktmbuf_pkt_len(cap->m[i]) >= 14 + 42 &&
            (q[12] << 8 | q[13]) == 0x86dd && q[14 + 6] == 97) {
            ethernet = cap->m[i];
            break;
        }
    }
    CHECK(ethernet != NULL);
    uint8_t *outer = mtod(ethernet);
    uint32_t olen = 40 + (uint32_t)(outer[14 + 4] << 8 | outer[14 + 5]);
    CHECK(olen > 42);
    CHECK(outer[14 + 40] == 0x30 && outer[14 + 41] == 0x00);
    uint8_t *inner_arp = outer + 14 + 40 + 2;
    CHECK((inner_arp[12] << 8 | inner_arp[13]) == 0x0806);
    CHECK((inner_arp[20] << 8 | inner_arp[21]) == 1);
    struct in_addr tpa;
    inet_pton(AF_INET, "10.0.0.2", &tpa);
    CHECK(memcmp(inner_arp + 38, &tpa, 4) == 0);

    /* Feed the overlay ARP reply.  The queued 9000-byte packet is flushed,
     * encapsulated, fragmented and transmitted on eth0. */
    capture_reset(cap);
    struct in_addr spa, target;
    inet_pton(AF_INET, "10.0.0.2", &spa);
    inet_pton(AF_INET, "10.0.0.1", &target);
    struct rte_mbuf *arp_reply =
        build_arp(mp, tun_mac, peer_mac, 2, peer_mac, &spa, tun_mac, &target);
    CHECK(arp_reply != NULL);
    CHECK(tr_engine_input(e, 0, tun0, arp_reply) == 0);
    CHECK(cap->n > 1);

    struct tr_reasm reasm;
    tr_reasm_init(&reasm);
    struct tr_reasm_out out = {0};
    int complete = 0;
    for (int i = 0; i < cap->n; i++) {
        uint8_t *q = mtod(cap->m[i]);
        uint32_t len = rte_pktmbuf_pkt_len(cap->m[i]);
        if (len < 14 + 40 || (q[12] << 8 | q[13]) != 0x86dd)
            continue;
        q += 14;
        len -= 14;
        if (q[6] != 44)
            continue;
        uint16_t fo = (uint16_t)(q[40 + 2] << 8 | q[40 + 3]);
        uint32_t off = fo & 0xfff8;
        bool more = (fo & 1) != 0;
        uint32_t id = (uint32_t)q[44] << 24 | (uint32_t)q[45] << 16 |
                      (uint32_t)q[46] << 8 | q[47];
        uint32_t plen = (uint32_t)(q[4] << 8 | q[5]);
        struct tr_ip src = {.family = TR_AF_INET6};
        struct tr_ip dst = {.family = TR_AF_INET6};
        memcpy(&src.u.v6, q + 8, 16);
        memcpy(&dst.u.v6, q + 24, 16);
        int rc = tr_reasm6_input(&reasm, eth0, &src, &dst, id, q[40], q, 40, off,
                                 more, q + 48, plen - 8, 1000, &out);
        CHECK(rc >= 0);
        if (rc == 1)
            complete = 1;
    }
    CHECK(complete);
    CHECK(out.len == 42 + inner_len);
    struct tr_tnl_frame frame = {
        .base = out.data,
        .cap = out.len,
        .off = 0,
        .len = out.len,
    };
    struct tr_tnl_driver *drv = tr_tunnel_driver_find("etherip6");
    CHECK(drv != NULL);
    struct tr_tnl_flow flow = {.family = 6};
    CHECK(drv->ops.decap(drv->ctx, &frame, &flow) == 0);
    CHECK(frame.len == inner_len);
    uint8_t *in = out.data + frame.off;
    CHECK(memcmp(in, peer_mac, 6) == 0);
    CHECK(memcmp(in + 6, tun_mac, 6) == 0);
    CHECK(in[14 + 8] == 63); /* inner TTL decremented */
    uint8_t *tcp2 = in + 14 + 20;
    CHECK(tcp2[12] == (6 << 4) && tcp2[13] == 0x02);
    CHECK(tcp2[20] == 2 && tcp2[21] == 4);
    uint16_t mss = (uint16_t)(tcp2[22] << 8 | tcp2[23]);
    /* 1500 - 42 (outer IPv6 + EtherIP) - 14 (inner Ethernet)
     *      - 40 (inner IPv4 + TCP) = 1404 */
    CHECK(mss == 1404);
    uint16_t stored = (uint16_t)(tcp2[16] << 8 | tcp2[17]);
    tcp2[16] = 0;
    tcp2[17] = 0;
    uint16_t tc = tcp_checksum4(in + 14, ip_total - 20);
    CHECK(tc == stored);
    free(out.data);
    tr_reasm_fini(&reasm);

    /* Feed a complete outer EtherIP6 packet into eth0 and verify that the
     * core decapsulates it and routes the inner IPv4 echo request back out
     * through the tunnel. */
    capture_reset(cap);
    uint8_t icmp[8] = {8, 0, 0, 0, 0x12, 0x34, 0, 1};
    uint16_t ic = ip_checksum(icmp, sizeof(icmp));
    icmp[2] = (uint8_t)(ic >> 8);
    icmp[3] = (uint8_t)ic;
    struct tr_ip isrc, idst;
    tr_ip_parse("10.0.0.2", &isrc);
    tr_ip_parse("10.0.0.1", &idst);
    struct rte_mbuf *echo_req =
        build_ipv4(mp, tun_mac, peer_mac, &isrc, &idst, 64, 1, icmp,
                   sizeof(icmp), 11);
    CHECK(echo_req != NULL);
    struct rte_mbuf *outer_pkt =
        build_outer_etherip6(mp, eth0_mac, peer_mac, &peer6, &me6,
                             echo_req);
    CHECK(outer_pkt != NULL);
    rte_pktmbuf_free(echo_req);
    CHECK(tr_engine_input(e, 0, eth0, outer_pkt) == 0);
    CHECK(cap->n == 1);
    uint8_t *rp = mtod(cap->m[0]);
    CHECK((rp[12] << 8 | rp[13]) == 0x86dd);
    CHECK(rp[14 + 6] == 97);
    CHECK(rp[14 + 7] == 64);
    CHECK(rp[14 + 40] == 0x30);
    uint8_t *re = rp + 14 + 42;
    CHECK((re[12] << 8 | re[13]) == 0x0800);
    CHECK(re[14 + 8] == 64);
    CHECK(re[14 + 9] == 1);
    CHECK(re[14 + 20] == 0);
    CHECK(memcmp(re + 14 + 16, &isrc.u.v4, 4) == 0);
    capture_reset(cap);
    tr_engine_destroy(e);
    return 0;
}


static struct rte_mbuf *build_tagged_arp(struct rte_mempool *mp,
                                         const uint8_t eth_src[6], uint16_t vid,
                                         uint16_t op, const uint8_t sha[6],
                                         const struct in_addr *spa,
                                         const struct in_addr *tpa)
{
    struct rte_mbuf *m = alloc_frame(mp, 46);
    if (!m)
        return NULL;
    uint8_t *p = mtod(m);
    static const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    eth_fill(p, bcast, eth_src, 0x8100);
    p[14] = (uint8_t)(vid >> 8);
    p[15] = (uint8_t)vid;
    p[16] = 0x08;
    p[17] = 0x06;
    p[18] = 0;
    p[19] = 1;
    p[20] = 0x08;
    p[21] = 0;
    p[22] = 6;
    p[23] = 4;
    p[24] = (uint8_t)(op >> 8);
    p[25] = (uint8_t)op;
    memcpy(p + 26, sha, 6);
    memcpy(p + 32, spa, 4);
    memset(p + 36, 0, 6);
    memcpy(p + 42, tpa, 4);
    return m;
}

static int test_vlan(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0xee};

    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 vlan-id 10 address "
                        "192.168.10.1/24") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    struct tr_iface *vlan = tr_config_find(&cfg, "eth0.10");
    CHECK(vlan != NULL);
    memcpy(vlan->mac, eth0_mac, 6);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;
    int vlan_slot = tr_config_find_const(&env_cfg, "eth0.10")->slot;

    struct in_addr spa, tpa;
    inet_pton(AF_INET, "192.168.10.2", &spa);
    inet_pton(AF_INET, "192.168.10.1", &tpa);
    struct rte_mbuf *m =
        build_tagged_arp(mp, peer_mac, 10, 1, peer_mac, &spa, &tpa);
    CHECK(m != NULL);
    capture_reset(cap);
    CHECK(tr_engine_input(e, 0, eth0, m) == 0);
    CHECK(cap->n == 1);
    CHECK(cap->slot[0] == vlan_slot);
    uint8_t *p = mtod(cap->m[0]);
    CHECK((p[12] << 8 | p[13]) == 0x8100);
    CHECK((p[14] & 0x0f) == 0 && p[15] == 10);
    CHECK((p[16] << 8 | p[17]) == 0x0806);
    CHECK((p[24] << 8 | p[25]) == 2);
    capture_reset(cap);
    tr_engine_destroy(e);
    return 0;
}

static int test_qinq(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0xee};

    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 vlan-s 100 vlan-c 200 "
                        "address 192.168.200.1/24") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    struct tr_iface *qinq = tr_config_find(&cfg, "eth0.100.200");
    CHECK(qinq != NULL && qinq->vlan_outer == 100 && qinq->vlan_id == 200);
    memcpy(qinq->mac, eth0_mac, 6);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;
    int qinq_slot = tr_config_find_const(&env_cfg, "eth0.100.200")->slot;

    struct rte_mbuf *m = alloc_frame(mp, 14 + 8 + 28);
    CHECK(m != NULL);
    uint8_t *p = mtod(m);
    eth_fill(p, eth0_mac, peer_mac, 0x88a8);
    p[14] = 0;
    p[15] = 100;
    p[16] = 0x81;
    p[17] = 0x00;
    p[18] = 0;
    p[19] = 200;
    p[20] = 0x08;
    p[21] = 0x06;
    uint8_t *arp = p + 22;
    arp[0] = 0;
    arp[1] = 1;
    arp[2] = 0x08;
    arp[3] = 0;
    arp[4] = 6;
    arp[5] = 4;
    arp[7] = 1;
    memcpy(arp + 8, peer_mac, 6);
    inet_pton(AF_INET, "192.168.200.2", arp + 14);
    memset(arp + 18, 0, 6);
    inet_pton(AF_INET, "192.168.200.1", arp + 24);
    capture_reset(cap);
    CHECK(tr_engine_input(e, 0, eth0, m) == 0);
    CHECK(cap->n == 1);
    CHECK(cap->slot[0] == qinq_slot);
    p = mtod(cap->m[0]);
    CHECK((p[12] << 8 | p[13]) == 0x88a8);
    CHECK((p[14] & 0x0f) == 0 && p[15] == 100);
    CHECK((p[16] << 8 | p[17]) == 0x8100);
    CHECK((p[18] & 0x0f) == 0 && p[19] == 200);
    CHECK((p[20] << 8 | p[21]) == 0x0806);
    CHECK((p[28] << 8 | p[29]) == 2);
    capture_reset(cap);
    tr_engine_destroy(e);
    return 0;
}

static int test_bridge(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t eth1_mac[6] = {0x02, 0, 0, 0, 0, 2};
    const uint8_t a_mac[6] = {0x02, 0, 0, 0, 0, 0xa1};
    const uint8_t b_mac[6] = {0x02, 0, 0, 0, 0, 0xb1};

    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth1 port 1") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces bridge br0 children eth0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces bridge br0 children eth1") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    CHECK(set_mac(&cfg, "eth1", eth1_mac) == 0);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;
    int eth1 = tr_config_find_const(&env_cfg, "eth1")->slot;

    struct rte_mbuf *m = alloc_frame(mp, 60);
    CHECK(m != NULL);
    eth_fill(mtod(m), b_mac, a_mac, 0x88b5);
    memset(mtod(m) + 14, 0x5a, 46);
    capture_reset(cap);
    CHECK(tr_engine_input(e, 0, eth0, m) == 0);
    CHECK(cap->n == 1 && cap->slot[0] == eth1);

    m = alloc_frame(mp, 60);
    CHECK(m != NULL);
    eth_fill(mtod(m), a_mac, b_mac, 0x88b5);
    memset(mtod(m) + 14, 0xa5, 46);
    capture_reset(cap);
    CHECK(tr_engine_input(e, 0, eth1, m) == 0);
    CHECK(cap->n == 1 && cap->slot[0] == eth0);

    /* a->b is now known on eth1. */
    m = alloc_frame(mp, 60);
    CHECK(m != NULL);
    eth_fill(mtod(m), b_mac, a_mac, 0x88b5);
    memset(mtod(m) + 14, 0x33, 46);
    capture_reset(cap);
    CHECK(tr_engine_input(e, 0, eth0, m) == 0);
    CHECK(cap->n == 1 && cap->slot[0] == eth1);
    char *macs = NULL;
    CHECK(tr_engine_show(e, 1, (char *[]){"bridge"}, &macs) == 0);
    CHECK(strstr(macs, "br0") != NULL);
    CHECK(strstr(macs, "eth1") != NULL);
    free(macs);
    capture_reset(cap);
    tr_engine_destroy(e);
    return 0;
}

static int test_autoconf(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0x11};
    struct in6_addr me_ll, peer_ll, all_nodes, prefix;
    uint8_t ra[16 + 32 + 8];

    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 address ipv6 autoconf") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;

    tr_ip6_linklocal(eth0_mac, &me_ll);
    inet_pton(AF_INET6, "fe80::2", &peer_ll);
    inet_pton(AF_INET6, "ff02::1", &all_nodes);
    inet_pton(AF_INET6, "2001:db8:abcd::", &prefix);
    memset(ra, 0, sizeof(ra));
    ra[0] = 134;
    ra[4] = 64;
    ra[6] = 0x07;
    ra[7] = 0x08; /* 1800 seconds */
    ra[16] = 3;
    ra[17] = 4;
    ra[18] = 64;
    ra[19] = 0x40; /* autonomous */
    ra[20] = 0;
    ra[21] = 0;
    ra[22] = 0;
    ra[23] = 0x0e;
    ra[24] = 0;
    ra[25] = 0;
    ra[26] = 0x07;
    ra[27] = 0x08;
    memcpy(ra + 32, &prefix, 16);
    ra[48] = 1;
    ra[49] = 1;
    memcpy(ra + 50, peer_mac, 6);
    uint32_t sum = 0;
    sum = csum_add(sum, (const uint8_t *)&peer_ll, 16);
    sum = csum_add(sum, (const uint8_t *)&all_nodes, 16);
    sum += sizeof(ra);
    sum += 58;
    sum = csum_add(sum, ra, sizeof(ra));
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    uint16_t c = (uint16_t)~sum;
    ra[2] = (uint8_t)(c >> 8);
    ra[3] = (uint8_t)c;
    struct rte_mbuf *m =
        build_ipv6(mp, (uint8_t[6]){0x33, 0x33, 0, 0, 0, 1}, peer_mac,
                   &peer_ll, &all_nodes, 255, 58, ra, sizeof(ra));
    CHECK(m != NULL);
    capture_reset(cap);
    CHECK(tr_engine_input(e, 0, eth0, m) == 0);
    tr_engine_housekeeping(e, 0);
    char *routes = NULL;
    CHECK(tr_engine_show(e, 1, (char *[]){"routes"}, &routes) == 0);
    CHECK(strstr(routes, "2001:db8:abcd::/64") != NULL);
    CHECK(strstr(routes, "fe80::2") != NULL);
    free(routes);
    capture_reset(cap);
    tr_engine_destroy(e);
    return 0;
}


static int test_vlan_autoconf(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0x22};
    struct in6_addr me_ll, peer_ll, all_nodes, prefix;
    uint8_t ra[16 + 32 + 8];

    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0.20 address "
                        "ipv6 autoconf") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    struct tr_iface *vlan = tr_config_find(&cfg, "eth0.20");
    CHECK(vlan != NULL && vlan->ipv6_autoconf);
    memcpy(vlan->mac, eth0_mac, 6);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;

    /* Router Solicitation for the autoconf VLAN must be tagged with VLAN 20. */
    capture_reset(cap);
    tr_engine_send_router_solicitations(e);
    CHECK(cap->n == 1);
    uint8_t *rs = mtod(cap->m[0]);
    CHECK((rs[12] << 8 | rs[13]) == 0x8100);
    CHECK((rs[14] & 0x0f) == 0 && rs[15] == 20);
    CHECK((rs[16] << 8 | rs[17]) == 0x86dd);
    CHECK(rs[18 + 6] == 58);
    CHECK(rs[18 + 40] == 133);
    capture_reset(cap);

    tr_ip6_linklocal(eth0_mac, &me_ll);
    inet_pton(AF_INET6, "fe80::2", &peer_ll);
    inet_pton(AF_INET6, "ff02::1", &all_nodes);
    inet_pton(AF_INET6, "2001:db8:20::", &prefix);
    memset(ra, 0, sizeof(ra));
    ra[0] = 134;
    ra[4] = 64;
    ra[6] = 0x07;
    ra[7] = 0x08;
    ra[16] = 3;
    ra[17] = 4;
    ra[18] = 64;
    ra[19] = 0x40;
    ra[23] = 0x0e;
    ra[27] = 0x08;
    memcpy(ra + 32, &prefix, 16);
    ra[48] = 1;
    ra[49] = 1;
    memcpy(ra + 50, peer_mac, 6);
    uint32_t sum = 0;
    sum = csum_add(sum, (const uint8_t *)&peer_ll, 16);
    sum = csum_add(sum, (const uint8_t *)&all_nodes, 16);
    sum += sizeof(ra);
    sum += 58;
    sum = csum_add(sum, ra, sizeof(ra));
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    uint16_t c = (uint16_t)~sum;
    ra[2] = (uint8_t)(c >> 8);
    ra[3] = (uint8_t)c;
    struct rte_mbuf *m =
        build_tagged_ipv6(mp, (uint8_t[6]){0x33, 0x33, 0, 0, 0, 1},
                          peer_mac, 20, &peer_ll, &all_nodes, 255, 58, ra,
                          sizeof(ra));
    CHECK(m != NULL);
    capture_reset(cap);
    CHECK(tr_engine_input(e, 0, eth0, m) == 0);
    tr_engine_housekeeping(e, 0);
    char *routes = NULL;
    CHECK(tr_engine_show(e, 1, (char *[]){"routes"}, &routes) == 0);
    CHECK(strstr(routes, "2001:db8:20::/64") != NULL);
    CHECK(strstr(routes, "fe80::2") != NULL);
    free(routes);
    char *ifaces = NULL;
    char *argv[] = {"interfaces"};
    CHECK(tr_engine_show(e, 1, argv, &ifaces) == 0);
    CHECK(strstr(ifaces, "eth0.20") != NULL);
    CHECK(strstr(ifaces, "autoconf") != NULL);
    CHECK(strstr(ifaces, "2001:db8:20") != NULL);
    free(ifaces);
    capture_reset(cap);
    tr_engine_destroy(e);
    return 0;
}

static int test_etherip4(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t tun_mac[6] = {0x02, 0, 0, 0, 0, 0xaa};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0xee};

    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 address 198.51.100.1/24") == 0);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces tunnel tun0 remote 198.51.100.2") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 local-address 198.51.100.1") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 local-interface eth0") == 0);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces tunnel tun0 mtu 1500") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 encapsulation etherip") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 address 10.1.0.1/30") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    CHECK(set_mac(&cfg, "tun0", tun_mac) == 0);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;
    int tun0 = tr_config_find_const(&env_cfg, "tun0")->slot;

    struct tr_ip src, dst;
    tr_ip_parse("10.1.0.1", &src);
    tr_ip_parse("10.1.0.2", &dst);
    uint8_t payload[16] = {0};
    struct rte_mbuf *inner =
        build_ipv4(mp, tun_mac, tun_mac, &src, &dst, 64, 17, payload,
                   sizeof(payload), 9);
    CHECK(inner != NULL);
    capture_reset(cap);
    CHECK(tr_engine_input(e, 0, tun0, inner) == 0);
    CHECK(cap->n == 1);
    uint8_t *arp = mtod(cap->m[0]);
    CHECK((arp[12] << 8 | arp[13]) == 0x0806);
    CHECK((arp[20] << 8 | arp[21]) == 1);
    struct in_addr outer_tpa;
    inet_pton(AF_INET, "198.51.100.2", &outer_tpa);
    CHECK(memcmp(arp + 38, &outer_tpa, 4) == 0);

    capture_reset(cap);
    struct in_addr spa, tpa;
    inet_pton(AF_INET, "198.51.100.2", &spa);
    inet_pton(AF_INET, "198.51.100.1", &tpa);
    struct rte_mbuf *outer_reply =
        build_arp(mp, eth0_mac, peer_mac, 2, peer_mac, &spa, eth0_mac, &tpa);
    CHECK(outer_reply != NULL);
    CHECK(tr_engine_input(e, 0, eth0, outer_reply) == 0);
    CHECK(cap->n == 1);
    uint8_t *o = mtod(cap->m[0]);
    CHECK((o[12] << 8 | o[13]) == 0x0800);
    CHECK(o[14 + 9] == 97);
    uint32_t olen = (uint32_t)(o[14 + 2] << 8 | o[14 + 3]);
    CHECK(olen == 20 + 2 + 42);
    CHECK(o[14 + 20] == 0x30 && o[14 + 21] == 0x00);
    uint8_t *iarp = o + 14 + 22;
    CHECK((iarp[12] << 8 | iarp[13]) == 0x0806);
    CHECK((iarp[20] << 8 | iarp[21]) == 1);
    struct in_addr itpa;
    inet_pton(AF_INET, "10.1.0.2", &itpa);
    CHECK(memcmp(iarp + 38, &itpa, 4) == 0);

    capture_reset(cap);
    struct in_addr ispa, itarget;
    inet_pton(AF_INET, "10.1.0.2", &ispa);
    inet_pton(AF_INET, "10.1.0.1", &itarget);
    struct rte_mbuf *inner_reply =
        build_arp(mp, tun_mac, peer_mac, 2, peer_mac, &ispa, tun_mac,
                  &itarget);
    CHECK(inner_reply != NULL);
    CHECK(tr_engine_input(e, 0, tun0, inner_reply) == 0);
    CHECK(cap->n == 1);
    o = mtod(cap->m[0]);
    CHECK((o[12] << 8 | o[13]) == 0x0800);
    CHECK(o[14 + 9] == 97);
    CHECK(memcmp(o + 14 + 12, &tpa, 4) == 0);
    CHECK(memcmp(o + 14 + 16, &spa, 4) == 0);
    CHECK(o[14 + 20] == 0x30 && o[14 + 21] == 0x00);
    uint8_t *idata = o + 14 + 22;
    CHECK((idata[12] << 8 | idata[13]) == 0x0800);
    CHECK(memcmp(idata, peer_mac, 6) == 0);
    CHECK(idata[14 + 8] == 63);
    CHECK(memcmp(idata + 14 + 16, &dst.u.v4, 4) == 0);
    CHECK(ip_checksum(idata + 14, 20) == 0);
    capture_reset(cap);
    tr_engine_destroy(e);
    return 0;
}


struct traceroute_arg {
    struct tr_engine *e;
    struct rte_mempool *mp;
    struct capture *cap;
    const uint8_t *local_mac;
    const uint8_t *hop_mac;
    const uint8_t *target_mac;
    int sent_hop;
    int sent_target;
};

static void *traceroute_thread(void *arg)
{
    struct traceroute_arg *a = arg;
    for (int round = 0; round < 400 && !a->sent_target; round++) {
        for (int i = 0; i < a->cap->n; i++) {
            struct rte_mbuf *req = a->cap->m[i];
            uint8_t *q = rte_pktmbuf_mtod(req, uint8_t *);
            if (rte_pktmbuf_pkt_len(req) < 42 ||
                (q[12] << 8 | q[13]) != 0x0800)
                continue;
            uint8_t *rip = q + 14;
            if (rip[9] != 1)
                continue;
            uint8_t ttl = rip[8];
            uint8_t *ricmp = rip + 20;
            if (ttl == 1 && !a->sent_hop) {
                struct rte_mbuf *m = alloc_frame(a->mp, 14 + 20 + 8 + 28);
                uint8_t *p = mtod(m);
                eth_fill(p, a->local_mac, a->hop_mac, 0x0800);
                uint8_t *ip = p + 14;
                ip[0] = 0x45;
                ip[2] = 0;
                ip[3] = 56;
                ip[8] = 64;
                ip[9] = 1;
                struct in_addr hop, src;
                inet_pton(AF_INET, "198.51.100.254", &hop);
                memcpy(&src, rip + 12, 4);
                memcpy(ip + 12, &hop, 4);
                memcpy(ip + 16, &src, 4);
                uint16_t c = ip_checksum(ip, 20);
                ip[10] = (uint8_t)(c >> 8);
                ip[11] = (uint8_t)c;
                uint8_t *icmp = ip + 20;
                memset(icmp, 0, 36);
                icmp[0] = 11;
                memcpy(icmp + 8, rip, 20);
                memcpy(icmp + 28, ricmp, 8);
                c = ip_checksum(icmp, 36);
                icmp[2] = (uint8_t)(c >> 8);
                icmp[3] = (uint8_t)c;
                tr_engine_input(a->e, 0, 1, m);
                a->sent_hop = 1;
            } else if (ttl == 2 && !a->sent_target) {
                struct rte_mbuf *m = alloc_frame(a->mp, 14 + 20 + 8 + 32);
                uint8_t *p = mtod(m);
                eth_fill(p, a->local_mac, a->target_mac, 0x0800);
                uint8_t *ip = p + 14;
                ip[0] = 0x45;
                ip[2] = 0;
                ip[3] = 60;
                ip[8] = 64;
                ip[9] = 1;
                struct in_addr target, src;
                inet_pton(AF_INET, "198.51.100.2", &target);
                memcpy(&src, rip + 12, 4);
                memcpy(ip + 12, &target, 4);
                memcpy(ip + 16, &src, 4);
                uint16_t c = ip_checksum(ip, 20);
                ip[10] = (uint8_t)(c >> 8);
                ip[11] = (uint8_t)c;
                uint8_t *icmp = ip + 20;
                memset(icmp, 0, 40);
                icmp[0] = 0;
                memcpy(icmp + 4, ricmp + 4, 4);
                for (int j = 0; j < 32; j++)
                    icmp[8 + j] = (uint8_t)j;
                c = ip_checksum(icmp, 40);
                icmp[2] = (uint8_t)(c >> 8);
                icmp[3] = (uint8_t)c;
                tr_engine_input(a->e, 0, 1, m);
                a->sent_target = 1;
            }
        }
        usleep(5000);
    }
    return NULL;
}

static int test_traceroute(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t eth1_mac[6] = {0x02, 0, 0, 0, 0, 2};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0xbb};
    const uint8_t hop_mac[6] = {0x02, 0, 0, 0, 0, 0xcc};

    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 address 192.0.2.1/24") == 0);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth1 port 1") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth1 address 198.51.100.1/24") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    CHECK(set_mac(&cfg, "eth1", eth1_mac) == 0);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int eth1 = tr_config_find_const(&env_cfg, "eth1")->slot;

    struct in_addr spa, tpa;
    inet_pton(AF_INET, "198.51.100.2", &spa);
    inet_pton(AF_INET, "198.51.100.1", &tpa);
    struct rte_mbuf *arp =
        build_arp(mp, eth1_mac, peer_mac, 2, peer_mac, &spa, eth1_mac, &tpa);
    CHECK(arp != NULL);
    CHECK(tr_engine_input(e, 0, eth1, arp) == 0);
    capture_reset(cap);

    struct tr_ip target;
    CHECK(tr_ip_parse("198.51.100.2", &target) == 0);
    struct traceroute_arg ta = {
        .e = e, .mp = mp, .cap = cap, .local_mac = eth1_mac,
        .hop_mac = hop_mac, .target_mac = peer_mac};
    pthread_t th;
    CHECK(pthread_create(&th, NULL, traceroute_thread, &ta) == 0);
    char *out = NULL;
    CHECK(tr_engine_traceroute(e, &target, NULL, NULL, 2, 1, 500, 32,
                               &out) == 0);
    pthread_join(th, NULL);
    CHECK(out != NULL);
    CHECK(strstr(out, "198.51.100.254") != NULL);
    CHECK(strstr(out, "Trace complete.") != NULL);
    free(out);
    capture_reset(cap);
    tr_engine_destroy(e);
    return 0;
}

struct ping_reply_arg {
    struct tr_engine *e;
    struct rte_mempool *mp;
};

static void *ping_reply_thread(void *arg)
{
    struct ping_reply_arg *a = arg;
    usleep(50000);
    struct rte_mbuf *m = rte_pktmbuf_alloc(a->mp);
    if (!m || !rte_pktmbuf_append(m, 14 + 20 + 8 + 56))
        return NULL;
    uint8_t *p = rte_pktmbuf_mtod(m, uint8_t *);
    memset(p, 0, 14 + 20 + 8 + 56);
    const uint8_t dm[6] = {0x02, 0, 0, 0, 0, 2};
    const uint8_t sm[6] = {0x02, 0, 0, 0, 0, 0xbb};
    memcpy(p, dm, 6);
    memcpy(p + 6, sm, 6);
    p[12] = 0x08;
    p[13] = 0;
    uint8_t *ip = p + 14;
    ip[0] = 0x45;
    ip[2] = 0;
    ip[3] = 84;
    ip[8] = 64;
    ip[9] = 1;
    inet_pton(AF_INET, "198.51.100.2", ip + 12);
    inet_pton(AF_INET, "198.51.100.1", ip + 16);
    uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2)
        sum += (uint32_t)(ip[i] << 8) | ip[i + 1];
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum;
    ip[10] = (uint8_t)(sum >> 8);
    ip[11] = (uint8_t)sum;
    uint8_t *icmp = ip + 20;
    icmp[0] = 0;
    icmp[5] = 1;
    for (int i = 0; i < 56; i++)
        icmp[8 + i] = (uint8_t)(0x40 + (i & 0x3f));
    sum = 0;
    for (int i = 0; i < 64; i += 2)
        sum += (uint32_t)(icmp[i] << 8) | icmp[i + 1];
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum;
    icmp[2] = (uint8_t)(sum >> 8);
    icmp[3] = (uint8_t)sum;
    tr_engine_input(a->e, 0, 1, m);
    return NULL;
}

static int test_ping(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t eth1_mac[6] = {0x02, 0, 0, 0, 0, 2};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0xbb};

    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 address 192.0.2.1/24") == 0);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth1 port 1") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth1 address 198.51.100.1/24") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    CHECK(set_mac(&cfg, "eth1", eth1_mac) == 0);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int eth1 = tr_config_find_const(&env_cfg, "eth1")->slot;

    struct in_addr spa, tpa;
    inet_pton(AF_INET, "198.51.100.2", &spa);
    inet_pton(AF_INET, "198.51.100.1", &tpa);
    struct rte_mbuf *arp =
        build_arp(mp, eth1_mac, peer_mac, 2, peer_mac, &spa, eth1_mac, &tpa);
    CHECK(arp != NULL);
    CHECK(tr_engine_input(e, 0, eth1, arp) == 0);
    capture_reset(cap);

    struct tr_ip target;
    CHECK(tr_ip_parse("198.51.100.2", &target) == 0);
    struct ping_reply_arg pa = {e, mp};
    pthread_t th;
    CHECK(pthread_create(&th, NULL, ping_reply_thread, &pa) == 0);
    char *out = NULL;
    CHECK(tr_engine_ping(e, &target, NULL, NULL, 1, 500, 56, &out) == 0);
    pthread_join(th, NULL);
    CHECK(out != NULL);
    CHECK(strstr(out, "1 received") != NULL);
    free(out);
    capture_reset(cap);
    tr_engine_destroy(e);
    return 0;
}

/* IPv6 ping through the data plane, following the real wire sequence: the
 * neighbour is unknown, so the router sends an NS; the host answers with an NA;
 * the queued echo request is flushed; the echo reply comes back.  This covers
 * the control-plane transmit path, the NS/NA handling and the receive path for
 * a global (non-link-local) destination. */
static uint16_t icmp6_checksum(const struct in6_addr *src,
                               const struct in6_addr *dst,
                               const uint8_t *icmp, uint32_t len)
{
    uint32_t sum = 0;

    sum = csum_add(sum, (const uint8_t *)src, 16);
    sum = csum_add(sum, (const uint8_t *)dst, 16);
    sum += len;
    sum += 58;
    sum = csum_add(sum, icmp, len);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

struct ping6_arg {
    struct tr_engine *e;
    struct rte_mempool *mp;
    struct capture *cap;
    int slot;
    const uint8_t *peer_mac;
};

/* Find the first transmitted frame of the given ICMPv6 type in the capture. */
static struct rte_mbuf *find_icmp6(struct capture *cap, uint8_t type, int *out)
{
    for (int i = 0; i < cap->n; i++) {
        uint8_t *p = mtod(cap->m[i]);
        if (rte_pktmbuf_pkt_len(cap->m[i]) < 14 + 40 + 8)
            continue;
        if (p[12] != 0x86 || p[13] != 0xdd || p[14 + 6] != 58)
            continue;
        if (p[14 + 40] == type) {
            if (out)
                *out = i;
            return cap->m[i];
        }
    }
    return NULL;
}

static void *ping6_responder(void *arg)
{
    struct ping6_arg *a = arg;
    struct in6_addr me, peer;
    struct rte_mbuf *m;
    uint8_t icmp[8 + 56];
    uint16_t c;

    inet_pton(AF_INET6, "2001:db8:2::1", &me);
    inet_pton(AF_INET6, "2001:db8:2::2", &peer);
    /* Wait for the neighbor solicitation, then answer it. */
    for (int i = 0; i < 500 && !(m = find_icmp6(a->cap, 135, NULL)); i++)
        usleep(1000);
    if (!m)
        return NULL;
    struct rte_mbuf *na = NULL;
    if (build_ndp_na(a->mp, mtod(m) + 6, a->peer_mac, &peer, &me, &peer,
                     a->peer_mac, &na) == 0)
        tr_engine_input(a->e, 0, a->slot, na);

    /* The queued echo request is flushed by the NA; mirror its id/seq. */
    for (int i = 0; i < 500 && !(m = find_icmp6(a->cap, 128, NULL)); i++)
        usleep(1000);
    if (!m)
        return NULL;
    const uint8_t *req = mtod(m) + 14 + 40;
    memset(icmp, 0, sizeof(icmp));
    icmp[0] = 129;
    memcpy(icmp + 4, req + 4, 4);
    for (size_t i = 0; i < 56; i++)
        icmp[8 + i] = (uint8_t)(0x40 + (i & 0x3f));
    c = icmp6_checksum(&peer, &me, icmp, sizeof(icmp));
    icmp[2] = (uint8_t)(c >> 8);
    icmp[3] = (uint8_t)c;
    struct in6_addr from, to;
    inet_pton(AF_INET6, "2001:db8:2::1", &to);
    from = peer;
    struct rte_mbuf *rep = build_ipv6(a->mp, mtod(m) + 6, a->peer_mac, &from,
                                      &to, 64, 58, icmp, sizeof(icmp));
    if (rep)
        tr_engine_input(a->e, 0, a->slot, rep);
    return NULL;
}

static int test_ping6(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t eth1_mac[6] = {0x02, 0, 0, 0, 0, 2};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0xbb};

    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 address 192.0.2.1/24") == 0);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth1 port 1") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth1 address 2001:db8:2::1/64") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    CHECK(set_mac(&cfg, "eth1", eth1_mac) == 0);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int eth1 = tr_config_find_const(&env_cfg, "eth1")->slot;
    capture_reset(cap);

    struct tr_ip target;
    CHECK(tr_ip_parse("2001:db8:2::2", &target) == 0);
    struct ping6_arg pa = {.e = e, .mp = mp, .cap = cap, .slot = eth1,
                           .peer_mac = peer_mac};
    pthread_t th;
    CHECK(pthread_create(&th, NULL, ping6_responder, &pa) == 0);
    char *out = NULL;
    CHECK(tr_engine_ping(e, &target, NULL, NULL, 1, 1000, 56, &out) == 0);
    pthread_join(th, NULL);
    CHECK(out != NULL);
    if (!strstr(out, "1 received")) {
        fprintf(stderr, "ping6 output:\n%s\n", out);
        CHECK(0);
    }
    /* The queued request must have been flushed to the resolved next hop with
     * the router's own address as the source. */
    struct rte_mbuf *req = find_icmp6(cap, 128, NULL);
    CHECK(req != NULL);
    if (req) {
        uint8_t *p = mtod(req);
        struct in6_addr src, dst;
        CHECK(memcmp(p, peer_mac, 6) == 0);
        CHECK(memcmp(p + 6, eth1_mac, 6) == 0);
        memcpy(&src, p + 14 + 8, 16);
        memcpy(&dst, p + 14 + 24, 16);
        CHECK(tr_ip_is_unspecified(&(struct tr_ip){.family = TR_AF_INET6,
                                                   .u.v6 = src}) == false);
        struct in6_addr want;
        inet_pton(AF_INET6, "2001:db8:2::2", &want);
        CHECK(memcmp(&dst, &want, 16) == 0);
    }
    /* A frame the engine originates (the NS) is submitted with
     * worker == e->workers: that is how the DPDK TX path tells control-plane
     * traffic apart from worker batches.  The queued echo request is flushed
     * from the context of the worker that processed the NA, so it keeps that
     * worker index and travels through the worker's batch. */
    int ns_idx = -1, req_idx = -1;
    CHECK(find_icmp6(cap, 135, &ns_idx) != NULL);
    CHECK(find_icmp6(cap, 128, &req_idx) != NULL);
    if (ns_idx >= 0)
        CHECK(cap->worker[ns_idx] == 1);
    if (req_idx >= 0)
        CHECK(cap->worker[req_idx] == 0);
    free(out);
    capture_reset(cap);
    tr_engine_destroy(e);
    return 0;
}

static int test_malformed(struct rte_mempool *mp, struct capture *cap)
{
    struct tr_config cfg, env_cfg;
    struct tr_config_env env;
    struct tr_engine *e;
    char err[256];
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};

    setup_config(&cfg, &env);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces ethernet eth0 port 0") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 address 192.0.2.1/24") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 address 2001:db8:1::1/64") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth0 vlan-id 30 mtu 1500") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces bridge br0 children eth0.30") == 0);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces tunnel tun0 remote 2001:db8::2") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 local-address 2001:db8:1::1") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 local-interface eth0") == 0);
    CHECK(test_apply_ok(&cfg, &env, "set interfaces tunnel tun0 mtu 9000") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 encapsulation etherip6") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun0 address 10.9.0.1/30") == 0);
    CHECK(set_mac(&cfg, "eth0", eth0_mac) == 0);
    e = tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    CHECK(e != NULL);
    tr_engine_set_tx(e, capture_tx, cap);
    CHECK(tr_engine_apply(e, &cfg, err, sizeof(err)) == 0);
    tr_engine_config_copy(e, &env_cfg);
    int slots[3] = {
        tr_config_find_const(&env_cfg, "eth0")->slot,
        tr_config_find_const(&env_cfg, "eth0.30")->slot,
        tr_config_find_const(&env_cfg, "tun0")->slot,
    };
    uint32_t seed = 0x12345678;
    for (int i = 0; i < 3000; i++) {
        seed = seed * 1664525u + 1013904223u;
        uint32_t len = 1 + (seed % 2000);
        struct rte_mbuf *m = alloc_frame(mp, len);
        CHECK(m != NULL);
        uint8_t *p = mtod(m);
        for (uint32_t j = 0; j < len; j++) {
            seed = seed * 1664525u + 1013904223u;
            p[j] = (uint8_t)(seed >> 24);
        }
        CHECK(tr_engine_input(e, 0, slots[i % 3], m) == 0);
        capture_reset(cap);
    }
    tr_engine_destroy(e);
    return 0;
}

int main(void)
{
    char *eal_argv[] = {"test_engine", "--no-huge", "--no-pci",
                        "--lcores",    "0",         "-m",
                        "512",         NULL};
    int eal_argc = 7;
    if (rte_eal_init(eal_argc, eal_argv) < 0) {
        fprintf(stderr, "EAL init failed (set XDG_RUNTIME_DIR)\n");
        return 1;
    }
    if (tr_tunnel_drivers_init()) {
        fprintf(stderr, "driver init failed\n");
        return 1;
    }
    struct rte_mempool *mp =
        rte_pktmbuf_pool_create("test_pool", 4096, 256, 0, 10240,
                                rte_socket_id());
    if (!mp) {
        fprintf(stderr, "mempool failed: %s\n", rte_strerror(rte_errno));
        return 1;
    }
    struct capture cap = {0};
    int rc = 0;
    rc |= test_checksum();
    rc |= test_drop_reasons(mp, &cap);
    rc |= test_arp(mp, &cap);
    rc |= test_ipv4_route(mp, &cap);
    rc |= test_ndp(mp, &cap);
    rc |= test_tunnel_overlay(mp, &cap);
    rc |= test_mss_clamp_decap(mp, &cap);
    rc |= test_vlan(mp, &cap);
    rc |= test_vlan_autoconf(mp, &cap);
    rc |= test_qinq(mp, &cap);
    rc |= test_bridge(mp, &cap);
    rc |= test_autoconf(mp, &cap);
    rc |= test_ping(mp, &cap);
    rc |= test_ping6(mp, &cap);
    rc |= test_traceroute(mp, &cap);
    rc |= test_etherip4(mp, &cap);
    rc |= test_malformed(mp, &cap);
    capture_reset(&cap);
    rte_mempool_free(mp);
    tr_tunnel_drivers_fini();
    rte_eal_cleanup();
    if (rc == 0)
        printf("test_engine: ok\n");
    return rc;
}
