#include "engine.h"

#include "addr.h"
#include "bridge.h"
#include "config_internal.h"
#include "fib.h"
#include "neigh.h"
#include "reasm.h"
#include "tunnel.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ETH_HLEN 14
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_IPV6 0x86dd
#define ETH_TYPE_VLAN 0x8100
#define ETH_TYPE_QINQ 0x88a8

#ifndef IPPROTO_ETHERIP
#define IPPROTO_ETHERIP 97
#endif

#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_TIME_EXCEEDED 11
#define ICMP_ECHO 8
#define ICMP_FRAG_NEEDED 4
#define ICMPV6_DEST_UNREACH 1
#define ICMPV6_PACKET_TOO_BIG 2
#define ICMPV6_TIME_EXCEEDED 3
#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129
#define ICMPV6_ROUTER_SOLICIT 133
#define ICMPV6_ROUTER_ADVERT 134
#define ICMPV6_NEIGH_SOLICIT 135
#define ICMPV6_NEIGH_ADVERT 136

#define TR_LOCAL_MAX 512
#define TR_DYN_ADDR_MAX 64
#define TR_DYN_ROUTE_MAX 64
#define TR_RA_QUEUE 64

struct tr_tunnel_rt {
    bool ready;
    const struct tr_tnl_driver *driver;
    uint8_t family;
    int local_if_slot;
    struct tr_ip local;
    struct tr_ip remote;
    uint32_t mtu;
    int tcp_mss;
};

struct tr_local_addr {
    struct tr_ip ip;
    int if_slot;
    bool linklocal;
    bool dynamic;
};

struct tr_dyn_addr {
    bool used;
    int if_slot;
    struct tr_prefix prefix;
    uint64_t expires_ms;
};

struct tr_dyn_route {
    bool used;
    struct tr_prefix prefix;
    struct tr_ip via;
    int if_slot;
    uint64_t expires_ms;
};

struct tr_ra_event {
    int if_slot;
    struct tr_prefix prefix;
    struct tr_ip router;
    uint32_t lifetime;
    uint32_t valid;
    uint32_t mtu;
};

struct tr_runtime {
    uint64_t generation;
    struct tr_config cfg;
    struct tr_fib fib;
    struct tr_tunnel_rt tunnel[TR_MAX_IFACES];
    struct tr_local_addr locals[TR_LOCAL_MAX];
    int nlocals;
};

struct tr_engine {
    pthread_rwlock_t rt_lock;
    struct tr_runtime *rt;
    uint64_t generation;
    int n_ports;
    int workers;
    struct rte_mempool *mp;
    tr_tx_fn tx;
    void *tx_arg;

    struct tr_neigh_table neigh4;
    struct tr_neigh_table neigh6;
    struct tr_bridge_db bridges;
    struct tr_reasm reasm[TR_MAX_WORKERS];

    struct tr_if_stats stats[TR_MAX_IFACES][TR_MAX_WORKERS];

    struct tr_dyn_addr dyn_addr[TR_DYN_ADDR_MAX];
    struct tr_dyn_route dyn_route[TR_DYN_ROUTE_MAX];

    pthread_mutex_t ra_lock;
    struct tr_ra_event raq[TR_RA_QUEUE];
    int ra_head;
    int ra_tail;

    bool rs_sent;
};

static void free_mbuf_cb(void *pkt)
{
    if (pkt)
        rte_pktmbuf_free((struct rte_mbuf *)pkt);
}

static struct tr_iface *rt_iface(struct tr_runtime *rt, int slot)
{
    if (!rt || slot < 0 || slot >= TR_MAX_IFACES)
        return NULL;
    return rt->cfg.ifaces[slot].present ? &rt->cfg.ifaces[slot] : NULL;
}

static const struct tr_iface *rt_iface_c(const struct tr_runtime *rt, int slot)
{
    if (!rt || slot < 0 || slot >= TR_MAX_IFACES)
        return NULL;
    return rt->cfg.ifaces[slot].present ? &rt->cfg.ifaces[slot] : NULL;
}

static uint8_t *mtod(struct rte_mbuf *m)
{
    return rte_pktmbuf_mtod(m, uint8_t *);
}

static uint32_t mlen(const struct rte_mbuf *m)
{
    return rte_pktmbuf_pkt_len(m);
}

static int pkt_single(const struct rte_mbuf *m)
{
    return rte_pktmbuf_is_contiguous(m) && m->nb_segs == 1;
}

static void stats_drop(struct tr_engine *e, int worker, int if_slot)
{
    if (if_slot >= 0 && if_slot < TR_MAX_IFACES && worker >= 0 &&
        worker < TR_MAX_WORKERS)
        atomic_fetch_add_explicit(&e->stats[if_slot][worker].drops, 1,
                                  memory_order_relaxed);
}

static void stats_rx(struct tr_engine *e, int worker, int if_slot,
                     uint32_t len)
{
    if (if_slot >= 0 && if_slot < TR_MAX_IFACES && worker >= 0 &&
        worker < TR_MAX_WORKERS) {
        atomic_fetch_add_explicit(&e->stats[if_slot][worker].rx_pkts, 1,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&e->stats[if_slot][worker].rx_bytes, len,
                                  memory_order_relaxed);
    }
}

static void stats_tx(struct tr_engine *e, int worker, int if_slot,
                     uint32_t len)
{
    if (if_slot >= 0 && if_slot < TR_MAX_IFACES && worker >= 0 &&
        worker < TR_MAX_WORKERS) {
        atomic_fetch_add_explicit(&e->stats[if_slot][worker].tx_pkts, 1,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&e->stats[if_slot][worker].tx_bytes, len,
                                  memory_order_relaxed);
    }
}

static void stats_inc_arp(struct tr_engine *e, int worker, int if_slot)
{
    if (if_slot >= 0 && if_slot < TR_MAX_IFACES && worker >= 0 &&
        worker < TR_MAX_WORKERS)
        atomic_fetch_add_explicit(&e->stats[if_slot][worker].arp_tx, 1,
                                  memory_order_relaxed);
}

static void stats_inc_ndp(struct tr_engine *e, int worker, int if_slot)
{
    if (if_slot >= 0 && if_slot < TR_MAX_IFACES && worker >= 0 &&
        worker < TR_MAX_WORKERS)
        atomic_fetch_add_explicit(&e->stats[if_slot][worker].ndp_tx, 1,
                                  memory_order_relaxed);
}


static bool dyn_addr_valid(const struct tr_dyn_addr *d, uint64_t now)
{
    return d->used && (d->expires_ms == 0 || now < d->expires_ms);
}

static bool dyn_route_valid(const struct tr_dyn_route *r, uint64_t now)
{
    return r->used && (r->expires_ms == 0 || now < r->expires_ms);
}

static void runtime_free(struct tr_runtime *rt)
{
    if (!rt)
        return;
    tr_fib_destroy(&rt->fib);
    free(rt);
}

static void local_add(struct tr_runtime *rt, const struct tr_ip *ip,
                      int if_slot, bool linklocal, bool dynamic)
{
    if (rt->nlocals >= TR_LOCAL_MAX)
        return;
    for (int i = 0; i < rt->nlocals; i++) {
        if (rt->locals[i].if_slot == if_slot &&
            tr_ip_equal(&rt->locals[i].ip, ip))
            return;
    }
    rt->locals[rt->nlocals].ip = *ip;
    rt->locals[rt->nlocals].if_slot = if_slot;
    rt->locals[rt->nlocals].linklocal = linklocal;
    rt->locals[rt->nlocals].dynamic = dynamic;
    rt->nlocals++;
}

static int runtime_build(struct tr_engine *e, const struct tr_config *cfg,
                         struct tr_runtime **out, char *err, size_t errlen)
{
    struct tr_runtime *rt = calloc(1, sizeof(*rt));
    struct tr_fib_extra extras[TR_DYN_ADDR_MAX + TR_DYN_ROUTE_MAX + 128];
    int nextras = 0;
    uint64_t now = tr_monotonic_ms();

    if (!rt) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    rt->generation = ++e->generation;
    tr_config_copy(&rt->cfg, cfg);
    tr_fib_init(&rt->fib);

    for (int i = 0; i < TR_MAX_IFACES; i++) {
        struct tr_iface *iface = &rt->cfg.ifaces[i];
        if (!iface->present)
            continue;
        if (iface->kind == TR_IF_TUNNEL) {
            struct tr_tunnel_rt *t = &rt->tunnel[i];
            t->driver = tr_tunnel_driver_find(iface->tunnel.driver);
            t->remote = iface->tunnel.remote;
            t->local = iface->tunnel.local;
            t->family = iface->tunnel.remote.family;
            t->mtu = iface->mtu;
            t->tcp_mss = iface->tunnel.tcp_mss;
            t->local_if_slot = -1;
            if (iface->tunnel.local_if[0]) {
                const struct tr_iface *li =
                    tr_config_find_const(&rt->cfg,
                                         iface->tunnel.local_if);
                if (li)
                    t->local_if_slot = li->slot;
            }
            t->ready = t->driver && t->remote.family &&
                       (t->local.family || t->local_if_slot >= 0);
        }
        if (iface->kind == TR_IF_BRIDGE)
            continue;
        for (int a = 0; a < iface->naddrs; a++)
            local_add(rt, &iface->addrs[a].addr, i, false, false);
        if (iface->bridge < 0 && iface->kind != TR_IF_BRIDGE) {
            struct in6_addr ll;
            struct tr_ip ip = {.family = TR_AF_INET6};
            tr_ip6_linklocal(iface->mac, &ll);
            ip.u.v6 = ll;
            local_add(rt, &ip, i, true, false);
        }
    }
    /* A tunnel pinned to a local interface needs a source address of the
     * outer family before it can be considered operational. */
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        struct tr_tunnel_rt *t = &rt->tunnel[i];
        if (!t->ready || t->local.family || t->local_if_slot < 0)
            continue;
        bool have_src = false;
        for (int l = 0; l < rt->nlocals; l++) {
            if (rt->locals[l].if_slot == t->local_if_slot &&
                rt->locals[l].ip.family == t->family) {
                have_src = true;
                break;
            }
        }
        if (!have_src)
            t->ready = false;
    }
    for (int i = 0; i < TR_DYN_ADDR_MAX; i++) {
        struct tr_dyn_addr *d = &e->dyn_addr[i];
        if (!dyn_addr_valid(d, now))
            continue;
        local_add(rt, &d->prefix.addr, d->if_slot, false, true);
        extras[nextras].prefix = d->prefix;
        extras[nextras].has_via = false;
        extras[nextras].if_slot = d->if_slot;
        extras[nextras].route_id = -10000 - i;
        nextras++;
    }
    for (int i = 0; i < TR_DYN_ROUTE_MAX; i++) {
        struct tr_dyn_route *d = &e->dyn_route[i];
        if (!dyn_route_valid(d, now))
            continue;
        extras[nextras].prefix = d->prefix;
        extras[nextras].via = d->via;
        extras[nextras].has_via = true;
        extras[nextras].if_slot = d->if_slot;
        extras[nextras].route_id = -20000 - i;
        nextras++;
    }
    if (tr_fib_build(&rt->fib, &rt->cfg, extras, nextras, err, errlen)) {
        runtime_free(rt);
        return -1;
    }
    *out = rt;
    return 0;
}

struct tr_engine *tr_engine_create(const struct tr_engine_params *params,
                                   char *err, size_t errlen)
{
    struct tr_engine *e;
    struct tr_config empty;
    struct tr_runtime *rt = NULL;

    if (!params || !params->mp || params->workers < 1 ||
        params->workers > TR_MAX_WORKERS) {
        snprintf(err, errlen, "invalid engine parameters");
        return NULL;
    }
    e = calloc(1, sizeof(*e));
    if (!e) {
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    e->n_ports = params->n_ports;
    e->workers = params->workers;
    e->mp = params->mp;
    pthread_rwlock_init(&e->rt_lock, NULL);
    pthread_mutex_init(&e->ra_lock, NULL);
    tr_neigh_init(&e->neigh4, free_mbuf_cb);
    tr_neigh_init(&e->neigh6, free_mbuf_cb);
    tr_bridge_db_init(&e->bridges);
    for (int i = 0; i < TR_MAX_WORKERS; i++)
        tr_reasm_init(&e->reasm[i]);

    tr_config_init(&empty);
    if (runtime_build(e, &empty, &rt, err, errlen)) {
        snprintf(err, errlen, "cannot build initial runtime");
        tr_engine_destroy(e);
        return NULL;
    }
    e->rt = rt;
    return e;
}

void tr_engine_destroy(struct tr_engine *e)
{
    if (!e)
        return;
    runtime_free(e->rt);
    e->rt = NULL;
    tr_neigh_fini(&e->neigh4);
    tr_neigh_fini(&e->neigh6);
    tr_bridge_db_fini(&e->bridges);
    for (int i = 0; i < TR_MAX_WORKERS; i++)
        tr_reasm_fini(&e->reasm[i]);
    pthread_mutex_destroy(&e->ra_lock);
    pthread_rwlock_destroy(&e->rt_lock);
    free(e);
}

void tr_engine_set_tx(struct tr_engine *e, tr_tx_fn tx, void *arg)
{
    e->tx = tx;
    e->tx_arg = arg;
}

void tr_engine_config_env(struct tr_engine *e, struct tr_config_env *env)
{
    env->n_ports = e->n_ports;
    env->port_valid = NULL;
    env->port_names = NULL;
}

int tr_engine_apply(struct tr_engine *e, const struct tr_config *cfg,
                    char *err, size_t errlen)
{
    struct tr_runtime *nr = NULL;
    struct tr_runtime *old;

    if (runtime_build(e, cfg, &nr, err, errlen))
        return -1;
    pthread_rwlock_wrlock(&e->rt_lock);
    old = e->rt;
    e->rt = nr;
    /* Topology may have changed; stale L2/L3 bindings must not survive.
     * No worker can be in the data path while the write lock is held. */
    tr_neigh_clear(&e->neigh4);
    tr_neigh_clear(&e->neigh6);
    for (int i = 0; i < TR_MAX_IFACES; i++)
        tr_bridge_clear(&e->bridges, i);
    pthread_rwlock_unlock(&e->rt_lock);
    runtime_free(old);
    return 0;
}

int tr_engine_config_copy(struct tr_engine *e, struct tr_config *out)
{
    pthread_rwlock_rdlock(&e->rt_lock);
    if (e->rt) {
        tr_config_copy(out, &e->rt->cfg);
    } else {
        tr_config_init(out);
        pthread_rwlock_unlock(&e->rt_lock);
        return -1;
    }
    pthread_rwlock_unlock(&e->rt_lock);
    return 0;
}

static struct rte_mbuf *pkt_alloc(struct tr_engine *e, uint32_t len)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(e->mp);
    if (!m)
        return NULL;
    if (rte_pktmbuf_append(m, (uint16_t)len) == NULL) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    return m;
}

static struct rte_mbuf *pkt_dup(struct tr_engine *e, struct rte_mbuf *m)
{
    return rte_pktmbuf_copy(m, e->mp, 0, mlen(m));
}

static int pkt_prepend(struct rte_mbuf *m, uint32_t len)
{
    return rte_pktmbuf_prepend(m, (uint16_t)len) ? 0 : -1;
}

static int pkt_add_vlan(struct rte_mbuf *m, uint16_t vid)
{
    uint8_t *p;
    uint32_t len = mlen(m);

    if (len < 12 || !pkt_single(m))
        return -1;
    p = (uint8_t *)rte_pktmbuf_prepend(m, 4);
    if (!p)
        return -1;
    memmove(p, p + 4, 12);
    uint16_t tci = (uint16_t)(vid & 0x0fff);
    p[12] = ETH_TYPE_VLAN >> 8;
    p[13] = ETH_TYPE_VLAN & 0xff;
    p[14] = (uint8_t)(tci >> 8);
    p[15] = (uint8_t)tci;
    return 0;
}

static int pkt_strip_vlan(struct rte_mbuf *m, uint16_t *vid)
{
    uint8_t *p = mtod(m);
    uint32_t len = mlen(m);

    if (len < 18 || p[12] != (ETH_TYPE_VLAN >> 8) || p[13] != 0x00 ||
        !pkt_single(m))
        return -1;
    if (vid)
        *vid = (uint16_t)((p[14] << 8 | p[15]) & 0x0fff);
    memmove(p + 12, p + 16, len - 16);
    rte_pktmbuf_trim(m, 4);
    return 0;
}

static bool pkt_tagged(const struct rte_mbuf *m)
{
    const uint8_t *p;

    if (mlen(m) < 14 || !pkt_single(m))
        return false;
    p = rte_pktmbuf_mtod(m, const uint8_t *);
    return p[12] == (ETH_TYPE_VLAN >> 8) && p[13] == 0x00;
}




static const struct tr_iface *iface_by_slot_rt(const struct tr_runtime *rt,
                                                int slot)
{
    return rt_iface_c(rt, slot);
}


static bool is_local_if(const struct tr_runtime *rt, int if_slot,
                        const struct tr_ip *ip)
{
    for (int i = 0; i < rt->nlocals; i++) {
        if (rt->locals[i].if_slot == if_slot &&
            tr_ip_equal(&rt->locals[i].ip, ip))
            return true;
    }
    return false;
}


static int pick_addr(const struct tr_runtime *rt, int if_slot, uint8_t family,
                     bool prefer_linklocal, struct tr_ip *out)
{
    bool have = false;

    for (int i = 0; i < rt->nlocals; i++) {
        const struct tr_local_addr *l = &rt->locals[i];
        if (l->if_slot != if_slot || l->ip.family != family)
            continue;
        if (family == TR_AF_INET6 && prefer_linklocal &&
            tr_ip_is_linklocal(&l->ip)) {
            *out = l->ip;
            return 0;
        }
        if (!have || (family == TR_AF_INET6 && !l->linklocal)) {
            *out = l->ip;
            have = true;
            if (family == TR_AF_INET6 && !prefer_linklocal && !l->linklocal)
                break;
        }
    }
    return have ? 0 : -1;
}

static uint32_t checksum_add_pseudo4(uint32_t sum, const uint8_t *src,
                                     const uint8_t *dst, uint8_t proto,
                                     uint16_t len)
{
    sum = tr_checksum_add(sum, src, 4);
    sum = tr_checksum_add(sum, dst, 4);
    sum += proto;
    sum += len;
    return sum;
}

static uint32_t checksum_add_pseudo6(uint32_t sum, const uint8_t *src,
                                     const uint8_t *dst, uint8_t proto,
                                     uint32_t len)
{
    sum = tr_checksum_add(sum, src, 16);
    sum = tr_checksum_add(sum, dst, 16);
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    sum += proto;
    return sum;
}

static void tunnel_send(struct tr_engine *e, int worker,
                        struct tr_runtime *rt, int if_slot,
                        struct rte_mbuf *m);
static void resolve_and_send(struct tr_engine *e, int worker,
                             struct tr_runtime *rt, int if_slot,
                             const struct tr_ip *next_hop,
                             struct rte_mbuf *m);
static void send_neighbor_request(struct tr_engine *e, int worker,
                                  struct tr_runtime *rt, int if_slot,
                                  const struct tr_ip *target, uint8_t family);

static void l2_emit(struct tr_engine *e, int worker, struct tr_runtime *rt,
                    int if_slot, struct rte_mbuf *m)
{
    const struct tr_iface *iface = iface_by_slot_rt(rt, if_slot);
    uint32_t maxlen;

    if (!iface || !m) {
        if (m)
            rte_pktmbuf_free(m);
        return;
    }
    if (iface->kind == TR_IF_VLAN && !pkt_tagged(m)) {
        if (pkt_add_vlan(m, (uint16_t)iface->vlan_id)) {
            stats_drop(e, worker, if_slot);
            rte_pktmbuf_free(m);
            return;
        }
    }
    maxlen = iface->mtu + ETH_HLEN + (pkt_tagged(m) ? 4 : 0);
    if (mlen(m) > maxlen) {
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    if (!e->tx) {
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    stats_tx(e, worker, if_slot, mlen(m));
    e->tx(e->tx_arg, worker, if_slot, m);
}

static void egress_frame(struct tr_engine *e, int worker,
                         struct tr_runtime *rt, int if_slot,
                         struct rte_mbuf *m)
{
    const struct tr_iface *iface = iface_by_slot_rt(rt, if_slot);

    if (!iface) {
        rte_pktmbuf_free(m);
        return;
    }
    if (iface->kind == TR_IF_TUNNEL)
        tunnel_send(e, worker, rt, if_slot, m);
    else
        l2_emit(e, worker, rt, if_slot, m);
}

static int build_ip4(uint8_t *p, uint32_t len, uint8_t proto,
                     const uint8_t src[4], const uint8_t dst[4], uint8_t ttl,
                     uint16_t id)
{
    memset(p, 0, 20);
    p[0] = 0x45;
    p[2] = (uint8_t)(len >> 8);
    p[3] = (uint8_t)len;
    p[4] = (uint8_t)(id >> 8);
    p[5] = (uint8_t)id;
    p[6] = 0x40; /* DF */
    p[8] = ttl;
    p[9] = proto;
    memcpy(p + 12, src, 4);
    memcpy(p + 16, dst, 4);
    uint16_t csum = tr_checksum16(p, 20, 0);
    p[10] = (uint8_t)(csum >> 8);
    p[11] = (uint8_t)csum;
    return 0;
}

static void build_ip6(uint8_t *p, uint16_t plen, uint8_t next,
                      const uint8_t src[16], const uint8_t dst[16],
                      uint8_t hop)
{
    uint32_t vtf = 6u << 28;
    p[0] = (uint8_t)(vtf >> 24);
    p[1] = (uint8_t)(vtf >> 16);
    p[2] = (uint8_t)(vtf >> 8);
    p[3] = (uint8_t)vtf;
    p[4] = (uint8_t)(plen >> 8);
    p[5] = (uint8_t)plen;
    p[6] = next;
    p[7] = hop;
    memcpy(p + 8, src, 16);
    memcpy(p + 24, dst, 16);
}

static void send_arp_request(struct tr_engine *e, int worker,
                             struct tr_runtime *rt, int if_slot,
                             const struct tr_ip *target)
{
    const struct tr_iface *iface = iface_by_slot_rt(rt, if_slot);
    struct tr_ip src;
    struct rte_mbuf *m;
    uint8_t *p;
    static const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    if (!iface || target->family != TR_AF_INET ||
        pick_addr(rt, if_slot, TR_AF_INET, false, &src))
        return;
    m = pkt_alloc(e, 42);
    if (!m)
        return;
    p = mtod(m);
    memcpy(p, bcast, 6);
    memcpy(p + 6, iface->mac, 6);
    p[12] = ETH_TYPE_ARP >> 8;
    p[13] = ETH_TYPE_ARP & 0xff;
    p[14] = 0x00;
    p[15] = 0x01;
    p[16] = 0x08;
    p[17] = 0x00;
    p[18] = 6;
    p[19] = 4;
    p[20] = 0;
    p[21] = 1;
    memcpy(p + 22, iface->mac, 6);
    memcpy(p + 28, &src.u.v4, 4);
    memset(p + 32, 0, 6);
    memcpy(p + 38, &target->u.v4, 4);
    stats_inc_arp(e, worker, if_slot);
    egress_frame(e, worker, rt, if_slot, m);
}

static void send_ndp_ns(struct tr_engine *e, int worker,
                        struct tr_runtime *rt, int if_slot,
                        const struct tr_ip *target)
{
    const struct tr_iface *iface = iface_by_slot_rt(rt, if_slot);
    struct tr_ip src;
    struct in6_addr sn;
    struct rte_mbuf *m;
    uint8_t *p, *icmp;
    uint32_t sum;
    static const uint8_t eth_sn[6] = {0x33, 0x33, 0xff, 0, 0, 0};

    if (!iface || target->family != TR_AF_INET6 ||
        pick_addr(rt, if_slot, TR_AF_INET6, true, &src))
        return;
    tr_ip6_solicited_node(&target->u.v6, &sn);
    m = pkt_alloc(e, 14 + 40 + 32);
    if (!m)
        return;
    p = mtod(m);
    memcpy(p, eth_sn, 6);
    p[3] = target->u.v6.s6_addr[13];
    p[4] = target->u.v6.s6_addr[14];
    p[5] = target->u.v6.s6_addr[15];
    memcpy(p + 6, iface->mac, 6);
    p[12] = ETH_TYPE_IPV6 >> 8;
    p[13] = ETH_TYPE_IPV6 & 0xff;
    build_ip6(p + 14, 32, IPPROTO_ICMPV6, (const uint8_t *)&src.u.v6,
              (const uint8_t *)&sn, 255);
    icmp = p + 14 + 40;
    memset(icmp, 0, 32);
    icmp[0] = ICMPV6_NEIGH_SOLICIT;
    memcpy(icmp + 8, &target->u.v6, 16);
    icmp[24] = 1;
    icmp[25] = 1;
    memcpy(icmp + 26, iface->mac, 6);
    sum = checksum_add_pseudo6(0, (const uint8_t *)&src.u.v6,
                               (const uint8_t *)&sn, IPPROTO_ICMPV6, 32);
    sum = tr_checksum_add(sum, icmp, 32);
    uint16_t csum = tr_checksum16_finish(sum);
    icmp[2] = (uint8_t)(csum >> 8);
    icmp[3] = (uint8_t)csum;
    stats_inc_ndp(e, worker, if_slot);
    egress_frame(e, worker, rt, if_slot, m);
}

static void send_ndp_na(struct tr_engine *e, int worker,
                        struct tr_runtime *rt, int if_slot,
                        const struct tr_ip *target, const uint8_t dst_mac[6],
                        const struct tr_ip *dst_ip, bool solicited)
{
    const struct tr_iface *iface = iface_by_slot_rt(rt, if_slot);
    struct rte_mbuf *m;
    uint8_t *p, *icmp;
    struct in6_addr dst6;
    uint32_t sum;

    if (!iface || target->family != TR_AF_INET6)
        return;
    if (dst_ip && dst_ip->family == TR_AF_INET6)
        dst6 = dst_ip->u.v6;
    else
        memset(&dst6, 0, sizeof(dst6)), dst6.s6_addr[0] = 0xff,
        dst6.s6_addr[1] = 0x02, dst6.s6_addr[15] = 0x01;
    m = pkt_alloc(e, 14 + 40 + 32);
    if (!m)
        return;
    p = mtod(m);
    memcpy(p, dst_mac, 6);
    memcpy(p + 6, iface->mac, 6);
    p[12] = ETH_TYPE_IPV6 >> 8;
    p[13] = ETH_TYPE_IPV6 & 0xff;
    build_ip6(p + 14, 32, IPPROTO_ICMPV6, (const uint8_t *)&target->u.v6,
              (const uint8_t *)&dst6, 255);
    icmp = p + 54;
    memset(icmp, 0, 32);
    icmp[0] = ICMPV6_NEIGH_ADVERT;
    icmp[4] = solicited ? 0x60 : 0x00;
    memcpy(icmp + 8, &target->u.v6, 16);
    icmp[24] = 2;
    icmp[25] = 1;
    memcpy(icmp + 26, iface->mac, 6);
    sum = checksum_add_pseudo6(0, (const uint8_t *)&target->u.v6,
                               (const uint8_t *)&dst6, IPPROTO_ICMPV6, 32);
    sum = tr_checksum_add(sum, icmp, 32);
    uint16_t csum = tr_checksum16_finish(sum);
    icmp[2] = (uint8_t)(csum >> 8);
    icmp[3] = (uint8_t)csum;
    egress_frame(e, worker, rt, if_slot, m);
}

static void send_echo_reply4(struct tr_engine *e, int worker,
                             struct tr_runtime *rt, int if_slot,
                             struct rte_mbuf *orig, uint32_t l3off)
{
    const struct tr_iface *iface = iface_by_slot_rt(rt, if_slot);
    uint8_t *op = mtod(orig) + l3off;
    uint32_t ip_len, icmp_len;
    struct rte_mbuf *m;
    uint8_t *p, *icmp, *oicmp;
    uint16_t csum;

    if (!iface || mlen(orig) < l3off + 20)
        return;
    ip_len = (uint32_t)(op[2] << 8 | op[3]);
    if (ip_len < 20 || ip_len > mlen(orig) - l3off)
        return;
    icmp_len = ip_len - 20;
    m = pkt_alloc(e, 14 + 20 + icmp_len);
    if (!m)
        return;
    p = mtod(m);
    memcpy(p, mtod(orig) + 6, 6);
    memcpy(p + 6, iface->mac, 6);
    p[12] = ETH_TYPE_IPV4 >> 8;
    p[13] = ETH_TYPE_IPV4 & 0xff;
    build_ip4(p + 14, 20 + icmp_len, IPPROTO_ICMP, op + 16, op + 12, 64, 0);
    icmp = p + 34;
    oicmp = op + 20;
    memcpy(icmp, oicmp, icmp_len);
    icmp[0] = ICMP_ECHO_REPLY;
    icmp[1] = 0;
    icmp[2] = 0;
    icmp[3] = 0;
    csum = tr_checksum16(icmp, icmp_len, 0);
    icmp[2] = (uint8_t)(csum >> 8);
    icmp[3] = (uint8_t)csum;
    egress_frame(e, worker, rt, if_slot, m);
}

static void send_echo_reply6(struct tr_engine *e, int worker,
                             struct tr_runtime *rt, int if_slot,
                             struct rte_mbuf *orig, uint32_t l3off)
{
    const struct tr_iface *iface = iface_by_slot_rt(rt, if_slot);
    uint8_t *op = mtod(orig) + l3off;
    uint32_t plen;
    struct rte_mbuf *m;
    uint8_t *p, *icmp, *oicmp;
    uint32_t sum;

    if (!iface || mlen(orig) < l3off + 40)
        return;
    plen = (uint32_t)(op[4] << 8 | op[5]);
    if (plen > mlen(orig) - l3off - 40)
        return;
    m = pkt_alloc(e, 14 + 40 + plen);
    if (!m)
        return;
    p = mtod(m);
    memcpy(p, mtod(orig) + 6, 6);
    memcpy(p + 6, iface->mac, 6);
    p[12] = ETH_TYPE_IPV6 >> 8;
    p[13] = ETH_TYPE_IPV6 & 0xff;
    build_ip6(p + 14, (uint16_t)plen, IPPROTO_ICMPV6, op + 24, op + 8, 64);
    icmp = p + 54;
    oicmp = op + 40;
    memcpy(icmp, oicmp, plen);
    icmp[0] = ICMPV6_ECHO_REPLY;
    icmp[1] = 0;
    icmp[2] = 0;
    icmp[3] = 0;
    sum = checksum_add_pseudo6(0, op + 24, op + 8, IPPROTO_ICMPV6, plen);
    sum = tr_checksum_add(sum, icmp, plen);
    uint16_t csum = tr_checksum16_finish(sum);
    icmp[2] = (uint8_t)(csum >> 8);
    icmp[3] = (uint8_t)csum;
    egress_frame(e, worker, rt, if_slot, m);
}

static void send_icmp4_error(struct tr_engine *e, int worker,
                             struct tr_runtime *rt, int if_slot,
                             struct rte_mbuf *orig, uint32_t l3off,
                             uint8_t type, uint8_t code, uint16_t mtu)
{
    const struct tr_iface *iface = iface_by_slot_rt(rt, if_slot);
    uint8_t *op = mtod(orig) + l3off;
    uint32_t oip_len;
    uint32_t inner;
    struct rte_mbuf *m;
    uint8_t *p, *icmp;

    if (!iface || mlen(orig) < l3off + 20)
        return;
    oip_len = (uint32_t)(op[2] << 8 | op[3]);
    if (oip_len > mlen(orig) - l3off)
        oip_len = mlen(orig) - l3off;
    inner = oip_len < 28 ? oip_len : 28;
    m = pkt_alloc(e, 14 + 20 + 8 + inner);
    if (!m)
        return;
    p = mtod(m);
    memcpy(p, mtod(orig) + 6, 6);
    memcpy(p + 6, iface->mac, 6);
    p[12] = ETH_TYPE_IPV4 >> 8;
    p[13] = ETH_TYPE_IPV4 & 0xff;
    build_ip4(p + 14, 20 + 8 + inner, IPPROTO_ICMP, op + 16, op + 12, 64, 0);
    icmp = p + 34;
    memset(icmp, 0, 8);
    icmp[0] = type;
    icmp[1] = code;
    if (type == ICMP_DEST_UNREACH && code == ICMP_FRAG_NEEDED) {
        icmp[6] = (uint8_t)(mtu >> 8);
        icmp[7] = (uint8_t)mtu;
    }
    memcpy(icmp + 8, op, inner);
    uint16_t csum = tr_checksum16(icmp, 8 + inner, 0);
    icmp[2] = (uint8_t)(csum >> 8);
    icmp[3] = (uint8_t)csum;
    egress_frame(e, worker, rt, if_slot, m);
}

static void send_icmp6_error(struct tr_engine *e, int worker,
                             struct tr_runtime *rt, int if_slot,
                             struct rte_mbuf *orig, uint32_t l3off,
                             uint8_t type, uint8_t code, uint32_t mtu)
{
    const struct tr_iface *iface = iface_by_slot_rt(rt, if_slot);
    uint8_t *op = mtod(orig) + l3off;
    uint32_t oplen, inner;
    struct rte_mbuf *m;
    uint8_t *p, *icmp;
    struct tr_ip src;
    uint32_t sum;

    if (!iface || mlen(orig) < l3off + 40)
        return;
    oplen = 40u + (uint32_t)(op[4] << 8 | op[5]);
    if (oplen > mlen(orig) - l3off)
        oplen = mlen(orig) - l3off;
    if (oplen > 1232)
        oplen = 1232;
    inner = oplen;
    if (pick_addr(rt, if_slot, TR_AF_INET6, false, &src))
        return;
    m = pkt_alloc(e, 14 + 40 + 8 + inner);
    if (!m)
        return;
    p = mtod(m);
    memcpy(p, mtod(orig) + 6, 6);
    memcpy(p + 6, iface->mac, 6);
    p[12] = ETH_TYPE_IPV6 >> 8;
    p[13] = ETH_TYPE_IPV6 & 0xff;
    build_ip6(p + 14, (uint16_t)(8 + inner), IPPROTO_ICMPV6,
              (const uint8_t *)&src.u.v6, op + 8, 64);
    icmp = p + 54;
    memset(icmp, 0, 8);
    icmp[0] = type;
    icmp[1] = code;
    if (type == ICMPV6_PACKET_TOO_BIG) {
        icmp[4] = (uint8_t)(mtu >> 24);
        icmp[5] = (uint8_t)(mtu >> 16);
        icmp[6] = (uint8_t)(mtu >> 8);
        icmp[7] = (uint8_t)mtu;
    }
    memcpy(icmp + 8, op, inner);
    sum = checksum_add_pseudo6(0, (const uint8_t *)&src.u.v6, op + 8,
                               IPPROTO_ICMPV6, (uint16_t)(8 + inner));
    sum = tr_checksum_add(sum, icmp, 8 + inner);
    uint16_t csum = tr_checksum16_finish(sum);
    icmp[2] = (uint8_t)(csum >> 8);
    icmp[3] = (uint8_t)csum;
    egress_frame(e, worker, rt, if_slot, m);
}

static void flush_pending_family(struct tr_engine *e, int worker,
                                 struct tr_runtime *rt, int if_slot,
                                 const struct tr_ip *ip, const uint8_t mac[6],
                                 uint8_t family)
{
    void *pending[TR_NEIGH_PENDING];
    int n = 0;
    struct tr_neigh_table *t =
        family == TR_AF_INET ? &e->neigh4 : &e->neigh6;

    if (tr_neigh_learn(t, if_slot, ip, mac, tr_monotonic_ms(), pending,
                       TR_NEIGH_PENDING, &n))
        return;
    for (int i = 0; i < n; i++) {
        struct rte_mbuf *m = pending[i];
        if (mlen(m) >= 6)
            memcpy(mtod(m), mac, 6);
        egress_frame(e, worker, rt, if_slot, m);
    }
}

static void send_neighbor_request(struct tr_engine *e, int worker,
                                  struct tr_runtime *rt, int if_slot,
                                  const struct tr_ip *target, uint8_t family)
{
    const struct tr_iface *iface = iface_by_slot_rt(rt, if_slot);

    if (!iface)
        return;
    if (family == TR_AF_INET)
        send_arp_request(e, worker, rt, if_slot, target);
    else if (family == TR_AF_INET6)
        send_ndp_ns(e, worker, rt, if_slot, target);
}

static void resolve_and_send(struct tr_engine *e, int worker,
                             struct tr_runtime *rt, int if_slot,
                             const struct tr_ip *next_hop,
                             struct rte_mbuf *m)
{
    uint8_t mac[6];
    uint8_t state = 0;
    struct tr_neigh_table *t;
    uint64_t now = tr_monotonic_ms();

    if (!m || (next_hop->family != TR_AF_INET &&
               next_hop->family != TR_AF_INET6)) {
        if (m)
            rte_pktmbuf_free(m);
        return;
    }
    t = next_hop->family == TR_AF_INET ? &e->neigh4 : &e->neigh6;
    if (tr_neigh_get(t, if_slot, next_hop, mac, now, &state)) {
        if (mlen(m) >= 6)
            memcpy(mtod(m), mac, 6);
        egress_frame(e, worker, rt, if_slot, m);
        return;
    }
    if (tr_neigh_queue(t, if_slot, next_hop, m, now)) {
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    if (tr_neigh_request_allowed(t, if_slot, next_hop, now, 1000))
        send_neighbor_request(e, worker, rt, if_slot, next_hop,
                              next_hop->family);
}

static int if_slot_stats_valid(struct tr_engine *e, int worker, int if_slot);

static int underlay_next_hop(struct tr_runtime *rt, int if_slot,
                             const struct tr_ip *remote,
                             struct tr_ip *next_hop)
{
    struct tr_fib_result res;

    if (tr_fib_lookup(&rt->fib, remote, &res) == 0 &&
        res.route->if_slot >= 0) {
        if (res.route->connected)
            *next_hop = *remote;
        else if (res.route->has_via)
            *next_hop = res.route->via;
        else
            *next_hop = *remote;
        return 0;
    }
    /* A pinned local-interface may be a point-to-point link with no
     * connected prefix configured. */
    const struct tr_iface *iface = rt_iface(rt, if_slot);
    if (iface && iface->kind != TR_IF_ETHERNET &&
        iface->kind != TR_IF_VLAN)
        return -1;
    if (iface && (iface->kind == TR_IF_ETHERNET ||
                  iface->kind == TR_IF_VLAN)) {
        *next_hop = *remote;
        return 0;
    }
    return -1;
}

static int mss_clamp_frame(struct tr_engine *e, int worker,
                           struct tr_runtime *rt, const struct tr_tunnel_rt *t,
                           int under_slot, struct rte_mbuf *m)
{
    uint8_t *p = mtod(m);
    uint32_t len = mlen(m);
    uint32_t l3off = 14;
    uint8_t family;
    uint8_t *ip;
    uint32_t ip_hlen, total, tcp_off, tcp_len;
    uint8_t *tcp;
    uint16_t max_mss, old_mss;
    int mss_off = -1;

    if (t->tcp_mss < 0 || len < 34)
        return 0;
    if (len >= 18 && p[12] == 0x81 && p[13] == 0x00) {
        l3off = 18;
        if (len < l3off + 20)
            return 0;
    }
    ip = p + l3off;
    family = ip[0] >> 4;
    if (family == 4) {
        ip_hlen = (uint32_t)(ip[0] & 0x0f) * 4;
        total = (uint32_t)(ip[2] << 8 | ip[3]);
        if (ip_hlen < 20 || total < ip_hlen ||
            len < l3off + total || (ip[6] & 0x20) || (ip[6] & 0x1f) ||
            ip[7])
            return 0;
        if (ip[9] != IPPROTO_TCP)
            return 0;
        tcp_len = total - ip_hlen;
    } else if (family == 6) {
        total = 40u + (uint32_t)(ip[4] << 8 | ip[5]);
        if (len < l3off + total || ip[6] != IPPROTO_TCP)
            return 0;
        ip_hlen = 40;
        tcp_len = total - 40;
    } else {
        return 0;
    }
    tcp_off = l3off + ip_hlen;
    if (tcp_off + 20 > len || tcp_len < 20)
        return 0;
    tcp = p + tcp_off;
    uint32_t doff = (uint32_t)(tcp[12] >> 4) * 4;
    if (doff < 20 || doff > tcp_len)
        return 0;
    if (!(tcp[13] & 0x02))
        return 0;
    for (uint32_t o = 20; o + 1 < doff;) {
        uint8_t kind = tcp[o];
        if (kind == 0)
            break;
        if (kind == 1) {
            o++;
            continue;
        }
        if (o + 1 >= doff)
            break;
        uint8_t olen = tcp[o + 1];
        if (olen < 2 || o + olen > doff)
            break;
        if (kind == 2 && olen == 4) {
            mss_off = (int)(o + 2);
            break;
        }
        o += olen;
    }
    if (mss_off < 0)
        return 0;
    old_mss = (uint16_t)(tcp[mss_off] << 8 | tcp[mss_off + 1]);
    if (t->tcp_mss > 0) {
        max_mss = (uint16_t)t->tcp_mss;
    } else {
        const struct tr_iface *under = rt_iface(rt, under_slot);
        if (!under || under->mtu < 100)
            return 0;
        int inner_hdr = family == 4 ? 40 : 60;
        int outer_hdr = t->family == 4 ? 22 : 42;
        int v = (int)under->mtu - outer_hdr - inner_hdr;
        if (v < 64)
            v = 64;
        max_mss = (uint16_t)v;
    }
    if (old_mss <= max_mss)
        return 0;
    tcp[mss_off] = (uint8_t)(max_mss >> 8);
    tcp[mss_off + 1] = (uint8_t)max_mss;
    uint16_t csum;
    uint32_t sum;
    tcp[16] = 0;
    tcp[17] = 0;
    if (family == 4) {
        sum = checksum_add_pseudo4(0, ip + 12, ip + 16, IPPROTO_TCP,
                                   (uint16_t)tcp_len);
        sum = tr_checksum_add(sum, tcp, tcp_len);
        csum = tr_checksum16_finish(sum);
    } else {
        sum = checksum_add_pseudo6(0, ip + 8, ip + 24, IPPROTO_TCP,
                                   (uint16_t)tcp_len);
        sum = tr_checksum_add(sum, tcp, tcp_len);
        csum = tr_checksum16_finish(sum);
    }
    tcp[16] = (uint8_t)(csum >> 8);
    tcp[17] = (uint8_t)csum;
    if (if_slot_stats_valid(e, worker, under_slot))
        atomic_fetch_add_explicit(&e->stats[under_slot][worker].mss_clamped,
                                  1, memory_order_relaxed);
    return 1;
}

static int if_slot_stats_valid(struct tr_engine *e, int worker, int if_slot)
{
    (void)e;
    return if_slot >= 0 && if_slot < TR_MAX_IFACES && worker >= 0 &&
           worker < TR_MAX_WORKERS;
}

static void send_outer_frame(struct tr_engine *e, int worker,
                             struct tr_runtime *rt, int under_slot,
                             struct rte_mbuf *m, const struct tr_ip *next_hop,
                             uint8_t family)
{
    const struct tr_iface *under = rt_iface(rt, under_slot);
    uint8_t *p;

    if (!under) {
        rte_pktmbuf_free(m);
        return;
    }
    if (pkt_prepend(m, 14)) {
        stats_drop(e, worker, under_slot);
        rte_pktmbuf_free(m);
        return;
    }
    p = mtod(m);
    memset(p, 0, 6);
    memcpy(p + 6, under->mac, 6);
    p[12] = family == 4 ? ETH_TYPE_IPV4 >> 8 : ETH_TYPE_IPV6 >> 8;
    p[13] = family == 4 ? ETH_TYPE_IPV4 & 0xff : ETH_TYPE_IPV6 & 0xff;
    resolve_and_send(e, worker, rt, under_slot, next_hop, m);
}

static void tunnel_send(struct tr_engine *e, int worker,
                        struct tr_runtime *rt, int if_slot,
                        struct rte_mbuf *m)
{
    const struct tr_iface *iface = rt_iface(rt, if_slot);
    const struct tr_tunnel_rt *t = &rt->tunnel[if_slot];
    const struct tr_iface *under;
    struct tr_ip src, next_hop;
    struct tr_tnl_frame frame;
    struct tr_tnl_flow flow;
    int under_slot;
    uint32_t under_mtu;
    uint32_t len, max_inner;

    if (!iface || iface->kind != TR_IF_TUNNEL || !t->ready || !t->driver) {
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    max_inner = iface->mtu + ETH_HLEN + (pkt_tagged(m) ? 4 : 0);
    if (mlen(m) > max_inner || !pkt_single(m)) {
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    if (t->local_if_slot >= 0) {
        under_slot = t->local_if_slot;
    } else {
        struct tr_fib_result res;
        if (tr_fib_lookup(&rt->fib, &t->remote, &res) ||
            res.route->if_slot < 0) {
            stats_drop(e, worker, if_slot);
            rte_pktmbuf_free(m);
            return;
        }
        under_slot = res.route->if_slot;
    }
    under = rt_iface(rt, under_slot);
    if (!under || (under->kind != TR_IF_ETHERNET &&
                   under->kind != TR_IF_VLAN)) {
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    if (t->local.family) {
        src = t->local;
    } else {
        bool prefer_ll = t->family == TR_AF_INET6 &&
                         tr_ip_is_linklocal(&t->remote);
        if (pick_addr(rt, under_slot, t->family, prefer_ll, &src)) {
            stats_drop(e, worker, if_slot);
            rte_pktmbuf_free(m);
            return;
        }
    }
    if (src.family != t->family || t->remote.family != t->family) {
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }

    mss_clamp_frame(e, worker, rt, t, under_slot, m);

    memset(&flow, 0, sizeof(flow));
    flow.family = t->family;
    flow.hop_limit = 64;
    flow.tunnel_id = tr_random_u32();
    if (t->family == 4) {
        memcpy(flow.src, &src.u.v4, 4);
        memcpy(flow.dst, &t->remote.u.v4, 4);
    } else {
        memcpy(flow.src, &src.u.v6, 16);
        memcpy(flow.dst, &t->remote.u.v6, 16);
    }
    frame.base = (uint8_t *)m->buf_addr;
    frame.cap = m->buf_len;
    frame.off = m->data_off;
    frame.len = mlen(m);
    if (t->driver->ops.encap(t->driver->ctx, &frame, &flow)) {
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    m->data_off = frame.off;
    m->pkt_len = frame.len;
    m->data_len = frame.len;
    under_mtu = under->mtu;
    len = mlen(m);
    if (underlay_next_hop(rt, under_slot, &t->remote, &next_hop)) {
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    if (len <= under_mtu) {
        send_outer_frame(e, worker, rt, under_slot, m, &next_hop, t->family);
        return;
    }
    /* Overlay MTU exceeds the underlay MTU: fragment the outer packet. */
    struct tr_frag_packet frags[TR_FRAG_MAX_OUT];
    int nf;
    if (t->family == 4)
        nf = tr_frag4(mtod(m), len, under_mtu, frags, TR_FRAG_MAX_OUT);
    else
        nf = tr_frag6(mtod(m), len, under_mtu, flow.tunnel_id, frags,
                      TR_FRAG_MAX_OUT);
    rte_pktmbuf_free(m);
    if (nf <= 0) {
        stats_drop(e, worker, if_slot);
        return;
    }
    for (int i = 0; i < nf; i++) {
        struct rte_mbuf *fm = pkt_alloc(e, frags[i].len);
        if (!fm) {
            free(frags[i].data);
            continue;
        }
        memcpy(mtod(fm), frags[i].data, frags[i].len);
        free(frags[i].data);
        if (if_slot_stats_valid(e, worker, if_slot))
            atomic_fetch_add_explicit(&e->stats[if_slot][worker].frag_tx, 1,
                                      memory_order_relaxed);
        send_outer_frame(e, worker, rt, under_slot, fm, &next_hop, t->family);
    }
}

static void engine_input_slot(struct tr_engine *e, int worker,
                              struct tr_runtime *rt, int if_slot,
                              struct rte_mbuf *m);

static int match_tunnel(struct tr_runtime *rt, int ingress, uint8_t family,
                        const struct tr_ip *src, const struct tr_ip *dst)
{
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        const struct tr_tunnel_rt *t = &rt->tunnel[i];
        if (!t->ready || t->family != family)
            continue;
        if (!tr_ip_equal(&t->remote, src))
            continue;
        if (t->local_if_slot >= 0 && t->local_if_slot != ingress)
            continue;
        if (t->local.family) {
            if (!tr_ip_equal(&t->local, dst))
                continue;
        } else {
            if (!is_local_if(rt, ingress, dst))
                continue;
        }
        return i;
    }
    return -1;
}

static void process_outer(struct tr_engine *e, int worker,
                          struct tr_runtime *rt, int ingress,
                          struct rte_mbuf *m, uint32_t l3off,
                          uint32_t ip_len, uint8_t family,
                          const struct tr_ip *src, const struct tr_ip *dst)
{
    int tslot = match_tunnel(rt, ingress, family, src, dst);
    struct tr_tnl_frame frame;
    struct tr_tnl_flow flow;
    const struct tr_tunnel_rt *t;
    const struct tr_iface *iface;

    if (tslot < 0) {
        stats_drop(e, worker, ingress);
        rte_pktmbuf_free(m);
        return;
    }
    t = &rt->tunnel[tslot];
    iface = rt_iface(rt, tslot);
    if (!iface || !t->driver) {
        stats_drop(e, worker, ingress);
        rte_pktmbuf_free(m);
        return;
    }
    memset(&flow, 0, sizeof(flow));
    flow.family = family;
    frame.base = (uint8_t *)m->buf_addr;
    frame.cap = m->buf_len;
    frame.off = m->data_off + l3off;
    frame.len = ip_len;
    if (t->driver->ops.decap(t->driver->ctx, &frame, &flow)) {
        stats_drop(e, worker, ingress);
        rte_pktmbuf_free(m);
        return;
    }
    if (frame.len < ETH_HLEN ||
        frame.len > iface->mtu + ETH_HLEN + 4) {
        stats_drop(e, worker, ingress);
        rte_pktmbuf_free(m);
        return;
    }
    m->data_off = frame.off;
    m->pkt_len = frame.len;
    m->data_len = frame.len;
    if (if_slot_stats_valid(e, worker, tslot))
        atomic_fetch_add_explicit(&e->stats[tslot][worker].reasm_ok, 1,
                                  memory_order_relaxed);
    engine_input_slot(e, worker, rt, tslot, m);
}

static void reasm_output(struct tr_engine *e, int worker,
                         struct tr_runtime *rt, int ingress,
                         struct tr_reasm_out *out)
{
    struct rte_mbuf *m = pkt_alloc(e, ETH_HLEN + out->len);
    struct tr_ip src = {0}, dst = {0};
    uint8_t *p;
    uint32_t l3off = ETH_HLEN;

    if (!m) {
        free(out->data);
        return;
    }
    memset(mtod(m), 0, ETH_HLEN);
    memcpy(mtod(m) + ETH_HLEN, out->data, out->len);
    p = mtod(m) + ETH_HLEN;
    if (out->family == 4) {
        src.family = TR_AF_INET;
        dst.family = TR_AF_INET;
        memcpy(&src.u.v4, p + 12, 4);
        memcpy(&dst.u.v4, p + 16, 4);
    } else {
        src.family = TR_AF_INET6;
        dst.family = TR_AF_INET6;
        memcpy(&src.u.v6, p + 8, 16);
        memcpy(&dst.u.v6, p + 24, 16);
    }
    process_outer(e, worker, rt, ingress, m, l3off, out->len, out->family,
                  &src, &dst);
    free(out->data);
}

static void handle_arp(struct tr_engine *e, int worker,
                       struct tr_runtime *rt, int if_slot,
                       struct rte_mbuf *m)
{
    const struct tr_iface *iface = rt_iface(rt, if_slot);
    uint8_t *p = mtod(m);
    uint32_t len = mlen(m);
    uint16_t op;
    struct tr_ip spa, tpa;
    uint8_t sha[6];
    struct rte_mbuf *reply;
    uint8_t *q;

    if (!iface || len < 42)
        goto drop;
    if (p[14] != 0x00 || p[15] != 0x01 || p[16] != 0x08 ||
        p[17] != 0x00 || p[18] != 6 || p[19] != 4)
        goto drop;
    op = (uint16_t)(p[20] << 8 | p[21]);
    if (op != 1 && op != 2)
        goto drop;
    memcpy(sha, p + 22, 6);
    spa.family = TR_AF_INET;
    memcpy(&spa.u.v4, p + 28, 4);
    tpa.family = TR_AF_INET;
    memcpy(&tpa.u.v4, p + 38, 4);
    if (!tr_ip_is_unspecified(&spa) && !tr_mac_is_multicast(sha))
        flush_pending_family(e, worker, rt, if_slot, &spa, sha, TR_AF_INET);
    if (op == 1 && is_local_if(rt, if_slot, &tpa)) {
        reply = pkt_alloc(e, 42);
        if (!reply)
            goto drop;
        q = mtod(reply);
        memcpy(q, sha, 6);
        memcpy(q + 6, iface->mac, 6);
        q[12] = ETH_TYPE_ARP >> 8;
        q[13] = ETH_TYPE_ARP & 0xff;
        q[14] = 0x00;
        q[15] = 0x01;
        q[16] = 0x08;
        q[17] = 0x00;
        q[18] = 6;
        q[19] = 4;
        q[20] = 0;
        q[21] = 2;
        memcpy(q + 22, iface->mac, 6);
        memcpy(q + 28, &tpa.u.v4, 4);
        memcpy(q + 32, sha, 6);
        memcpy(q + 38, &spa.u.v4, 4);
        egress_frame(e, worker, rt, if_slot, reply);
    }
    rte_pktmbuf_free(m);
    return;
drop:
    stats_drop(e, worker, if_slot);
    rte_pktmbuf_free(m);
}

static const uint8_t *ndp_find_option(const uint8_t *icmp, uint32_t icmp_len,
                                     uint32_t start, uint8_t type,
                                     uint32_t *opt_len)
{
    uint32_t off = start;

    while (off + 2 <= icmp_len) {
        uint8_t t = icmp[off];
        uint8_t l = icmp[off + 1];
        uint32_t bytes = (uint32_t)l * 8;
        if (l == 0 || off + bytes > icmp_len)
            break;
        if (t == type) {
            if (opt_len)
                *opt_len = bytes;
            return icmp + off;
        }
        off += bytes;
    }
    return NULL;
}

static void handle_ra(struct tr_engine *e, int worker, struct tr_runtime *rt,
                      int if_slot, const uint8_t *ip, const uint8_t *icmp,
                      uint32_t icmp_len)
{
    const struct tr_iface *iface = rt_iface(rt, if_slot);
    uint16_t lifetime;
    uint32_t off = 16;
    struct tr_ip router;
    uint8_t mac[6];
    bool have_mac = false;

    if (!iface || !iface->ipv6_autoconf || ip[7] != 255)
        return;
    struct tr_ip ra_src = {.family = TR_AF_INET6};
    memcpy(&ra_src.u.v6, ip + 8, 16);
    if (!tr_ip_is_linklocal(&ra_src))
        return;
    lifetime = (uint16_t)(icmp[6] << 8 | icmp[7]);
    router.family = TR_AF_INET6;
    memcpy(&router.u.v6, ip + 8, 16);
    const uint8_t *sll = ndp_find_option(icmp, icmp_len, 24, 1, NULL);
    if (sll && sll[1] == 1) {
        memcpy(mac, sll + 2, 6);
        have_mac = true;
    }
    if (have_mac)
        flush_pending_family(e, worker, rt, if_slot, &router, mac, TR_AF_INET6);
    if (!tr_ip_is_unspecified(&router)) {
        pthread_mutex_lock(&e->ra_lock);
        if ((e->ra_tail + 1) % TR_RA_QUEUE != e->ra_head) {
            struct tr_ra_event *ev = &e->raq[e->ra_tail];
            memset(ev, 0, sizeof(*ev));
            ev->if_slot = if_slot;
            ev->prefix.addr.family = TR_AF_INET6;
            ev->prefix.plen = 0;
            ev->router = router;
            ev->lifetime = lifetime;
            ev->valid = 0;
            e->ra_tail = (e->ra_tail + 1) % TR_RA_QUEUE;
        }
        pthread_mutex_unlock(&e->ra_lock);
    }

    while (off + 8 <= icmp_len) {
        uint8_t type = icmp[off];
        uint8_t olen = icmp[off + 1];
        uint32_t bytes = (uint32_t)olen * 8;
        if (olen == 0 || off + bytes > icmp_len)
            break;
        if (type == 3 && olen >= 4) {
            uint8_t plen = icmp[off + 2];
            uint8_t flags = icmp[off + 3];
            uint32_t valid = (uint32_t)icmp[off + 4] << 24 |
                             (uint32_t)icmp[off + 5] << 16 |
                             (uint32_t)icmp[off + 6] << 8 | icmp[off + 7];
            if ((flags & 0x40) && plen == 64) {
                pthread_mutex_lock(&e->ra_lock);
                if ((e->ra_tail + 1) % TR_RA_QUEUE != e->ra_head) {
                    struct tr_ra_event *ev = &e->raq[e->ra_tail];
                    ev->if_slot = if_slot;
                    ev->prefix.addr.family = TR_AF_INET6;
                    memcpy(&ev->prefix.addr.u.v6, icmp + off + 16, 16);
                    ev->prefix.plen = plen;
                    tr_prefix_canonical(&ev->prefix);
                    ev->router = router;
                    ev->lifetime = lifetime;
                    ev->valid = valid;
                    ev->mtu = 0;
                    e->ra_tail = (e->ra_tail + 1) % TR_RA_QUEUE;
                }
                pthread_mutex_unlock(&e->ra_lock);
            }
        } else if (type == 5 && olen >= 1) {
            /* MTU option: informational only in this data plane. */
        }
        off += bytes;
    }
}

static void handle_icmp6(struct tr_engine *e, int worker,
                         struct tr_runtime *rt, int if_slot,
                         struct rte_mbuf *m, uint32_t l3off,
                         const uint8_t *ip, uint32_t plen)
{
    const struct tr_iface *iface = rt_iface(rt, if_slot);
    uint8_t *icmp = mtod(m) + l3off + 40;
    uint32_t icmp_len = plen;
    struct tr_ip src, dst;
    uint8_t icmp_type;

    if (!iface || plen < 8)
        goto drop;
    src.family = TR_AF_INET6;
    dst.family = TR_AF_INET6;
    memcpy(&src.u.v6, ip + 8, 16);
    memcpy(&dst.u.v6, ip + 24, 16);
    icmp_type = icmp[0];
    if ((icmp_type == ICMPV6_NEIGH_SOLICIT ||
         icmp_type == ICMPV6_NEIGH_ADVERT ||
         icmp_type == ICMPV6_ROUTER_ADVERT) &&
        ip[7] != 255)
        goto drop;
    if (icmp_type == ICMPV6_NEIGH_SOLICIT && plen >= 24) {
        struct tr_ip target;
        const uint8_t *sll;
        uint8_t smac[6];
        target.family = TR_AF_INET6;
        memcpy(&target.u.v6, icmp + 8, 16);
        if (!is_local_if(rt, if_slot, &target))
            goto drop;
        sll = ndp_find_option(icmp, icmp_len, 24, 1, NULL);
        if (sll && sll[1] == 1) {
            memcpy(smac, sll + 2, 6);
            if (!tr_ip_is_unspecified(&src) && !tr_mac_is_multicast(smac))
                flush_pending_family(e, worker, rt, if_slot, &src, smac,
                                     TR_AF_INET6);
        }
        uint8_t dmac[6];
        if (tr_ip_is_unspecified(&src)) {
            static const uint8_t all_nodes[6] = {0x33, 0x33, 0x00,
                                                 0x00, 0x00, 0x01};
            memcpy(dmac, all_nodes, 6);
        } else {
            memcpy(dmac, mtod(m) + 6, 6);
        }
        send_ndp_na(e, worker, rt, if_slot, &target, dmac,
                    tr_ip_is_unspecified(&src) ? NULL : &src,
                    !tr_ip_is_unspecified(&src));
        goto drop;
    }
    if (icmp_type == ICMPV6_NEIGH_ADVERT && plen >= 24) {
        struct tr_ip target;
        const uint8_t *tll;
        target.family = TR_AF_INET6;
        memcpy(&target.u.v6, icmp + 8, 16);
        tll = ndp_find_option(icmp, icmp_len, 24, 2, NULL);
        if (tll && tll[1] == 1)
            flush_pending_family(e, worker, rt, if_slot, &target, tll + 2,
                                 TR_AF_INET6);
        rte_pktmbuf_free(m);
        return;
    }
    if (icmp_type == ICMPV6_ROUTER_ADVERT) {
        handle_ra(e, worker, rt, if_slot, ip, icmp, icmp_len);
        rte_pktmbuf_free(m);
        return;
    }
    if (icmp_type == ICMPV6_ECHO_REQUEST && is_local_if(rt, if_slot, &dst)) {
        send_echo_reply6(e, worker, rt, if_slot, m, l3off);
        rte_pktmbuf_free(m);
        return;
    }
drop:
    stats_drop(e, worker, if_slot);
    rte_pktmbuf_free(m);
}

static void handle_icmp4(struct tr_engine *e, int worker,
                         struct tr_runtime *rt, int if_slot,
                         struct rte_mbuf *m, uint32_t l3off,
                         const uint8_t *ip)
{
    uint8_t *icmp = mtod(m) + l3off + 20;
    if (mlen(m) < l3off + 20 + 8)
        goto drop;
    if (icmp[0] != ICMP_ECHO)
        goto drop;
    send_echo_reply4(e, worker, rt, if_slot, m, l3off);
    rte_pktmbuf_free(m);
    return;
drop:
    stats_drop(e, worker, if_slot);
    rte_pktmbuf_free(m);
}

static void l3_forward4(struct tr_engine *e, int worker,
                        struct tr_runtime *rt, int if_slot,
                        struct rte_mbuf *m, uint32_t l3off, const uint8_t *ip,
                        uint32_t ip_len)
{
    struct tr_ip dst, next_hop;
    struct tr_fib_result res;
    const struct tr_iface *egress;
    uint8_t *p = mtod(m) + l3off;
    uint8_t ttl = p[8];
    bool df = (p[6] & 0x40) != 0;
    struct rte_mbuf *frag_m;

    dst.family = TR_AF_INET;
    memcpy(&dst.u.v4, p + 16, 4);
    if (is_local_if(rt, if_slot, &dst)) {
        if (p[9] == IPPROTO_ICMP) {
            handle_icmp4(e, worker, rt, if_slot, m, l3off, ip);
        } else {
            stats_drop(e, worker, if_slot);
            rte_pktmbuf_free(m);
        }
        return;
    }
    if (tr_fib_lookup(&rt->fib, &dst, &res) || res.route->if_slot < 0) {
        send_icmp4_error(e, worker, rt, if_slot, m, l3off,
                         ICMP_DEST_UNREACH, 0, 0);
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    egress = rt_iface(rt, res.route->if_slot);
    if (!egress) {
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    if (ttl <= 1) {
        send_icmp4_error(e, worker, rt, if_slot, m, l3off,
                         ICMP_TIME_EXCEEDED, 0, 0);
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    if (ip_len > egress->mtu) {
        if (df) {
            send_icmp4_error(e, worker, rt, if_slot, m, l3off,
                             ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
                             (uint16_t)egress->mtu);
            stats_drop(e, worker, if_slot);
            rte_pktmbuf_free(m);
            return;
        }
        struct tr_frag_packet frags[TR_FRAG_MAX_OUT];
        int nf = tr_frag4(ip, ip_len, egress->mtu, frags, TR_FRAG_MAX_OUT);
        if (nf <= 0) {
            stats_drop(e, worker, if_slot);
            rte_pktmbuf_free(m);
            return;
        }
        next_hop = res.route->has_via ? res.route->via : dst;
        for (int i = 0; i < nf; i++) {
            frag_m = pkt_alloc(e, ETH_HLEN + frags[i].len);
            if (!frag_m) {
                free(frags[i].data);
                continue;
            }
            memcpy(mtod(frag_m) + ETH_HLEN, frags[i].data, frags[i].len);
            free(frags[i].data);
            memcpy(mtod(frag_m) + 6, egress->mac, 6);
            memset(mtod(frag_m), 0, 6);
            mtod(frag_m)[12] = ETH_TYPE_IPV4 >> 8;
            mtod(frag_m)[13] = ETH_TYPE_IPV4 & 0xff;
            resolve_and_send(e, worker, rt, egress->slot, &next_hop, frag_m);
        }
        rte_pktmbuf_free(m);
        return;
    }
    p[8] = (uint8_t)(ttl - 1);
    p[10] = 0;
    p[11] = 0;
    uint16_t csum = tr_checksum16(p, (uint32_t)(p[0] & 0x0f) * 4, 0);
    p[10] = (uint8_t)(csum >> 8);
    p[11] = (uint8_t)csum;
    next_hop = res.route->has_via ? res.route->via : dst;
    memcpy(mtod(m) + 6, egress->mac, 6);
    memset(mtod(m), 0, 6);
    resolve_and_send(e, worker, rt, egress->slot, &next_hop, m);
}

static void l3_forward6(struct tr_engine *e, int worker,
                        struct tr_runtime *rt, int if_slot,
                        struct rte_mbuf *m, uint32_t l3off, const uint8_t *ip,
                        uint32_t plen)
{
    struct tr_ip dst, next_hop;
    struct tr_fib_result res;
    const struct tr_iface *egress;
    uint8_t *p = mtod(m) + l3off;

    dst.family = TR_AF_INET6;
    memcpy(&dst.u.v6, p + 24, 16);
    if (is_local_if(rt, if_slot, &dst)) {
        if (p[6] == IPPROTO_ICMPV6) {
            handle_icmp6(e, worker, rt, if_slot, m, l3off, ip, plen);
        } else {
            stats_drop(e, worker, if_slot);
            rte_pktmbuf_free(m);
        }
        return;
    }
    if (tr_fib_lookup(&rt->fib, &dst, &res) || res.route->if_slot < 0) {
        send_icmp6_error(e, worker, rt, if_slot, m, l3off,
                         ICMPV6_DEST_UNREACH, 0, 0);
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    egress = rt_iface(rt, res.route->if_slot);
    if (!egress) {
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    if (p[7] <= 1) {
        send_icmp6_error(e, worker, rt, if_slot, m, l3off,
                         ICMPV6_TIME_EXCEEDED, 0, 0);
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    if (plen > egress->mtu) {
        send_icmp6_error(e, worker, rt, if_slot, m, l3off,
                         ICMPV6_PACKET_TOO_BIG, 0, egress->mtu);
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    p[7]--;
    next_hop = res.route->has_via ? res.route->via : dst;
    memcpy(mtod(m) + 6, egress->mac, 6);
    memset(mtod(m), 0, 6);
    resolve_and_send(e, worker, rt, egress->slot, &next_hop, m);
}

static void l3_ingress(struct tr_engine *e, int worker,
                       struct tr_runtime *rt, int if_slot,
                       struct rte_mbuf *m)
{
    const struct tr_iface *iface = rt_iface(rt, if_slot);
    uint8_t *p;
    uint32_t len;
    uint16_t type;
    uint32_t l3off = ETH_HLEN;

    if (!iface) {
        rte_pktmbuf_free(m);
        return;
    }
    len = mlen(m);
    if (len < ETH_HLEN)
        goto drop;
    if (pkt_tagged(m)) {
        uint16_t vid;
        if (pkt_strip_vlan(m, &vid))
            goto drop;
        len = mlen(m);
    }
    p = mtod(m);
    if (len < ETH_HLEN)
        goto drop;
    if (!tr_mac_is_multicast(p) && memcmp(p, iface->mac, 6) != 0)
        goto drop;
    type = (uint16_t)(p[12] << 8 | p[13]);
    if (type == ETH_TYPE_ARP) {
        handle_arp(e, worker, rt, if_slot, m);
        return;
    }
    if (type == ETH_TYPE_IPV4) {
        uint32_t total;
        if (len < l3off + 20)
            goto drop;
        uint8_t *ip = p + l3off;
        uint32_t ihl = (uint32_t)(ip[0] & 0x0f) * 4;
        if ((ip[0] >> 4) != 4 || ihl < 20 || len < l3off + ihl)
            goto drop;
        if (tr_checksum16(ip, ihl, 0) != 0)
            goto drop;
        total = (uint32_t)(ip[2] << 8 | ip[3]);
        if (total < ihl || l3off + total > len)
            goto drop;
        if (len > l3off + total)
            rte_pktmbuf_trim(m, (uint16_t)(len - l3off - total));
        if (ip[9] == IPPROTO_ETHERIP) {
            struct tr_ip src, dst;
            uint16_t fo = (uint16_t)(ip[6] << 8 | ip[7]);
            uint32_t frag_off = (uint32_t)(fo & 0x1fff) * 8;
            bool more = (fo & 0x2000) != 0;
            src.family = TR_AF_INET;
            dst.family = TR_AF_INET;
            memcpy(&src.u.v4, ip + 12, 4);
            memcpy(&dst.u.v4, ip + 16, 4);
            if (frag_off || more) {
                struct tr_reasm_out out = {0};
                int rc = tr_reasm4_input(&e->reasm[worker], if_slot, &src, &dst,
                                         (uint16_t)(ip[4] << 8 | ip[5]),
                                         ip[9], ip, ihl, frag_off, more,
                                         ip + ihl, total - ihl,
                                         tr_monotonic_ms(), &out);
                if (rc == 1) {
                    reasm_output(e, worker, rt, if_slot, &out);
                } else if (rc < 0) {
                    if (if_slot_stats_valid(e, worker, if_slot))
                        atomic_fetch_add_explicit(
                            &e->stats[if_slot][worker].reasm_fail, 1,
                            memory_order_relaxed);
                }
                rte_pktmbuf_free(m);
                return;
            }
            process_outer(e, worker, rt, if_slot, m, l3off, total,
                          TR_AF_INET, &src, &dst);
            return;
        }
        l3_forward4(e, worker, rt, if_slot, m, l3off, ip, total);
        return;
    }
    if (type == ETH_TYPE_IPV6) {
        if (len < l3off + 40)
            goto drop;
        uint8_t *ip = p + l3off;
        uint32_t plen = (uint32_t)(ip[4] << 8 | ip[5]);
        if ((ip[0] >> 4) != 6 || l3off + 40 + plen > len)
            goto drop;
        if (len > l3off + 40 + plen)
            rte_pktmbuf_trim(m, (uint16_t)(len - l3off - 40 - plen));
        if (ip[6] == IPPROTO_FRAGMENT) {
            if (plen < 8)
                goto drop;
            uint8_t *fh = ip + 40;
            uint16_t fo = (uint16_t)(fh[2] << 8 | fh[3]);
            uint32_t frag_off = fo & 0xfff8;
            bool more = (fo & 1) != 0;
            uint32_t id = (uint32_t)fh[4] << 24 | (uint32_t)fh[5] << 16 |
                          (uint32_t)fh[6] << 8 | fh[7];
            uint8_t nh = fh[0];
            if (nh != IPPROTO_ETHERIP)
                goto drop;
            struct tr_ip src, dst;
            struct tr_reasm_out out = {0};
            src.family = TR_AF_INET6;
            dst.family = TR_AF_INET6;
            memcpy(&src.u.v6, ip + 8, 16);
            memcpy(&dst.u.v6, ip + 24, 16);
            int rc = tr_reasm6_input(&e->reasm[worker], if_slot, &src, &dst, id, nh,
                                     ip, 40, frag_off, more, ip + 48,
                                     plen - 8, tr_monotonic_ms(), &out);
            if (rc == 1)
                reasm_output(e, worker, rt, if_slot, &out);
            else if (rc < 0 && if_slot_stats_valid(e, worker, if_slot))
                atomic_fetch_add_explicit(&e->stats[if_slot][worker].reasm_fail,
                                          1, memory_order_relaxed);
            rte_pktmbuf_free(m);
            return;
        }
        if (ip[6] == IPPROTO_ETHERIP) {
            struct tr_ip src, dst;
            src.family = TR_AF_INET6;
            dst.family = TR_AF_INET6;
            memcpy(&src.u.v6, ip + 8, 16);
            memcpy(&dst.u.v6, ip + 24, 16);
            process_outer(e, worker, rt, if_slot, m, l3off, 40 + plen,
                          TR_AF_INET6, &src, &dst);
            return;
        }
        if (ip[6] == IPPROTO_ICMPV6 && plen >= 8) {
            struct tr_ip dst;
            uint8_t icmp_type = ip[40];
            dst.family = TR_AF_INET6;
            memcpy(&dst.u.v6, ip + 24, 16);
            /* Neighbor Solicitations and Router Advertisements are sent to
             * multicast groups, not to one of our unicast addresses. */
            if (icmp_type == ICMPV6_NEIGH_SOLICIT ||
                icmp_type == ICMPV6_ROUTER_ADVERT ||
                is_local_if(rt, if_slot, &dst)) {
                handle_icmp6(e, worker, rt, if_slot, m, l3off, ip, plen);
                return;
            }
        }
        l3_forward6(e, worker, rt, if_slot, m, l3off, ip, plen);
        return;
    }
drop:
    stats_drop(e, worker, if_slot);
    rte_pktmbuf_free(m);
}

static void bridge_ingress(struct tr_engine *e, int worker,
                           struct tr_runtime *rt, int if_slot,
                           struct rte_mbuf *m)
{
    const struct tr_iface *iface = rt_iface(rt, if_slot);
    const struct tr_iface *br;
    uint8_t *p = mtod(m);
    uint32_t len = mlen(m);
    uint8_t dstmac[6];
    int out_slot;
    uint64_t now = tr_monotonic_ms();
    int copies = 0;

    if (!iface || iface->bridge < 0 || len < ETH_HLEN)
        goto drop;
    br = rt_iface(rt, iface->bridge);
    if (!br || br->kind != TR_IF_BRIDGE || len > br->mtu + ETH_HLEN + 4)
        goto drop;
    memcpy(dstmac, p, 6);
    tr_bridge_learn(&e->bridges, br->slot, p + 6, if_slot, now);
    out_slot = tr_bridge_lookup(&e->bridges, br->slot, dstmac);
    if (tr_mac_is_multicast(dstmac) || out_slot < 0) {
        for (int i = 0; i < br->nchildren; i++) {
            int child_slot = br->children[i];
            if (child_slot == if_slot)
                continue;
            struct rte_mbuf *out = pkt_dup(e, m);
            if (!out)
                continue;
            copies++;
            egress_frame(e, worker, rt, child_slot, out);
        }
    } else if (out_slot != if_slot) {
        egress_frame(e, worker, rt, out_slot, m);
        return;
    }
    rte_pktmbuf_free(m);
    return;
drop:
    stats_drop(e, worker, if_slot);
    rte_pktmbuf_free(m);
}

static void engine_input_slot(struct tr_engine *e, int worker,
                              struct tr_runtime *rt, int if_slot,
                              struct rte_mbuf *m)
{
    const struct tr_iface *iface = rt_iface(rt, if_slot);

    if (!iface) {
        rte_pktmbuf_free(m);
        return;
    }
    if (mlen(m) < ETH_HLEN) {
        stats_drop(e, worker, if_slot);
        rte_pktmbuf_free(m);
        return;
    }
    if (iface->kind == TR_IF_ETHERNET && pkt_tagged(m)) {
        uint8_t *p = mtod(m);
        uint16_t vid = (uint16_t)((p[14] << 8 | p[15]) & 0x0fff);
        char name[TR_IFNAME_LEN];
        snprintf(name, sizeof(name), "%s.%u", iface->name, vid);
        const struct tr_iface *vlan = tr_config_find_const(&rt->cfg, name);
        if (vlan && vlan->kind == TR_IF_VLAN && vlan->parent == if_slot) {
            if (pkt_strip_vlan(m, NULL)) {
                stats_drop(e, worker, if_slot);
                rte_pktmbuf_free(m);
                return;
            }
            if_slot = vlan->slot;
            iface = vlan;
        }
    }
    if (iface->bridge >= 0)
        bridge_ingress(e, worker, rt, if_slot, m);
    else
        l3_ingress(e, worker, rt, if_slot, m);
}

int tr_engine_input(struct tr_engine *e, int worker, int if_slot,
                    struct rte_mbuf *m)
{
    struct tr_runtime *rt;

    if (!e || !m)
        return -1;
    if (worker < 0 || worker >= e->workers) {
        rte_pktmbuf_free(m);
        return -1;
    }
    pthread_rwlock_rdlock(&e->rt_lock);
    rt = e->rt;
    stats_rx(e, worker, if_slot, mlen(m));
    engine_input_slot(e, worker, rt, if_slot, m);
    pthread_rwlock_unlock(&e->rt_lock);
    return 0;
}


static void process_ra_events(struct tr_engine *e, bool *dirty)
{
    struct tr_ra_event events[TR_RA_QUEUE];
    int n = 0;
    uint64_t now = tr_monotonic_ms();

    pthread_mutex_lock(&e->ra_lock);
    while (e->ra_head != e->ra_tail && n < TR_RA_QUEUE) {
        events[n++] = e->raq[e->ra_head];
        e->ra_head = (e->ra_head + 1) % TR_RA_QUEUE;
    }
    pthread_mutex_unlock(&e->ra_lock);
    if (!n)
        return;

    pthread_rwlock_rdlock(&e->rt_lock);
    struct tr_runtime *rt = e->rt;
    for (int k = 0; k < n; k++) {
        struct tr_ra_event *ev = &events[k];
        const struct tr_iface *iface = rt_iface(rt, ev->if_slot);
        if (!iface || !iface->ipv6_autoconf)
            continue;
        if (ev->prefix.plen == 0) {
            struct tr_dyn_route *slot = NULL;
            for (int i = 0; i < TR_DYN_ROUTE_MAX; i++) {
                struct tr_dyn_route *r = &e->dyn_route[i];
                if (r->used && r->if_slot == ev->if_slot &&
                    r->prefix.plen == 0 &&
                    r->prefix.addr.family == TR_AF_INET6 &&
                    tr_ip_equal(&r->via, &ev->router)) {
                    slot = r;
                    break;
                }
            }
            if (ev->lifetime == 0) {
                if (slot) {
                    slot->used = false;
                    *dirty = true;
                }
                continue;
            }
            if (!slot) {
                for (int i = 0; i < TR_DYN_ROUTE_MAX; i++) {
                    if (!e->dyn_route[i].used) {
                        slot = &e->dyn_route[i];
                        break;
                    }
                }
            }
            if (slot) {
                slot->used = true;
                slot->if_slot = ev->if_slot;
                memset(&slot->prefix, 0, sizeof(slot->prefix));
                slot->prefix.addr.family = TR_AF_INET6;
                slot->prefix.plen = 0;
                slot->via = ev->router;
                slot->expires_ms =
                    ev->lifetime == 0xffffffffu
                        ? 0
                        : now + (uint64_t)ev->lifetime * 1000;
                *dirty = true;
            }
            continue;
        }
        if (ev->prefix.plen != 64)
            continue;
        struct in6_addr addr;
        tr_ip6_from_eui64(&ev->prefix.addr.u.v6, ev->prefix.plen, iface->mac,
                          &addr);
        struct tr_prefix prefix = ev->prefix;
        prefix.addr.u.v6 = addr;
        struct tr_dyn_addr *slot = NULL;
        for (int i = 0; i < TR_DYN_ADDR_MAX; i++) {
            struct tr_dyn_addr *d = &e->dyn_addr[i];
            if (d->used && d->if_slot == ev->if_slot &&
                tr_ip_equal(&d->prefix.addr, &prefix.addr)) {
                slot = d;
                break;
            }
        }
        if (ev->valid == 0) {
            if (slot) {
                slot->used = false;
                *dirty = true;
            }
            continue;
        }
        if (!slot) {
            for (int i = 0; i < TR_DYN_ADDR_MAX; i++) {
                if (!e->dyn_addr[i].used) {
                    slot = &e->dyn_addr[i];
                    break;
                }
            }
        }
        if (slot) {
            slot->used = true;
            slot->if_slot = ev->if_slot;
            slot->prefix = prefix;
            slot->expires_ms =
                ev->valid == 0xffffffffu ? 0
                                         : now + (uint64_t)ev->valid * 1000;
            *dirty = true;
        }
    }
    pthread_rwlock_unlock(&e->rt_lock);
}

static bool expire_dynamic(struct tr_engine *e, uint64_t now)
{
    bool dirty = false;
    pthread_rwlock_rdlock(&e->rt_lock);
    for (int i = 0; i < TR_DYN_ADDR_MAX; i++) {
        struct tr_dyn_addr *d = &e->dyn_addr[i];
        if (d->used && d->expires_ms && now >= d->expires_ms) {
            d->used = false;
            dirty = true;
        }
    }
    for (int i = 0; i < TR_DYN_ROUTE_MAX; i++) {
        struct tr_dyn_route *r = &e->dyn_route[i];
        if (r->used && r->expires_ms && now >= r->expires_ms) {
            r->used = false;
            dirty = true;
        }
    }
    pthread_rwlock_unlock(&e->rt_lock);
    return dirty;
}

static int rebuild_dynamic(struct tr_engine *e)
{
    struct tr_runtime *nr = NULL;
    struct tr_runtime *old;
    char err[128];
    int rc;

    pthread_rwlock_wrlock(&e->rt_lock);
    rc = runtime_build(e, &e->rt->cfg, &nr, err, sizeof(err));
    if (rc == 0) {
        old = e->rt;
        e->rt = nr;
        pthread_rwlock_unlock(&e->rt_lock);
        runtime_free(old);
        return 0;
    }
    pthread_rwlock_unlock(&e->rt_lock);
    return -1;
}

void tr_engine_housekeeping(struct tr_engine *e, uint64_t now_ms)
{
    bool dirty;
    uint64_t now = now_ms ? now_ms : tr_monotonic_ms();

    tr_neigh_expire(&e->neigh4, now);
    tr_neigh_expire(&e->neigh6, now);
    tr_bridge_expire(&e->bridges, now);
    for (int i = 0; i < e->workers; i++)
        tr_reasm_expire(&e->reasm[i], now);
    dirty = expire_dynamic(e, now);
    process_ra_events(e, &dirty);
    if (dirty)
        rebuild_dynamic(e);
}

static void send_router_solicit(struct tr_engine *e, int if_slot,
                                const struct tr_iface *iface)
{
    struct tr_runtime *rt;
    struct tr_ip src;
    struct rte_mbuf *m;
    uint8_t *p, *icmp;
    struct in6_addr all_routers;
    uint32_t sum;

    pthread_rwlock_rdlock(&e->rt_lock);
    rt = e->rt;
    if (pick_addr(rt, if_slot, TR_AF_INET6, true, &src)) {
        pthread_rwlock_unlock(&e->rt_lock);
        return;
    }
    memset(&all_routers, 0, sizeof(all_routers));
    all_routers.s6_addr[0] = 0xff;
    all_routers.s6_addr[1] = 0x02;
    all_routers.s6_addr[15] = 0x02;
    m = pkt_alloc(e, 14 + 40 + 16);
    if (!m) {
        pthread_rwlock_unlock(&e->rt_lock);
        return;
    }
    p = mtod(m);
    p[0] = 0x33;
    p[1] = 0x33;
    p[5] = 0x02;
    memcpy(p + 6, iface->mac, 6);
    p[12] = ETH_TYPE_IPV6 >> 8;
    p[13] = ETH_TYPE_IPV6 & 0xff;
    build_ip6(p + 14, 16, IPPROTO_ICMPV6, (const uint8_t *)&src.u.v6,
              (const uint8_t *)&all_routers, 255);
    icmp = p + 54;
    memset(icmp, 0, 16);
    icmp[0] = ICMPV6_ROUTER_SOLICIT;
    icmp[8] = 1;
    icmp[9] = 1;
    memcpy(icmp + 10, iface->mac, 6);
    sum = checksum_add_pseudo6(0, (const uint8_t *)&src.u.v6,
                               (const uint8_t *)&all_routers,
                               IPPROTO_ICMPV6, 16);
    sum = tr_checksum_add(sum, icmp, 16);
    uint16_t csum = tr_checksum16_finish(sum);
    icmp[2] = (uint8_t)(csum >> 8);
    icmp[3] = (uint8_t)csum;
    egress_frame(e, 0, rt, if_slot, m);
    pthread_rwlock_unlock(&e->rt_lock);
}

void tr_engine_send_router_solicitations(struct tr_engine *e)
{
    struct tr_config cfg;
    if (e->rs_sent)
        return;
    if (tr_engine_config_copy(e, &cfg))
        return;
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        if (cfg.ifaces[i].present && cfg.ifaces[i].ipv6_autoconf &&
            cfg.ifaces[i].bridge < 0)
            send_router_solicit(e, i, &cfg.ifaces[i]);
    }
    e->rs_sent = true;
}

int tr_engine_stats_text(struct tr_engine *e, char **out)
{
    char *buf = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&buf, &n);

    if (!f)
        return -1;
    pthread_rwlock_rdlock(&e->rt_lock);
    fprintf(f, "%-16s %10s %10s %10s %10s %8s %8s %8s\n", "Interface",
            "RX-pkts", "TX-pkts", "drops", "bytes", "arp", "ndp", "frags");
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        if (!e->rt->cfg.ifaces[i].present)
            continue;
        uint64_t rx = 0, tx = 0, drop = 0, bytes = 0, arp = 0, ndp = 0,
                 frag = 0, reasm = 0, fail = 0, mss = 0;
        for (int w = 0; w < e->workers; w++) {
            const struct tr_if_stats *s = &e->stats[i][w];
            rx += atomic_load_explicit(&s->rx_pkts, memory_order_relaxed);
            tx += atomic_load_explicit(&s->tx_pkts, memory_order_relaxed);
            drop += atomic_load_explicit(&s->drops, memory_order_relaxed);
            bytes += atomic_load_explicit(&s->rx_bytes, memory_order_relaxed);
            arp += atomic_load_explicit(&s->arp_tx, memory_order_relaxed);
            ndp += atomic_load_explicit(&s->ndp_tx, memory_order_relaxed);
            frag += atomic_load_explicit(&s->frag_tx, memory_order_relaxed);
            reasm += atomic_load_explicit(&s->reasm_ok, memory_order_relaxed);
            fail += atomic_load_explicit(&s->reasm_fail,
                                         memory_order_relaxed);
            mss += atomic_load_explicit(&s->mss_clamped,
                                        memory_order_relaxed);
        }
        fprintf(f, "%-16s %10llu %10llu %10llu %10llu %8llu %8llu %8llu\n",
                e->rt->cfg.ifaces[i].name, (unsigned long long)rx,
                (unsigned long long)tx, (unsigned long long)drop,
                (unsigned long long)bytes, (unsigned long long)arp,
                (unsigned long long)ndp, (unsigned long long)frag);
        if (reasm || fail || mss)
            fprintf(f, "  reassembled %llu failed %llu mss-clamped %llu\n",
                    (unsigned long long)reasm, (unsigned long long)fail,
                    (unsigned long long)mss);
    }
    pthread_rwlock_unlock(&e->rt_lock);
    fclose(f);
    *out = buf;
    return 0;
}

int tr_engine_show(struct tr_engine *e, int argc, char **argv, char **out)
{
    if (!e || !argc || !argv || !out)
        return -1;
    if (strcmp(argv[0], "statistics") == 0)
        return tr_engine_stats_text(e, out);
    if (strcmp(argv[0], "routes") == 0) {
        char *buf = NULL;
        size_t n = 0;
        FILE *f = open_memstream(&buf, &n);
        if (!f)
            return -1;
        pthread_rwlock_rdlock(&e->rt_lock);
        for (int i = 0; i < e->rt->fib.nroutes; i++) {
            const struct tr_fib_route *r = &e->rt->fib.routes[i];
            char pfx[96], via[96];
            tr_prefix_ntop(&r->prefix, pfx, sizeof(pfx));
            if (r->has_via)
                tr_ip_ntop(&r->via, via, sizeof(via));
            else
                snprintf(via, sizeof(via), "-");
            const struct tr_iface *iface = rt_iface(e->rt, r->if_slot);
            fprintf(f, "%-42s via %-42s %s%s\n", pfx, via,
                    iface ? iface->name : "-",
                    r->connected ? " connected" : "");
        }
        pthread_rwlock_unlock(&e->rt_lock);
        fclose(f);
        *out = buf;
        return 0;
    }
    if (strcmp(argv[0], "neighbors") == 0) {
        char *n4 = NULL, *n6 = NULL, *buf = NULL;
        size_t n = 0;
        FILE *f;
        if (tr_neigh_show(&e->neigh4, &n4) ||
            tr_neigh_show(&e->neigh6, &n6)) {
            free(n4);
            free(n6);
            return -1;
        }
        f = open_memstream(&buf, &n);
        if (!f) {
            free(n4);
            free(n6);
            return -1;
        }
        fprintf(f, "IPv4 neighbors:\n%sIPv6 neighbors:\n%s", n4, n6);
        free(n4);
        free(n6);
        fclose(f);
        *out = buf;
        return 0;
    }
    if (strcmp(argv[0], "bridge") == 0)
        return tr_bridge_show(&e->bridges, out);
    if (strcmp(argv[0], "tunnels") == 0) {
        char *buf = NULL;
        size_t n = 0;
        FILE *f = open_memstream(&buf, &n);
        if (!f)
            return -1;
        pthread_rwlock_rdlock(&e->rt_lock);
        for (int i = 0; i < TR_MAX_IFACES; i++) {
            const struct tr_iface *iface = rt_iface(e->rt, i);
            if (!iface || iface->kind != TR_IF_TUNNEL)
                continue;
            const struct tr_tunnel_rt *t = &e->rt->tunnel[i];
            char rem[96] = "-", loc[96] = "-";
            if (t->remote.family)
                tr_ip_ntop(&t->remote, rem, sizeof(rem));
            if (t->local.family)
                tr_ip_ntop(&t->local, loc, sizeof(loc));
            fprintf(f,
                    "%s encap %s state %s remote %s local %s underlay %s "
                    "mtu %u tcp-mss %d\n",
                    iface->name, iface->tunnel.driver,
                    t->ready ? "up" : "down", rem, loc,
                    t->local_if_slot >= 0
                        ? e->rt->cfg.ifaces[t->local_if_slot].name
                        : "fib",
                    iface->mtu, iface->tunnel.tcp_mss);
        }
        pthread_rwlock_unlock(&e->rt_lock);
        fclose(f);
        *out = buf;
        return 0;
    }
    if (strcmp(argv[0], "drivers") == 0) {
        char *buf = NULL;
        size_t n = 0;
        FILE *f = open_memstream(&buf, &n);
        if (!f)
            return -1;
        for (int i = 0; i < tr_tunnel_driver_count(); i++) {
            const struct tr_tnl_driver *d = tr_tunnel_driver_at(i);
            fprintf(f, "%-16s %s%s\n", d->name,
                    d->ipv6_only ? "IPv6-only" : "IPv4/IPv6",
                    d->builtin ? " builtin" : " plugin");
        }
        fclose(f);
        *out = buf;
        return 0;
    }
    if (strcmp(argv[0], "configuration") == 0) {
        pthread_rwlock_rdlock(&e->rt_lock);
        int rc = tr_config_show(&e->rt->cfg, argc, argv, out);
        pthread_rwlock_unlock(&e->rt_lock);
        return rc;
    }
    if (strcmp(argv[0], "interfaces") == 0) {
        char *base = NULL;
        char *extra = NULL;
        size_t xlen = 0;
        FILE *xf;
        pthread_rwlock_rdlock(&e->rt_lock);
        if (tr_config_show(&e->rt->cfg, argc, argv, &base)) {
            pthread_rwlock_unlock(&e->rt_lock);
            return -1;
        }
        xf = open_memstream(&extra, &xlen);
        if (!xf) {
            pthread_rwlock_unlock(&e->rt_lock);
            free(base);
            return -1;
        }
        fprintf(xf, "\nRuntime IPv6 addresses (link-local / autoconf):\n");
        for (int i = 0; i < e->rt->nlocals; i++) {
            const struct tr_local_addr *l = &e->rt->locals[i];
            if (!l->linklocal && !l->dynamic)
                continue;
            const struct tr_iface *iface = rt_iface(e->rt, l->if_slot);
            if (!iface)
                continue;
            if (argc >= 2 && strcmp(argv[1], iface->name) != 0)
                continue;
            char a[96];
            tr_ip_ntop(&l->ip, a, sizeof(a));
            fprintf(xf, "  %-16s %s/64 %s\n", iface->name, a,
                    l->dynamic ? "autoconf" : "link-local");
        }
        pthread_rwlock_unlock(&e->rt_lock);
        fclose(xf);
        if (asprintf(out, "%s%s", base ? base : "", extra ? extra : "") < 0) {
            free(base);
            free(extra);
            return -1;
        }
        free(base);
        free(extra);
        return 0;
    }
    return -1;
}
