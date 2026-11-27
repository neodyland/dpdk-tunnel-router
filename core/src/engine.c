#include "engine.h"

#include "addr.h"
#include "bridge.h"
#include "capture.h"
#include "config_internal.h"
#include "fib.h"
#include "neigh.h"
#include "reasm.h"
#include "tunnel.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <rte_prefetch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
#define TR_LOCAL_MAP_SIZE 1024
#define TR_STATS_WORDS ((TR_MAX_IFACES + 63) / 64)
#define TR_DYN_ADDR_MAX 64
#define TR_DYN_ROUTE_MAX 64
#define TR_RA_QUEUE 64
#define TR_RT_CACHE4_SIZE 1024
#define TR_RT_CACHE6_SIZE 256
#define TR_NEIGH_CACHE_SIZE 512
#define TR_NEIGH_CACHE_TTL_MS 2000
#define TR_PING_MAX 64
#define TR_TRACE_MAX_HOPS 64
#define TR_TRACE_MAX_PROBES 5

struct tr_ping_state {
    pthread_mutex_t lock;
    _Atomic bool active;
    uint16_t id;
    uint16_t seq;
    bool replied;
    uint8_t ttl;
    uint64_t sent_ns;
    uint64_t rtt_ns;
    struct tr_ip target;
    struct tr_ip source;
};

struct tr_trace_state {
    pthread_mutex_t lock;
    _Atomic bool active;
    uint16_t id;
    uint16_t seq;
    uint8_t reply_kind; /* 1 = time exceeded, 2 = echo reply */
    uint8_t ttl;
    bool replied;
    uint64_t sent_ns;
    uint64_t rtt_ns;
    struct tr_ip target;
    struct tr_ip source;
    struct tr_ip responder;
};

struct tr_neigh_cache_entry {
    uint64_t generation;
    uint64_t seen_ms;
    int if_slot;
    struct tr_ip ip;
    uint8_t mac[6];
    bool valid;
};

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

struct tr_local_map_entry {
    struct tr_ip ip;
    int if_slot;
    bool used;
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

#define TR_VLAN_MAP_SIZE 512
#define TR_TUNNEL_HASH_SIZE 256

struct tr_vlan_map_entry {
    int parent;
    uint16_t outer;
    uint16_t inner;
    int16_t child;
    bool used;
};

struct tr_runtime {
    uint64_t generation;
    struct tr_config cfg;
    /* Present interfaces by slot.  struct tr_iface is ~0.5 KiB wide, so
     * indexing cfg.ifaces[] by slot needs a multiply and touches a cold line;
     * the hot path only needs the pointer. */
    struct tr_iface *iface_ptrs[TR_MAX_IFACES];
    struct tr_fib fib;
    struct tr_tunnel_rt tunnel[TR_MAX_IFACES];
    struct tr_local_addr locals[TR_LOCAL_MAX];
    struct tr_local_map_entry local_map[TR_LOCAL_MAP_SIZE];
    int nlocals;
    struct tr_vlan_map_entry vlan_map[TR_VLAN_MAP_SIZE];
    int tunnel_head[TR_TUNNEL_HASH_SIZE];
    int16_t tunnel_next[TR_MAX_IFACES];
};

/* The IPv4 route cache holds the whole entry in 16 bytes, so the 1024-entry
 * table is 16 KiB and stays in L1.  The earlier layout carried a 64-bit
 * runtime generation and the full 20-byte struct tr_ip per slot (40 bytes,
 * 40 KiB), which pushed every lookup out of L1 and showed up as one of the
 * hottest functions in the profile.  Cache coherency with the runtime
 * generation is kept by clearing the tables when the generation changes
 * (below) instead of storing the generation in every entry. */
struct tr_rt_cache4 {
    uint32_t addr; /* IPv4 destination, network byte order; 0 = empty slot */
    uint16_t plen;
    uint16_t pad;
    const struct tr_fib_route *route;
};

struct tr_rt_cache6 {
    struct tr_ip dst;
    uint32_t plen;
    const struct tr_fib_route *route;
};

/* Per-packet TX accounting is the hottest bookkeeping in the forwarding path.
 * Instead of updating three separate arrays per packet (pending packets,
 * pending bytes and the dirty bitmap), the worker accumulates into one
 * cache-line-sized struct while the egress interface stays the same -- the
 * normal case for a burst -- and the generic per-interface arrays are only
 * touched when the egress slot changes or at the end of the burst. */
struct tr_tx_acc {
    int slot;    /* interface being accumulated, -1 when idle */
    uint64_t pkts;
    uint64_t bytes;
} __attribute__((aligned(64)));

struct tr_engine {
    pthread_rwlock_t rt_lock;
    struct tr_runtime *rt;
    _Atomic(struct tr_runtime *) rt_fast;
    _Atomic bool rt_updating;
    _Atomic bool rt_reader[TR_MAX_WORKERS];
    uint64_t generation;
    int n_ports;
    int workers;
    struct rte_mempool *mp;
    tr_tx_fn tx;
    void *tx_arg;
    bool tx_ipv4_cksum;

    struct tr_capture *capture;
    struct tr_neigh_table neigh4;
    struct tr_neigh_table neigh6;
    struct tr_bridge_db bridges;
    struct tr_reasm reasm[TR_MAX_WORKERS];

    struct tr_if_stats stats[TR_MAX_IFACES][TR_MAX_WORKERS];
    uint64_t tx_pending_pkts[TR_MAX_WORKERS][TR_MAX_IFACES];
    uint64_t tx_pending_bytes[TR_MAX_WORKERS][TR_MAX_IFACES];
    uint64_t tx_dirty[TR_MAX_WORKERS][TR_STATS_WORDS];
    struct tr_tx_acc tx_acc[TR_MAX_WORKERS];
    struct tr_rt_cache4 rt_cache4[TR_MAX_WORKERS][TR_RT_CACHE4_SIZE];
    struct tr_rt_cache6 rt_cache6[TR_MAX_WORKERS][TR_RT_CACHE6_SIZE];
    /* Generation the per-worker route caches were filled for; a mismatch
     * clears them (see fib_lookup_cached()). */
    uint64_t rt_cache_gen[TR_MAX_WORKERS];
    struct tr_neigh_cache_entry
        neigh_cache[TR_MAX_WORKERS][TR_NEIGH_CACHE_SIZE];

    /* Per-worker snapshots taken once per RX burst.  Neighbour aging,
     * reassembly timeouts, bridge aging and capture filtering all only need
     * millisecond resolution, so one clock read and one capture-flag read per
     * burst replace one of each per packet. */
    uint64_t now_ms[TR_MAX_WORKERS];
    bool capture_on[TR_MAX_WORKERS];

    struct tr_dyn_addr dyn_addr[TR_DYN_ADDR_MAX];
    struct tr_dyn_route dyn_route[TR_DYN_ROUTE_MAX];

    pthread_mutex_t ra_lock;
    struct tr_ra_event raq[TR_RA_QUEUE];
    int ra_head;
    int ra_tail;

    bool rs_sent;
    uint16_t ping_id;
    struct tr_ping_state ping;
    uint16_t trace_id;
    struct tr_trace_state trace;
};

static void free_mbuf_cb(void *pkt)
{
    if (pkt)
        rte_pktmbuf_free((struct rte_mbuf *)pkt);
}

/* Data-plane time and capture state are snapshotted once per RX burst (see
 * tr_engine_input_burst()).  A burst is a few microseconds of work, so every
 * consumer of these values -- neighbour aging, neighbour request rate
 * limiting, reassembly timeouts, bridge aging, capture filtering -- observes
 * the same value as before with millisecond resolution.
 *
 * Callers outside the worker range (control-plane transmissions) get a live
 * reading instead, so ping/traceroute and route solicitation keep their
 * existing timing behaviour. */
static inline __attribute__((always_inline)) uint64_t
pkt_now(const struct tr_engine *e, int worker)
{
    if (worker >= 0 && worker < e->workers)
        return e->now_ms[worker];
    return tr_monotonic_ms();
}

/* Capture enable state is likewise sampled per burst, so starting or stopping
 * a capture takes effect at the next burst boundary (at most one RX burst of
 * packets, i.e. a few microseconds).  The packet filter itself is still
 * evaluated per packet inside the capture code. */
static inline __attribute__((always_inline)) bool
pkt_capture_on(const struct tr_engine *e, int worker)
{
    if (worker >= 0 && worker < e->workers)
        return e->capture_on[worker];
    return tr_capture_is_active(e->capture);
}

static inline __attribute__((always_inline)) struct tr_iface *
rt_iface(struct tr_runtime *rt, int slot)
{
    if (!rt || (unsigned)slot >= (unsigned)TR_MAX_IFACES)
        return NULL;
    return rt->iface_ptrs[slot];
}

static inline __attribute__((always_inline)) const struct tr_iface *
rt_iface_c(const struct tr_runtime *rt, int slot)
{
    if (!rt || (unsigned)slot >= (unsigned)TR_MAX_IFACES)
        return NULL;
    return rt->iface_ptrs[slot];
}

static inline __attribute__((always_inline)) uint8_t *mtod(struct rte_mbuf *m)
{
    return rte_pktmbuf_mtod(m, uint8_t *);
}

static inline __attribute__((always_inline)) uint32_t
mlen(const struct rte_mbuf *m)
{
    return rte_pktmbuf_pkt_len(m);
}

static inline __attribute__((always_inline)) int
pkt_single(const struct rte_mbuf *m)
{
    return rte_pktmbuf_is_contiguous(m) && m->nb_segs == 1;
}

static const char *const drop_reason_names[TR_DROP_COUNT] = {
    "rx-short",  "rx-mac",  "rx-type", "rx-cksum", "rx-malformed",
    "no-route",  "mtu",     "df",      "ttl",      "neigh",
    "frag",      "tunnel",  "no-tunnel", "bridge", "other",
};

const char *tr_drop_reason_name(int reason)
{
    if (reason < 0 || reason >= TR_DROP_COUNT)
        return "?";
    return drop_reason_names[reason];
}

static void stats_drop_reason(struct tr_engine *e, int worker, int if_slot,
                              enum tr_drop_reason why)
{
    if (if_slot < 0 || if_slot >= TR_MAX_IFACES || worker < 0 ||
        worker >= TR_MAX_WORKERS)
        return;
    atomic_fetch_add_explicit(&e->stats[if_slot][worker].drops, 1,
                              memory_order_relaxed);
    if ((unsigned)why < (unsigned)TR_DROP_COUNT)
        atomic_fetch_add_explicit(&e->stats[if_slot][worker].drop_reason[why],
                                  1, memory_order_relaxed);
}

static void stats_rx_bulk(struct tr_engine *e, int worker, int if_slot,
                          uint32_t pkts, uint64_t bytes)
{
    if (if_slot >= 0 && if_slot < TR_MAX_IFACES && worker >= 0 &&
        worker < TR_MAX_WORKERS && pkts) {
        atomic_fetch_add_explicit(&e->stats[if_slot][worker].rx_pkts, pkts,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&e->stats[if_slot][worker].rx_bytes, bytes,
                                  memory_order_relaxed);
    }
}

/* Fold the worker's per-interface accumulator into the pending arrays. */
static inline void tx_acc_fold(struct tr_engine *e, int worker)
{
    struct tr_tx_acc *a = &e->tx_acc[worker];

    if (a->slot < 0)
        return;
    e->tx_pending_pkts[worker][a->slot] += a->pkts;
    e->tx_pending_bytes[worker][a->slot] += a->bytes;
    e->tx_dirty[worker][a->slot / 64] |= 1ull << (a->slot % 64);
    a->slot = -1;
    a->pkts = 0;
    a->bytes = 0;
}

static inline __attribute__((always_inline)) void
stats_tx(struct tr_engine *e, int worker, int if_slot, uint32_t len)
{
    if (if_slot < 0 || if_slot >= TR_MAX_IFACES)
        return;
    if (worker >= 0 && worker < e->workers) {
        struct tr_tx_acc *a = &e->tx_acc[worker];

        /* Bursts almost always egress one interface; keep the running total
         * in a single cache line and only fold it when the interface
         * changes. */
        if (a->slot == if_slot) {
            a->pkts++;
            a->bytes += len;
            return;
        }
        tx_acc_fold(e, worker);
        a->slot = if_slot;
        a->pkts = 1;
        a->bytes = len;
        return;
    }
    if (worker >= 0 && worker < TR_MAX_WORKERS) {
        atomic_fetch_add_explicit(&e->stats[if_slot][worker].tx_pkts, 1,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&e->stats[if_slot][worker].tx_bytes, len,
                                  memory_order_relaxed);
    } else {
        /* Control-plane transmission (ping/RS). */
        atomic_fetch_add_explicit(&e->stats[if_slot][0].tx_pkts, 1,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&e->stats[if_slot][0].tx_bytes, len,
                                  memory_order_relaxed);
    }
}

static void stats_tx_flush(struct tr_engine *e, int worker)
{
    if (worker < 0 || worker >= e->workers)
        return;
    tx_acc_fold(e, worker);
    for (int w = 0; w < TR_STATS_WORDS; w++) {
        uint64_t bits = e->tx_dirty[worker][w];
        e->tx_dirty[worker][w] = 0;
        while (bits) {
            int bit = __builtin_ctzll(bits);
            int slot = w * 64 + bit;
            bits &= bits - 1;
            if (slot >= TR_MAX_IFACES)
                continue;
            uint64_t pkts = e->tx_pending_pkts[worker][slot];
            uint64_t bytes = e->tx_pending_bytes[worker][slot];
            e->tx_pending_pkts[worker][slot] = 0;
            e->tx_pending_bytes[worker][slot] = 0;
            if (pkts) {
                atomic_fetch_add_explicit(&e->stats[slot][worker].tx_pkts,
                                          pkts, memory_order_relaxed);
                atomic_fetch_add_explicit(&e->stats[slot][worker].tx_bytes,
                                          bytes, memory_order_relaxed);
            }
        }
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

/* Address hash used by the per-worker forwarding caches.  It is deliberately
 * cheaper than tr_ip_hash() (one multiply for IPv4, four for IPv6) because it
 * runs once or twice per packet; the neighbour table keeps its own hash. */
static inline unsigned addr_hash_slot(const struct tr_ip *ip, int slot)
{
    if (ip->family == TR_AF_INET) {
        uint32_t x = ntohl(ip->u.v4.s_addr) ^
                     ((uint32_t)slot * 2654435761u);
        x *= 2654435761u;
        return (unsigned)(x ^ (x >> 16));
    }
    uint32_t w[4];
    uint32_t h = 2166136261u ^ ((uint32_t)slot * 2654435761u);

    memcpy(w, ip->u.v6.s6_addr, sizeof(w));
    for (int i = 0; i < 4; i++) {
        h ^= w[i];
        h *= 16777619u;
    }
    return (unsigned)(h ^ (h >> 16));
}

static unsigned local_map_hash(const struct tr_ip *ip, int if_slot)
{
    return addr_hash_slot(ip, if_slot) & (TR_LOCAL_MAP_SIZE - 1);
}

static struct tr_local_map_entry *local_map_find(struct tr_runtime *rt,
                                                 const struct tr_ip *ip,
                                                 int if_slot)
{
    unsigned h = local_map_hash(ip, if_slot);
    for (int probe = 0; probe < TR_LOCAL_MAP_SIZE; probe++) {
        struct tr_local_map_entry *e =
            &rt->local_map[(h + (unsigned)probe) & (TR_LOCAL_MAP_SIZE - 1)];
        if (!e->used)
            return NULL;
        if (e->if_slot == if_slot && tr_ip_equal(&e->ip, ip))
            return e;
    }
    return NULL;
}

static void local_add(struct tr_runtime *rt, const struct tr_ip *ip,
                      int if_slot, bool linklocal, bool dynamic)
{
    if (rt->nlocals >= TR_LOCAL_MAX || local_map_find(rt, ip, if_slot))
        return;
    rt->locals[rt->nlocals].ip = *ip;
    rt->locals[rt->nlocals].if_slot = if_slot;
    rt->locals[rt->nlocals].linklocal = linklocal;
    rt->locals[rt->nlocals].dynamic = dynamic;
    rt->nlocals++;

    unsigned h = local_map_hash(ip, if_slot);
    for (int probe = 0; probe < TR_LOCAL_MAP_SIZE; probe++) {
        struct tr_local_map_entry *e =
            &rt->local_map[(h + (unsigned)probe) & (TR_LOCAL_MAP_SIZE - 1)];
        if (!e->used) {
            e->used = true;
            e->ip = *ip;
            e->if_slot = if_slot;
            break;
        }
    }
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
    for (int i = 0; i < TR_MAX_IFACES; i++)
        rt->iface_ptrs[i] =
            rt->cfg.ifaces[i].present ? &rt->cfg.ifaces[i] : NULL;
    tr_fib_init(&rt->fib);
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        const struct tr_iface *iface = &rt->cfg.ifaces[i];
        if (!iface->present || iface->kind != TR_IF_VLAN)
            continue;
        uint16_t outer = iface->vlan_outer >= 0
                             ? (uint16_t)iface->vlan_outer
                             : (uint16_t)iface->vlan_id;
        uint16_t inner = iface->vlan_outer >= 0 ? (uint16_t)iface->vlan_id : 0;
        unsigned h = (unsigned)(((iface->parent * 4096 + outer) * 2654435761u) ^
                                inner) &
                     (TR_VLAN_MAP_SIZE - 1);
        for (int probe = 0; probe < TR_VLAN_MAP_SIZE; probe++) {
            struct tr_vlan_map_entry *entry =
                &rt->vlan_map[(h + (unsigned)probe) & (TR_VLAN_MAP_SIZE - 1)];
            if (!entry->used) {
                entry->used = true;
                entry->parent = iface->parent;
                entry->outer = outer;
                entry->inner = inner;
                entry->child = (int16_t)i;
                break;
            }
        }
    }

    for (int i = 0; i < TR_TUNNEL_HASH_SIZE; i++)
        rt->tunnel_head[i] = -1;
    for (int i = 0; i < TR_MAX_IFACES; i++)
        rt->tunnel_next[i] = -1;
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
            unsigned h = tr_ip_hash(&t->remote) & (TR_TUNNEL_HASH_SIZE - 1);
            rt->tunnel_next[i] = rt->tunnel_head[h];
            rt->tunnel_head[h] = i;
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

static void runtime_read_enter(struct tr_engine *e, int worker)
{
    for (;;) {
        while (atomic_load_explicit(&e->rt_updating, memory_order_acquire))
            rte_pause();
        atomic_store_explicit(&e->rt_reader[worker], true,
                              memory_order_release);
        if (!atomic_load_explicit(&e->rt_updating, memory_order_acquire))
            return;
        atomic_store_explicit(&e->rt_reader[worker], false,
                              memory_order_release);
    }
}

static void runtime_read_exit(struct tr_engine *e, int worker)
{
    atomic_store_explicit(&e->rt_reader[worker], false,
                          memory_order_release);
}

static void runtime_pause(struct tr_engine *e)
{
    atomic_store_explicit(&e->rt_updating, true, memory_order_release);
    for (int w = 0; w < e->workers; w++) {
        while (atomic_load_explicit(&e->rt_reader[w], memory_order_acquire))
            rte_pause();
    }
}

static void runtime_resume(struct tr_engine *e)
{
    atomic_store_explicit(&e->rt_updating, false, memory_order_release);
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
    for (int i = 0; i < TR_MAX_WORKERS; i++) {
        e->now_ms[i] = tr_monotonic_ms();
        e->capture_on[i] = false;
        e->tx_acc[i].slot = -1;
    }
    pthread_rwlock_init(&e->rt_lock, NULL);
    pthread_mutex_init(&e->ra_lock, NULL);
    pthread_mutex_init(&e->ping.lock, NULL);
    pthread_mutex_init(&e->trace.lock, NULL);
    tr_neigh_init(&e->neigh4, free_mbuf_cb);
    tr_neigh_init(&e->neigh6, free_mbuf_cb);
    tr_bridge_db_init(&e->bridges);
    for (int i = 0; i < TR_MAX_WORKERS; i++)
        tr_reasm_init(&e->reasm[i]);
    if (tr_capture_create(&e->capture, err, errlen)) {
        tr_engine_destroy(e);
        return NULL;
    }

    tr_config_init(&empty);
    if (runtime_build(e, &empty, &rt, err, errlen)) {
        snprintf(err, errlen, "cannot build initial runtime");
        tr_engine_destroy(e);
        return NULL;
    }
    e->rt = rt;
    atomic_store_explicit(&e->rt_fast, rt, memory_order_release);
    return e;
}

void tr_engine_destroy(struct tr_engine *e)
{
    if (!e)
        return;
    runtime_free(e->rt);
    e->rt = NULL;
    tr_capture_destroy(e->capture);
    tr_neigh_fini(&e->neigh4);
    tr_neigh_fini(&e->neigh6);
    tr_bridge_db_fini(&e->bridges);
    for (int i = 0; i < TR_MAX_WORKERS; i++)
        tr_reasm_fini(&e->reasm[i]);
    pthread_mutex_destroy(&e->trace.lock);
    pthread_mutex_destroy(&e->ping.lock);
    pthread_mutex_destroy(&e->ra_lock);
    pthread_rwlock_destroy(&e->rt_lock);
    free(e);
}

void tr_engine_set_tx(struct tr_engine *e, tr_tx_fn tx, void *arg)
{
    e->tx = tx;
    e->tx_arg = arg;
}

void tr_engine_set_tx_ipv4_cksum(struct tr_engine *e, bool enabled)
{
    if (e)
        e->tx_ipv4_cksum = enabled;
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
    runtime_pause(e);
    old = e->rt;
    e->rt = nr;
    atomic_store_explicit(&e->rt_fast, nr, memory_order_release);
    /* No packet reader can observe the old runtime or these tables while
     * rt_updating is set and rt_active is zero. */
    tr_neigh_clear(&e->neigh4);
    tr_neigh_clear(&e->neigh6);
    for (int i = 0; i < TR_MAX_IFACES; i++)
        tr_bridge_clear(&e->bridges, i);
    runtime_resume(e);
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

static int pkt_add_qinq(struct rte_mbuf *m, uint16_t outer, uint16_t inner)
{
    uint8_t *p;
    uint32_t len = mlen(m);

    if (len < 12 || !pkt_single(m))
        return -1;
    p = (uint8_t *)rte_pktmbuf_prepend(m, 8);
    if (!p)
        return -1;
    memmove(p, p + 8, 12);
    p[12] = ETH_TYPE_QINQ >> 8;
    p[13] = ETH_TYPE_QINQ & 0xff;
    p[14] = (uint8_t)(outer >> 8);
    p[15] = (uint8_t)outer;
    p[16] = ETH_TYPE_VLAN >> 8;
    p[17] = ETH_TYPE_VLAN & 0xff;
    p[18] = (uint8_t)(inner >> 8);
    p[19] = (uint8_t)inner;
    return 0;
}

static int pkt_strip_qinq(struct rte_mbuf *m)
{
    uint8_t *p = mtod(m);
    uint32_t len = mlen(m);

    if (len < 22 || p[12] != (ETH_TYPE_QINQ >> 8) || p[13] != 0xa8 ||
        p[16] != (ETH_TYPE_VLAN >> 8) || p[17] != 0x00 || !pkt_single(m))
        return -1;
    memmove(p + 12, p + 20, len - 20);
    rte_pktmbuf_trim(m, 8);
    return 0;
}

static bool pkt_tagged(const struct rte_mbuf *m)
{
    const uint8_t *p;

    if (mlen(m) < 14 || !pkt_single(m))
        return false;
    p = rte_pktmbuf_mtod(m, const uint8_t *);
    return (p[12] == (ETH_TYPE_VLAN >> 8) && p[13] == 0x00) ||
           (p[12] == (ETH_TYPE_QINQ >> 8) && p[13] == 0xa8);
}




static const struct tr_iface *iface_by_slot_rt(const struct tr_runtime *rt,
                                                int slot)
{
    return rt_iface_c(rt, slot);
}


static inline __attribute__((always_inline)) bool
is_local_if(const struct tr_runtime *rt, int if_slot, const struct tr_ip *ip)
{
    /* Small tables are cheaper to scan than to hash; anything larger uses the
     * open-addressed map built by local_add(). */
    if (rt->nlocals <= 2) {
        for (int i = 0; i < rt->nlocals; i++) {
            if (rt->locals[i].if_slot == if_slot &&
                tr_ip_equal(&rt->locals[i].ip, ip))
                return true;
        }
        return false;
    }
    unsigned h = local_map_hash(ip, if_slot);
    for (int probe = 0; probe < TR_LOCAL_MAP_SIZE; probe++) {
        const struct tr_local_map_entry *e =
            &rt->local_map[(h + (unsigned)probe) & (TR_LOCAL_MAP_SIZE - 1)];
        if (!e->used)
            return false;
        if (e->if_slot == if_slot && tr_ip_equal(&e->ip, ip))
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
static unsigned rt_cache_hash6(const struct tr_ip *ip)
{
    uint32_t w[4];
    uint32_t h = 2166136261u;

    memcpy(w, ip->u.v6.s6_addr, sizeof(w));
    for (int i = 0; i < 4; i++) {
        h ^= w[i];
        h *= 16777619u;
    }
    return (unsigned)(h ^ (h >> 16));
}

static int fib_lookup_cached(struct tr_engine *e, int worker,
                             struct tr_runtime *rt, const struct tr_ip *dst,
                             struct tr_fib_result *out)
{
    if (!e || worker < 0 || worker >= e->workers)
        return tr_fib_lookup(&rt->fib, dst, out);
    if (dst->family == TR_AF_INET) {
        /* Multiplicative hash on the raw network-order address: one multiply
         * and a shift, no byte swap. */
        uint32_t addr = dst->u.v4.s_addr;
        uint32_t x = addr * 2654435761u;
        struct tr_rt_cache4 *c =
            &e->rt_cache4[worker][(x >> 22) & (TR_RT_CACHE4_SIZE - 1)];

        if (c->addr == addr && c->route) {
            out->route = c->route;
            out->prefix_len = c->plen;
            return 0;
        }
        if (tr_fib_lookup(&rt->fib, dst, out))
            return -1;
        c->addr = addr;
        c->plen = (uint16_t)out->prefix_len;
        c->route = out->route;
        return 0;
    }
    struct tr_rt_cache6 *c =
        &e->rt_cache6[worker][rt_cache_hash6(dst) & (TR_RT_CACHE6_SIZE - 1)];

    if (c->route && tr_ip_equal(&c->dst, dst)) {
        out->route = c->route;
        out->prefix_len = (int)c->plen;
        return 0;
    }
    if (tr_fib_lookup(&rt->fib, dst, out))
        return -1;
    c->dst = *dst;
    c->plen = (uint32_t)out->prefix_len;
    c->route = out->route;
    return 0;
}

static int neigh_lookup_cached(struct tr_engine *e, int worker,
                               struct tr_runtime *rt, int if_slot,
                               const struct tr_ip *ip, uint64_t now,
                               uint8_t mac[6], uint8_t *state)
{
    struct tr_neigh_table *t =
        ip->family == TR_AF_INET ? &e->neigh4 : &e->neigh6;
    unsigned h = addr_hash_slot(ip, if_slot);
    struct tr_neigh_cache_entry *c =
        &e->neigh_cache[worker][h & (TR_NEIGH_CACHE_SIZE - 1)];

    if (c->valid && c->generation == rt->generation &&
        c->if_slot == if_slot && tr_ip_equal(&c->ip, ip) &&
        now >= c->seen_ms && now - c->seen_ms < TR_NEIGH_CACHE_TTL_MS) {
        memcpy(mac, c->mac, 6);
        if (state)
            *state = TR_NEIGH_REACHABLE;
        return 1;
    }
    if (tr_neigh_get(t, if_slot, ip, mac, now, state)) {
        c->valid = true;
        c->generation = rt->generation;
        c->seen_ms = now;
        c->if_slot = if_slot;
        c->ip = *ip;
        memcpy(c->mac, mac, 6);
        return 1;
    }
    return 0;
}

static void resolve_and_send_at(struct tr_engine *e, int worker,
                                struct tr_runtime *rt,
                                const struct tr_iface *iface,
                                const struct tr_ip *next_hop,
                                struct rte_mbuf *m);
static void send_neighbor_request(struct tr_engine *e, int worker,
                                  struct tr_runtime *rt, int if_slot,
                                  const struct tr_ip *target, uint8_t family);

/* `iface` is the egress interface already resolved by the caller: the
 * forwarding path looks each interface up once instead of once per helper. */
static void l2_emit(struct tr_engine *e, int worker, struct tr_runtime *rt,
                    int if_slot, const struct tr_iface *iface,
                    struct rte_mbuf *m)
{
    uint32_t maxlen;

    if (!iface || !m) {
        if (m)
            rte_pktmbuf_free(m);
        return;
    }
    bool tagged = pkt_tagged(m);
    bool qinq = iface->kind == TR_IF_VLAN && iface->vlan_outer >= 0;
    uint32_t tag_len = qinq ? 8 : 4;
    bool will_tag = iface->kind == TR_IF_VLAN && !tagged;
    uint32_t final_len = mlen(m) + (will_tag ? tag_len : 0);
    maxlen = iface->mtu + ETH_HLEN + ((tagged || will_tag) ? tag_len : 0);
    if (final_len > maxlen) {
        stats_drop_reason(e, worker, if_slot, TR_DROP_MTU);
        rte_pktmbuf_free(m);
        return;
    }
    if (!e->tx) {
        stats_drop_reason(e, worker, if_slot, TR_DROP_OTHER);
        rte_pktmbuf_free(m);
        return;
    }
    bool capture = pkt_capture_on(e, worker);
    if (iface->kind == TR_IF_VLAN) {
        /* Logical VLAN tap: untagged inner frame, like tcpdump on eth0.10. */
        if (capture)
            tr_capture_tap_exact(e->capture, if_slot, TR_CAP_TX, m);
        if (will_tag &&
            (qinq ? pkt_add_qinq(m, (uint16_t)iface->vlan_outer,
                                 (uint16_t)iface->vlan_id)
                  : pkt_add_vlan(m, (uint16_t)iface->vlan_id))) {
            stats_drop_reason(e, worker, if_slot, TR_DROP_MTU);
            rte_pktmbuf_free(m);
            return;
        }
        /* Physical parent tap: tagged frame on the wire. */
        if (capture)
            tr_capture_tap(e->capture, iface->parent, TR_CAP_TX, m);
    } else if (capture) {
        tr_capture_tap(e->capture, if_slot, TR_CAP_TX, m);
    }
    stats_tx(e, worker, if_slot, mlen(m));
    e->tx(e->tx_arg, worker, if_slot, m);
}

static inline __attribute__((always_inline)) void
egress_frame_iface(struct tr_engine *e, int worker, struct tr_runtime *rt,
                   const struct tr_iface *iface, struct rte_mbuf *m)
{
    if (!iface) {
        rte_pktmbuf_free(m);
        return;
    }
    if (iface->kind == TR_IF_TUNNEL)
        tunnel_send(e, worker, rt, iface->slot, m);
    else
        l2_emit(e, worker, rt, iface->slot, iface, m);
}

static void egress_frame(struct tr_engine *e, int worker,
                         struct tr_runtime *rt, int if_slot,
                         struct rte_mbuf *m)
{
    egress_frame_iface(e, worker, rt, iface_by_slot_rt(rt, if_slot), m);
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

    if (tr_neigh_learn(t, if_slot, ip, mac, pkt_now(e, worker), pending,
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

/* `iface` is the resolved egress interface for the next hop, so the frame can
 * be handed to the egress path without another slot lookup. */
static inline __attribute__((always_inline)) void
resolve_and_send_at(struct tr_engine *e, int worker, struct tr_runtime *rt,
                    const struct tr_iface *iface,
                    const struct tr_ip *next_hop, struct rte_mbuf *m)
{
    uint8_t mac[6];
    uint8_t state = 0;
    struct tr_neigh_table *t;
    int if_slot = iface->slot;
    uint64_t now = pkt_now(e, worker);

    if (!m || (next_hop->family != TR_AF_INET &&
               next_hop->family != TR_AF_INET6)) {
        if (m)
            rte_pktmbuf_free(m);
        return;
    }
    t = next_hop->family == TR_AF_INET ? &e->neigh4 : &e->neigh6;
    if (neigh_lookup_cached(e, worker, rt, if_slot, next_hop, now, mac,
                            &state)) {
        if (mlen(m) >= 6)
            memcpy(mtod(m), mac, 6);
        egress_frame_iface(e, worker, rt, iface, m);
        return;
    }
    if (tr_neigh_queue(t, if_slot, next_hop, m, now)) {
        stats_drop_reason(e, worker, if_slot, TR_DROP_NEIGH);
        rte_pktmbuf_free(m);
        return;
    }
    if (tr_neigh_request_allowed(t, if_slot, next_hop, now, 1000))
        send_neighbor_request(e, worker, rt, if_slot, next_hop,
                              next_hop->family);
}

static int if_slot_stats_valid(struct tr_engine *e, int worker, int if_slot);

static int underlay_next_hop(struct tr_engine *e, int worker,
                             struct tr_runtime *rt, int if_slot,
                             const struct tr_ip *remote,
                             struct tr_ip *next_hop)
{
    struct tr_fib_result res;

    if (fib_lookup_cached(e, worker, rt, remote, &res) == 0 &&
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

    /* The rewrite touches bytes anywhere in the TCP header, so only a
     * contiguous single-segment frame can be clamped safely. */
    if (t->tcp_mss < 0 || len < 34 || !pkt_single(m))
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
        /* outer IP packet = outer header (IP + EtherIP)
         *                 + inner Ethernet header
         *                 + inner IP header + TCP header + MSS  */
        int inner_hdr = family == 4 ? 40 : 60; /* inner IP + TCP */
        int outer_hdr = t->family == 4 ? 22 : 42;
        int v = (int)under->mtu - outer_hdr - ETH_HLEN - inner_hdr;
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
        stats_drop_reason(e, worker, under_slot, TR_DROP_FRAG);
        rte_pktmbuf_free(m);
        return;
    }
    p = mtod(m);
    memcpy(p + 6, under->mac, 6);
    p[12] = family == 4 ? ETH_TYPE_IPV4 >> 8 : ETH_TYPE_IPV6 >> 8;
    p[13] = family == 4 ? ETH_TYPE_IPV4 & 0xff : ETH_TYPE_IPV6 & 0xff;
    resolve_and_send_at(e, worker, rt, under, next_hop, m);
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
        stats_drop_reason(e, worker, if_slot, TR_DROP_TUNNEL);
        rte_pktmbuf_free(m);
        return;
    }
    max_inner = iface->mtu + ETH_HLEN + (pkt_tagged(m) ? 4 : 0);
    if (mlen(m) > max_inner || !pkt_single(m)) {
        stats_drop_reason(e, worker, if_slot, TR_DROP_MTU);
        rte_pktmbuf_free(m);
        return;
    }
    if (t->local_if_slot >= 0) {
        under_slot = t->local_if_slot;
    } else {
        struct tr_fib_result res;
        if (fib_lookup_cached(e, worker, rt, &t->remote, &res) ||
            res.route->if_slot < 0) {
            stats_drop_reason(e, worker, if_slot, TR_DROP_NO_ROUTE);
            rte_pktmbuf_free(m);
            return;
        }
        under_slot = res.route->if_slot;
    }
    under = rt_iface(rt, under_slot);
    if (!under || (under->kind != TR_IF_ETHERNET &&
                   under->kind != TR_IF_VLAN)) {
        stats_drop_reason(e, worker, if_slot, TR_DROP_NO_ROUTE);
        rte_pktmbuf_free(m);
        return;
    }
    if (t->local.family) {
        src = t->local;
    } else {
        bool prefer_ll = t->family == TR_AF_INET6 &&
                         tr_ip_is_linklocal(&t->remote);
        if (pick_addr(rt, under_slot, t->family, prefer_ll, &src)) {
            stats_drop_reason(e, worker, if_slot, TR_DROP_NO_ROUTE);
            rte_pktmbuf_free(m);
            return;
        }
    }
    if (src.family != t->family || t->remote.family != t->family) {
        stats_drop_reason(e, worker, if_slot, TR_DROP_NO_ROUTE);
        rte_pktmbuf_free(m);
        return;
    }

    mss_clamp_frame(e, worker, rt, t, under_slot, m);
    tr_capture_tap(e->capture, if_slot, TR_CAP_TX, m);

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
        stats_drop_reason(e, worker, if_slot, TR_DROP_TUNNEL);
        rte_pktmbuf_free(m);
        return;
    }
    m->data_off = frame.off;
    m->pkt_len = frame.len;
    m->data_len = frame.len;
    under_mtu = under->mtu;
    len = mlen(m);
    if (underlay_next_hop(e, worker, rt, under_slot, &t->remote, &next_hop)) {
        stats_drop_reason(e, worker, if_slot, TR_DROP_NO_ROUTE);
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
        stats_drop_reason(e, worker, if_slot, TR_DROP_FRAG);
        return;
    }
    for (int i = 0; i < nf; i++) {
        struct rte_mbuf *fm = pkt_alloc(e, frags[i].len);
        if (!fm) {
            free(frags[i].data);
            stats_drop_reason(e, worker, if_slot, TR_DROP_FRAG);
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
    unsigned h = tr_ip_hash(src) & (TR_TUNNEL_HASH_SIZE - 1);
    for (int i = rt->tunnel_head[h]; i >= 0; i = rt->tunnel_next[i]) {
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
        stats_drop_reason(e, worker, ingress, TR_DROP_NO_TUNNEL);
        rte_pktmbuf_free(m);
        return;
    }
    t = &rt->tunnel[tslot];
    iface = rt_iface(rt, tslot);
    if (!iface || !t->driver) {
        stats_drop_reason(e, worker, ingress, TR_DROP_TUNNEL);
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
        stats_drop_reason(e, worker, ingress, TR_DROP_TUNNEL);
        rte_pktmbuf_free(m);
        return;
    }
    if (frame.len < ETH_HLEN ||
        frame.len > iface->mtu + ETH_HLEN + 8) {
        stats_drop_reason(e, worker, ingress, TR_DROP_MTU);
        rte_pktmbuf_free(m);
        return;
    }
    m->data_off = frame.off;
    m->pkt_len = frame.len;
    m->data_len = frame.len;
    if (if_slot_stats_valid(e, worker, tslot))
        atomic_fetch_add_explicit(&e->stats[tslot][worker].reasm_ok, 1,
                                  memory_order_relaxed);
    /* Clamp TCP MSS on frames leaving the tunnel as well.  Clamping only on
     * the transmit side would leave a SYN-ACK coming out of the tunnel
     * unmodified, so a host on a large-MTU LAN would keep advertising (and
     * accepting) segments large enough that every one of them has to be
     * fragmented by the underlay. */
    mss_clamp_frame(e, worker, rt, t, ingress, m);
    tr_capture_tap(e->capture, tslot, TR_CAP_RX, m);
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
    stats_drop_reason(e, worker, if_slot, TR_DROP_RX_MALFORMED);
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

static void trace_note_reply(struct tr_engine *e, const struct tr_ip *src,
                            const struct tr_ip *dst, uint8_t kind,
                            uint8_t ttl, uint16_t id, uint16_t seq)
{
    if (!atomic_load_explicit(&e->trace.active, memory_order_relaxed))
        return;
    uint64_t now = tr_monotonic_ns();
    pthread_mutex_lock(&e->trace.lock);
    if (e->trace.active && id == e->trace.id && seq == e->trace.seq &&
        !e->trace.replied && tr_ip_equal(dst, &e->trace.source) &&
        (kind == 1 || tr_ip_equal(src, &e->trace.target))) {
        e->trace.replied = true;
        e->trace.reply_kind = kind;
        e->trace.ttl = ttl;
        e->trace.responder = *src;
        e->trace.rtt_ns = now - e->trace.sent_ns;
    }
    pthread_mutex_unlock(&e->trace.lock);
}

static void ping_note_reply(struct tr_engine *e, const struct tr_ip *src,
                            const struct tr_ip *dst, const uint8_t *icmp,
                            uint8_t ttl);

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
    if (icmp_type == 3 && icmp_len >= 8 + 40 + 8) {
        const uint8_t *emb = icmp + 8;
        const uint8_t *ei = emb + 40;
        if (ei[0] == ICMPV6_ECHO_REQUEST) {
            struct tr_ip esrc = {.family = TR_AF_INET6};
            struct tr_ip edst = {.family = TR_AF_INET6};
            memcpy(&esrc.u.v6, ip + 8, 16);
            memcpy(&edst.u.v6, ip + 24, 16);
            trace_note_reply(e, &esrc, &edst, 1, ip[7],
                             (uint16_t)(ei[4] << 8 | ei[5]),
                             (uint16_t)(ei[6] << 8 | ei[7]));
            rte_pktmbuf_free(m);
            return;
        }
    }
    if (icmp_type == ICMPV6_ECHO_REPLY) {
        uint16_t id = (uint16_t)(icmp[4] << 8 | icmp[5]);
        uint16_t seq = (uint16_t)(icmp[6] << 8 | icmp[7]);
        ping_note_reply(e, &src, &dst, icmp, ip[7]);
        trace_note_reply(e, &src, &dst, 2, ip[7], id, seq);
        rte_pktmbuf_free(m);
        return;
    }
    if (icmp_type == ICMPV6_ECHO_REQUEST && is_local_if(rt, if_slot, &dst)) {
        send_echo_reply6(e, worker, rt, if_slot, m, l3off);
        rte_pktmbuf_free(m);
        return;
    }
drop:
    stats_drop_reason(e, worker, if_slot, TR_DROP_RX_MALFORMED);
    rte_pktmbuf_free(m);
}

static void ping_note_reply(struct tr_engine *e, const struct tr_ip *src,
                            const struct tr_ip *dst, const uint8_t *icmp,
                            uint8_t ttl)
{
    if (!atomic_load_explicit(&e->ping.active, memory_order_relaxed))
        return;
    uint16_t id = (uint16_t)(icmp[4] << 8 | icmp[5]);
    uint16_t seq = (uint16_t)(icmp[6] << 8 | icmp[7]);
    uint64_t now = tr_monotonic_ns();

    pthread_mutex_lock(&e->ping.lock);
    if (e->ping.active && id == e->ping.id && seq == e->ping.seq &&
        !e->ping.replied && tr_ip_equal(src, &e->ping.target) &&
        tr_ip_equal(dst, &e->ping.source)) {
        e->ping.replied = true;
        e->ping.ttl = ttl;
        e->ping.rtt_ns = now - e->ping.sent_ns;
    }
    pthread_mutex_unlock(&e->ping.lock);
}

static void handle_icmp4(struct tr_engine *e, int worker,
                         struct tr_runtime *rt, int if_slot,
                         struct rte_mbuf *m, uint32_t l3off,
                         const uint8_t *ip)
{
    uint8_t *icmp = mtod(m) + l3off + 20;
    if (mlen(m) < l3off + 20 + 8)
        goto drop;
    if (icmp[0] == 11 && mlen(m) >= l3off + 20 + 8 + 20 + 8) {
        const uint8_t *emb = icmp + 8;
        uint32_t eihl = (uint32_t)(emb[0] & 0x0f) * 4;
        if (eihl >= 20 && mlen(m) >= l3off + 20 + 8 + eihl + 8 &&
            emb[eihl] == ICMP_ECHO) {
            const uint8_t *ei = emb + eihl;
            struct tr_ip esrc = {.family = TR_AF_INET};
            struct tr_ip edst = {.family = TR_AF_INET};
            memcpy(&esrc.u.v4, ip + 12, 4);
            memcpy(&edst.u.v4, ip + 16, 4);
            trace_note_reply(e, &esrc, &edst, 1, ip[8],
                             (uint16_t)(ei[4] << 8 | ei[5]),
                             (uint16_t)(ei[6] << 8 | ei[7]));
            rte_pktmbuf_free(m);
            return;
        }
    }
    if (icmp[0] == ICMP_ECHO_REPLY) {
        struct tr_ip src = {.family = TR_AF_INET};
        struct tr_ip dst = {.family = TR_AF_INET};
        memcpy(&src.u.v4, ip + 12, 4);
        memcpy(&dst.u.v4, ip + 16, 4);
        uint16_t id = (uint16_t)(icmp[4] << 8 | icmp[5]);
        uint16_t seq = (uint16_t)(icmp[6] << 8 | icmp[7]);
        ping_note_reply(e, &src, &dst, icmp, ip[8]);
        trace_note_reply(e, &src, &dst, 2, ip[8], id, seq);
        rte_pktmbuf_free(m);
        return;
    }
    if (icmp[0] != ICMP_ECHO)
        goto drop;
    send_echo_reply4(e, worker, rt, if_slot, m, l3off);
    rte_pktmbuf_free(m);
    return;
drop:
    stats_drop_reason(e, worker, if_slot, TR_DROP_RX_MALFORMED);
    rte_pktmbuf_free(m);
}

/* Slow path of IPv4 forwarding: the egress interface MTU is smaller than the
 * packet, so the datagram has to be fragmented.  It is deliberately a
 * separate out-of-line function because the descriptor array it needs
 * (TR_FRAG_MAX_OUT * 16 = 2 KiB) used to be part of l3_forward4()'s stack
 * frame, which every forwarded packet paid for in the function prologue.
 * Fraction of traffic that reaches this path: MTU mismatch only. */
static __attribute__((noinline)) void forward4_fragment(
    struct tr_engine *e, int worker, struct tr_runtime *rt, int in_slot,
    const struct tr_iface *egress, struct rte_mbuf *m, const uint8_t *ip,
    uint32_t ip_len, const struct tr_ip *next_hop)
{
    struct tr_frag_packet frags[TR_FRAG_MAX_OUT];
    int nf = tr_frag4(ip, ip_len, egress->mtu, frags, TR_FRAG_MAX_OUT);

    if (nf <= 0) {
        stats_drop_reason(e, worker, in_slot, TR_DROP_FRAG);
        rte_pktmbuf_free(m);
        return;
    }
    for (int i = 0; i < nf; i++) {
        struct rte_mbuf *frag_m = pkt_alloc(e, ETH_HLEN + frags[i].len);
        if (!frag_m) {
            free(frags[i].data);
            continue;
        }
        memcpy(mtod(frag_m) + ETH_HLEN, frags[i].data, frags[i].len);
        free(frags[i].data);
        memcpy(mtod(frag_m) + 6, egress->mac, 6);
        mtod(frag_m)[12] = ETH_TYPE_IPV4 >> 8;
        mtod(frag_m)[13] = ETH_TYPE_IPV4 & 0xff;
        resolve_and_send_at(e, worker, rt, egress, next_hop, frag_m);
    }
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

    dst.family = TR_AF_INET;
    memcpy(&dst.u.v4, p + 16, 4);
    if (is_local_if(rt, if_slot, &dst)) {
        if (p[9] == IPPROTO_ICMP) {
            handle_icmp4(e, worker, rt, if_slot, m, l3off, ip);
        } else {
            stats_drop_reason(e, worker, if_slot, TR_DROP_RX_TYPE);
            rte_pktmbuf_free(m);
        }
        return;
    }
    if (fib_lookup_cached(e, worker, rt, &dst, &res) ||
        res.route->if_slot < 0) {
        send_icmp4_error(e, worker, rt, if_slot, m, l3off,
                         ICMP_DEST_UNREACH, 0, 0);
        stats_drop_reason(e, worker, if_slot, TR_DROP_NO_ROUTE);
        rte_pktmbuf_free(m);
        return;
    }
    egress = rt_iface(rt, res.route->if_slot);
    if (!egress) {
        stats_drop_reason(e, worker, if_slot, TR_DROP_NO_ROUTE);
        rte_pktmbuf_free(m);
        return;
    }
    if (ttl <= 1) {
        send_icmp4_error(e, worker, rt, if_slot, m, l3off,
                         ICMP_TIME_EXCEEDED, 0, 0);
        stats_drop_reason(e, worker, if_slot, TR_DROP_TTL);
        rte_pktmbuf_free(m);
        return;
    }
    if (ip_len > egress->mtu) {
        if (df) {
            send_icmp4_error(e, worker, rt, if_slot, m, l3off,
                             ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
                             (uint16_t)egress->mtu);
            stats_drop_reason(e, worker, if_slot, TR_DROP_DF);
            rte_pktmbuf_free(m);
            return;
        }
        next_hop = res.route->has_via ? res.route->via : dst;
        forward4_fragment(e, worker, rt, if_slot, egress, m, ip, ip_len,
                          &next_hop);
        return;
    }
    p[8] = (uint8_t)(ttl - 1);
    bool hw_cksum = e->tx_ipv4_cksum &&
                    egress->kind != TR_IF_TUNNEL;
    if (hw_cksum) {
        p[10] = 0;
        p[11] = 0;
        m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
        m->l2_len = egress->kind == TR_IF_VLAN
                        ? (egress->vlan_outer >= 0 ? 22 : 18)
                        : 14;
        m->l3_len = (uint16_t)((p[0] & 0x0f) * 4);
    } else {
        /* Only the TTL halfword changed (the header checksum was verified on
         * ingress), so update the checksum incrementally instead of summing
         * the whole header again. */
        uint16_t old_word = (uint16_t)((uint16_t)ttl << 8 | p[9]);
        uint16_t new_word = (uint16_t)((uint16_t)(ttl - 1) << 8 | p[9]);
        uint16_t csum = tr_checksum16_update((uint16_t)(p[10] << 8 | p[11]),
                                             old_word, new_word);
        p[10] = (uint8_t)(csum >> 8);
        p[11] = (uint8_t)csum;
    }
    next_hop = res.route->has_via ? res.route->via : dst;
    memcpy(mtod(m) + 6, egress->mac, 6);
    resolve_and_send_at(e, worker, rt, egress, &next_hop, m);
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
            stats_drop_reason(e, worker, if_slot, TR_DROP_RX_TYPE);
            rte_pktmbuf_free(m);
        }
        return;
    }
    if (fib_lookup_cached(e, worker, rt, &dst, &res) ||
        res.route->if_slot < 0) {
        send_icmp6_error(e, worker, rt, if_slot, m, l3off,
                         ICMPV6_DEST_UNREACH, 0, 0);
        stats_drop_reason(e, worker, if_slot, TR_DROP_NO_ROUTE);
        rte_pktmbuf_free(m);
        return;
    }
    egress = rt_iface(rt, res.route->if_slot);
    if (!egress) {
        stats_drop_reason(e, worker, if_slot, TR_DROP_NO_ROUTE);
        rte_pktmbuf_free(m);
        return;
    }
    if (p[7] <= 1) {
        send_icmp6_error(e, worker, rt, if_slot, m, l3off,
                         ICMPV6_TIME_EXCEEDED, 0, 0);
        stats_drop_reason(e, worker, if_slot, TR_DROP_TTL);
        rte_pktmbuf_free(m);
        return;
    }
    if (plen > egress->mtu) {
        send_icmp6_error(e, worker, rt, if_slot, m, l3off,
                         ICMPV6_PACKET_TOO_BIG, 0, egress->mtu);
        stats_drop_reason(e, worker, if_slot, TR_DROP_MTU);
        rte_pktmbuf_free(m);
        return;
    }
    p[7]--;
    next_hop = res.route->has_via ? res.route->via : dst;
    memcpy(mtod(m) + 6, egress->mac, 6);
    resolve_and_send_at(e, worker, rt, egress, &next_hop, m);
}

static void l3_ingress(struct tr_engine *e, int worker,
                       struct tr_runtime *rt, int if_slot,
                       const struct tr_iface *iface, struct rte_mbuf *m,
                       bool tagged)
{
    uint8_t *p;
    uint32_t len;
    uint16_t type;
    uint32_t l3off = ETH_HLEN;
    enum tr_drop_reason why = TR_DROP_RX_TYPE;

    if (!iface) {
        rte_pktmbuf_free(m);
        return;
    }
    len = mlen(m);
    if (len < ETH_HLEN) {
        why = TR_DROP_RX_SHORT;
        goto drop;
    }
    if (tagged) {
        uint16_t vid;
        if (pkt_strip_vlan(m, &vid)) {
            why = TR_DROP_RX_MALFORMED;
            goto drop;
        }
        len = mlen(m);
    }
    p = mtod(m);
    if (len < ETH_HLEN) {
        why = TR_DROP_RX_SHORT;
        goto drop;
    }
    if (!tr_mac_is_multicast(p) && memcmp(p, iface->mac, 6) != 0) {
        why = TR_DROP_RX_MAC;
        goto drop;
    }
    type = (uint16_t)(p[12] << 8 | p[13]);
    if (type == ETH_TYPE_ARP) {
        handle_arp(e, worker, rt, if_slot, m);
        return;
    }
    if (type == ETH_TYPE_IPV4) {
        uint32_t total;
        if (len < l3off + 20) {
            why = TR_DROP_RX_SHORT;
            goto drop;
        }
        uint8_t *ip = p + l3off;
        uint32_t ihl = (uint32_t)(ip[0] & 0x0f) * 4;
        if ((ip[0] >> 4) != 4 || ihl < 20 || len < l3off + ihl) {
            why = TR_DROP_RX_MALFORMED;
            goto drop;
        }
        if ((m->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) !=
                RTE_MBUF_F_RX_IP_CKSUM_GOOD &&
            !tr_ip4_cksum_ok(ip, ihl)) {
            why = TR_DROP_RX_CKSUM;
            goto drop;
        }
        total = (uint32_t)(ip[2] << 8 | ip[3]);
        if (total < ihl || l3off + total > len) {
            why = TR_DROP_RX_MALFORMED;
            goto drop;
        }
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
                                         pkt_now(e, worker), &out);
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
        if (len < l3off + 40) {
            why = TR_DROP_RX_SHORT;
            goto drop;
        }
        uint8_t *ip = p + l3off;
        uint32_t plen = (uint32_t)(ip[4] << 8 | ip[5]);
        if ((ip[0] >> 4) != 6 || l3off + 40 + plen > len) {
            why = TR_DROP_RX_MALFORMED;
            goto drop;
        }
        if (len > l3off + 40 + plen)
            rte_pktmbuf_trim(m, (uint16_t)(len - l3off - 40 - plen));
        if (ip[6] == IPPROTO_FRAGMENT) {
            if (plen < 8) {
                why = TR_DROP_RX_MALFORMED;
                goto drop;
            }
            uint8_t *fh = ip + 40;
            uint16_t fo = (uint16_t)(fh[2] << 8 | fh[3]);
            uint32_t frag_off = fo & 0xfff8;
            bool more = (fo & 1) != 0;
            uint32_t id = (uint32_t)fh[4] << 24 | (uint32_t)fh[5] << 16 |
                          (uint32_t)fh[6] << 8 | fh[7];
            uint8_t nh = fh[0];
            if (nh != IPPROTO_ETHERIP) {
                why = TR_DROP_RX_TYPE;
                goto drop;
            }
            struct tr_ip src, dst;
            struct tr_reasm_out out = {0};
            src.family = TR_AF_INET6;
            dst.family = TR_AF_INET6;
            memcpy(&src.u.v6, ip + 8, 16);
            memcpy(&dst.u.v6, ip + 24, 16);
            int rc = tr_reasm6_input(&e->reasm[worker], if_slot, &src, &dst, id, nh,
                                     ip, 40, frag_off, more, ip + 48,
                                     plen - 8, pkt_now(e, worker), &out);
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
    stats_drop_reason(e, worker, if_slot, why);
    rte_pktmbuf_free(m);
}

static void bridge_ingress(struct tr_engine *e, int worker,
                           struct tr_runtime *rt, int if_slot,
                           const struct tr_iface *iface,
                           struct rte_mbuf *m)
{
    const struct tr_iface *br;
    uint8_t *p = mtod(m);
    uint32_t len = mlen(m);
    uint8_t dstmac[6];
    int out_slot;
    uint64_t now = pkt_now(e, worker);
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
    stats_drop_reason(e, worker, if_slot, TR_DROP_BRIDGE);
    rte_pktmbuf_free(m);
}

static int rt_vlan_lookup(const struct tr_runtime *rt, int parent,
                          uint16_t outer, uint16_t inner)
{
    unsigned h = (unsigned)(((parent * 4096 + outer) * 2654435761u) ^ inner) &
                 (TR_VLAN_MAP_SIZE - 1);
    for (int probe = 0; probe < TR_VLAN_MAP_SIZE; probe++) {
        const struct tr_vlan_map_entry *entry =
            &rt->vlan_map[(h + (unsigned)probe) & (TR_VLAN_MAP_SIZE - 1)];
        if (!entry->used)
            return -1;
        if (entry->parent == parent && entry->outer == outer &&
            entry->inner == inner)
            return entry->child;
    }
    return -1;
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
        stats_drop_reason(e, worker, if_slot, TR_DROP_RX_SHORT);
        rte_pktmbuf_free(m);
        return;
    }
    /* Evaluate the tag once here and pass the result down: l3_ingress needs
     * the same bit and used to recompute it for every packet. */
    bool tagged = pkt_tagged(m);
    if (iface->kind == TR_IF_ETHERNET && tagged) {
        uint8_t *p = mtod(m);
        bool qinq = p[12] == (ETH_TYPE_QINQ >> 8) && p[13] == 0xa8;
        uint16_t outer, inner = 0;
        int child = -1;
        if (qinq) {
            if (mlen(m) < 22 ||
                p[16] != (ETH_TYPE_VLAN >> 8) || p[17] != 0x00)
                goto unknown_vlan;
            outer = (uint16_t)((p[14] << 8 | p[15]) & 0x0fff);
            inner = (uint16_t)((p[18] << 8 | p[19]) & 0x0fff);
            child = rt_vlan_lookup(rt, if_slot, outer, inner);
        } else {
            outer = (uint16_t)((p[14] << 8 | p[15]) & 0x0fff);
            child = rt_vlan_lookup(rt, if_slot, outer, 0);
        }
        if (child >= 0) {
            if (qinq ? pkt_strip_qinq(m) : pkt_strip_vlan(m, NULL)) {
                stats_drop_reason(e, worker, if_slot, TR_DROP_RX_MALFORMED);
                rte_pktmbuf_free(m);
                return;
            }
            tagged = false;
            if_slot = child;
            iface = rt_iface(rt, child);
            if (!iface) {
                stats_drop_reason(e, worker, if_slot, TR_DROP_OTHER);
                rte_pktmbuf_free(m);
                return;
            }
            /* Logical VLAN tap: untagged frame selected by the tags. */
            if (pkt_capture_on(e, worker))
                tr_capture_tap_exact(e->capture, if_slot, TR_CAP_RX, m);
        }
    }
unknown_vlan:
    if (iface->bridge >= 0)
        bridge_ingress(e, worker, rt, if_slot, iface, m);
    else
        l3_ingress(e, worker, rt, if_slot, iface, m, tagged);
}

int tr_engine_input_burst(struct tr_engine *e, int worker, int if_slot,
                          struct rte_mbuf **mbufs, uint16_t n)
{
    struct tr_runtime *rt;

    if (!e || !mbufs)
        return -1;
    if (worker < 0 || worker >= e->workers) {
        for (uint16_t i = 0; i < n; i++)
            rte_pktmbuf_free(mbufs[i]);
        return -1;
    }
    if (n == 0)
        return 0;
    /* Snapshot time and capture state for the whole burst: one clock read and
     * one capture-flag read instead of one of each per packet. */
    e->now_ms[worker] = tr_monotonic_ms();
    e->capture_on[worker] = tr_capture_is_active(e->capture);
    if (e->capture_on[worker]) {
        for (uint16_t i = 0; i < n; i++)
            tr_capture_tap(e->capture, if_slot, TR_CAP_RX, mbufs[i]);
    }
    uint64_t bytes = 0;
    runtime_read_enter(e, worker);
    rt = atomic_load_explicit(&e->rt_fast, memory_order_acquire);
    if (e->rt_cache_gen[worker] != rt->generation) {
        /* A new runtime means new route pointers; drop the cached ones
         * instead of tagging every entry with the generation.  Happens once
         * per configuration change, not per packet. */
        memset(e->rt_cache4[worker], 0, sizeof(e->rt_cache4[worker]));
        memset(e->rt_cache6[worker], 0, sizeof(e->rt_cache6[worker]));
        e->rt_cache_gen[worker] = rt->generation;
    }
    for (uint16_t i = 0; i < n; i++) {
        /* One pass over the burst: the length needed for the RX byte counter
         * is read here instead of in a separate pre-pass. */
        bytes += mlen(mbufs[i]);
        if (i + 1 < n)
            rte_prefetch0(rte_pktmbuf_mtod(mbufs[i + 1], void *));
        engine_input_slot(e, worker, rt, if_slot, mbufs[i]);
    }
    runtime_read_exit(e, worker);
    stats_tx_flush(e, worker);
    stats_rx_bulk(e, worker, if_slot, n, bytes);
    return 0;
}

int tr_engine_input(struct tr_engine *e, int worker, int if_slot,
                    struct rte_mbuf *m)
{
    return tr_engine_input_burst(e, worker, if_slot, &m, 1);
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
                /* Refreshing the lifetime of an unchanged default route does
                 * not alter the FIB, so it must not trigger a runtime rebuild
                 * (which pauses every worker and invalidates the per-worker
                 * caches).  Only real changes are marked dirty. */
                bool changed = !slot->used ||
                               slot->if_slot != ev->if_slot ||
                               !tr_ip_equal(&slot->via, &ev->router);
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
                if (changed)
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
            bool changed = !slot->used ||
                           slot->if_slot != ev->if_slot ||
                           !tr_ip_equal(&slot->prefix.addr, &prefix.addr) ||
                           slot->prefix.plen != prefix.plen;
            slot->used = true;
            slot->if_slot = ev->if_slot;
            slot->prefix = prefix;
            slot->expires_ms =
                ev->valid == 0xffffffffu ? 0
                                         : now + (uint64_t)ev->valid * 1000;
            if (changed)
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
    runtime_pause(e);
    rc = runtime_build(e, &e->rt->cfg, &nr, err, sizeof(err));
    if (rc == 0) {
        old = e->rt;
        e->rt = nr;
        atomic_store_explicit(&e->rt_fast, nr, memory_order_release);
    }
    runtime_resume(e);
    pthread_rwlock_unlock(&e->rt_lock);
    if (rc == 0) {
        runtime_free(old);
        return 0;
    }
    return -1;
}

void tr_engine_housekeeping(struct tr_engine *e, uint64_t now_ms)
{
    bool dirty;
    uint64_t now = now_ms ? now_ms : tr_monotonic_ms();

    tr_capture_poll(e->capture);
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
    egress_frame(e, e->workers, rt, if_slot, m);
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

static int trace_select_path(struct tr_engine *e, struct tr_runtime *rt,
                            const struct tr_ip *target, const char *interface,
                            const struct tr_ip *source, int *egress,
                            struct tr_ip *chosen, struct tr_ip *next_hop,
                            char *err, size_t errlen)
{
    struct tr_iface *iface = NULL;
    struct tr_fib_result res;
    bool route_ok = false;

    *egress = -1;
    *next_hop = *target;
    if (interface && interface[0]) {
        iface = tr_config_find(&rt->cfg, interface);
        if (!iface || (iface->kind != TR_IF_ETHERNET &&
                       iface->kind != TR_IF_VLAN)) {
            snprintf(err, errlen, "unknown/non-L3 interface '%s'", interface);
            return -1;
        }
        *egress = iface->slot;
    }
    if (tr_ip_is_linklocal(target) && *egress >= 0) {
        route_ok = true;
    } else if (!tr_fib_lookup(&rt->fib, target, &res) &&
               res.route->if_slot >= 0) {
        if (*egress < 0)
            *egress = res.route->if_slot;
        if (*egress != res.route->if_slot) {
            snprintf(err, errlen, "target is not routed via %s", interface);
            return -1;
        }
        if (res.route->connected)
            *next_hop = *target;
        else if (res.route->has_via)
            *next_hop = res.route->via;
        route_ok = true;
    } else if (*egress >= 0) {
        route_ok = true;
    }
    if (!route_ok || *egress < 0) {
        snprintf(err, errlen, "no route to target");
        return -1;
    }
    iface = rt_iface(rt, *egress);
    if (!iface || iface->kind == TR_IF_TUNNEL) {
        snprintf(err, errlen, "unsupported egress interface");
        return -1;
    }
    if (source && source->family) {
        if (source->family != target->family ||
            !is_local_if(rt, *egress, source)) {
            snprintf(err, errlen,
                     "source address is not local to the egress interface");
            return -1;
        }
        *chosen = *source;
    } else if (pick_addr(rt, *egress, target->family,
                         tr_ip_is_linklocal(target), chosen)) {
        snprintf(err, errlen, "no source address on %s", iface->name);
        return -1;
    }
    return 0;
}

static int ping_send_packet(struct tr_engine *e, struct tr_runtime *rt,
                            int if_slot, const struct tr_ip *next_hop,
                            const struct tr_ip *source,
                            const struct tr_ip *target, uint16_t id,
                            uint16_t seq, size_t payload_len, uint8_t ttl)
{
    const struct tr_iface *iface = rt_iface(rt, if_slot);
    bool v4 = target->family == TR_AF_INET;
    uint32_t l3len = (v4 ? 20u : 40u);
    uint32_t total = 14 + l3len + 8 + (uint32_t)payload_len;
    struct rte_mbuf *m;
    uint8_t *p, *icmp;

    if (!iface)
        return -1;
    m = pkt_alloc(e, total);
    if (!m)
        return -1;
    p = mtod(m);
    memset(p, 0, 6);
    memcpy(p + 6, iface->mac, 6);
    if (v4) {
        p[12] = ETH_TYPE_IPV4 >> 8;
        p[13] = ETH_TYPE_IPV4 & 0xff;
        build_ip4(p + 14, 20 + 8 + (uint32_t)payload_len, IPPROTO_ICMP,
                  (const uint8_t *)&source->u.v4,
                  (const uint8_t *)&target->u.v4, ttl, id);
        icmp = p + 34;
        icmp[0] = ICMP_ECHO;
    } else {
        p[12] = ETH_TYPE_IPV6 >> 8;
        p[13] = ETH_TYPE_IPV6 & 0xff;
        build_ip6(p + 14, (uint16_t)(8 + payload_len), IPPROTO_ICMPV6,
                  (const uint8_t *)&source->u.v6,
                  (const uint8_t *)&target->u.v6, ttl);
        icmp = p + 54;
        icmp[0] = ICMPV6_ECHO_REQUEST;
    }
    icmp[1] = 0;
    icmp[2] = 0;
    icmp[3] = 0;
    icmp[4] = (uint8_t)(id >> 8);
    icmp[5] = (uint8_t)id;
    icmp[6] = (uint8_t)(seq >> 8);
    icmp[7] = (uint8_t)seq;
    for (size_t i = 0; i < payload_len; i++)
        icmp[8 + i] = (uint8_t)(0x40 + (i & 0x3f));
    uint16_t csum;
    if (v4) {
        csum = tr_checksum16(icmp, 8 + (uint32_t)payload_len, 0);
    } else {
        uint32_t sum = checksum_add_pseudo6(0, (const uint8_t *)&source->u.v6,
                                            (const uint8_t *)&target->u.v6,
                                            IPPROTO_ICMPV6,
                                            8 + (uint32_t)payload_len);
        sum = tr_checksum_add(sum, icmp, 8 + payload_len);
        csum = tr_checksum16_finish(sum);
    }
    icmp[2] = (uint8_t)(csum >> 8);
    icmp[3] = (uint8_t)csum;

    uint8_t mac[6];
    uint8_t state = 0;
    struct tr_neigh_table *t =
        next_hop->family == TR_AF_INET ? &e->neigh4 : &e->neigh6;
    uint64_t now = tr_monotonic_ms();
    if (tr_neigh_get(t, if_slot, next_hop, mac, now, &state)) {
        memcpy(p, mac, 6);
        egress_frame(e, e->workers, rt, if_slot, m);
        return 0;
    }
    if (tr_neigh_queue(t, if_slot, next_hop, m, now)) {
        rte_pktmbuf_free(m);
        return -1;
    }
    if (tr_neigh_request_allowed(t, if_slot, next_hop, now, 1000))
        send_neighbor_request(e, e->workers, rt, if_slot, next_hop,
                              next_hop->family);
    return 0;
}

int tr_engine_ping(struct tr_engine *e, const struct tr_ip *target,
                   const char *interface, const struct tr_ip *source,
                   int count, int timeout_ms, size_t payload_len, char **out)
{
    char *buf = NULL;
    size_t blen = 0;
    FILE *f;
    struct tr_ip tgt;
    struct tr_ip src = {0};
    int received = 0;
    int sent = 0;
    uint16_t id;
    char tbuf[96];

    if (!e || !target || !out || count < 1 || count > TR_PING_MAX ||
        payload_len < 8 || payload_len > 1400 || timeout_ms < 100)
        return -1;
    *out = NULL;
    tr_ip_ntop(target, tbuf, sizeof(tbuf));
    pthread_mutex_lock(&e->ping.lock);
    if (e->ping.active ||
        atomic_load_explicit(&e->trace.active, memory_order_relaxed)) {
        pthread_mutex_unlock(&e->ping.lock);
        if (asprintf(out, "ping: another probe is already running\n") < 0)
            *out = NULL;
        return -1;
    }
    id = ++e->ping_id;
    if (id == 0)
        id = ++e->ping_id;
    tgt = *target;
    e->ping.id = id;
    e->ping.target = tgt;
    e->ping.source = src;
    e->ping.replied = false;
    e->ping.seq = 0;
    atomic_store_explicit(&e->ping.active, true, memory_order_release);
    pthread_mutex_unlock(&e->ping.lock);

    f = open_memstream(&buf, &blen);
    if (!f) {
        atomic_store_explicit(&e->ping.active, false, memory_order_release);
        return -1;
    }
    fprintf(f, "PING %s: %zu data bytes\n", tbuf, payload_len);

    for (int i = 0; i < count; i++) {
        struct tr_runtime *rt;
        struct tr_iface *iface = NULL;
        struct tr_ip next_hop = tgt;
        struct tr_ip chosen = {0};
        struct tr_fib_result res;
        int egress = -1;
        bool route_ok = false;
        uint64_t send_ms;

        pthread_rwlock_rdlock(&e->rt_lock);
        rt = e->rt;
        if (interface && interface[0]) {
            iface = tr_config_find(&rt->cfg, interface);
            if (!iface || (iface->kind != TR_IF_ETHERNET &&
                           iface->kind != TR_IF_VLAN)) {
                fprintf(f, "ping: unknown/non-L3 interface '%s'\n", interface);
                pthread_rwlock_unlock(&e->rt_lock);
                break;
            }
            egress = iface->slot;
        }
        if (tr_ip_is_linklocal(&tgt) && egress >= 0) {
            route_ok = true;
        } else if (!tr_fib_lookup(&rt->fib, &tgt, &res) &&
                   res.route->if_slot >= 0) {
            if (egress < 0)
                egress = res.route->if_slot;
            if (egress != res.route->if_slot) {
                fprintf(f, "ping: target is not routed via %s\n", interface);
                pthread_rwlock_unlock(&e->rt_lock);
                break;
            }
            if (res.route->connected)
                next_hop = tgt;
            else if (res.route->has_via)
                next_hop = res.route->via;
            route_ok = true;
        } else if (egress >= 0) {
            /* Point-to-point / link-local use of an explicit interface. */
            route_ok = true;
        }
        if (!route_ok || egress < 0) {
            fprintf(f, "ping: no route to %s\n", tbuf);
            pthread_rwlock_unlock(&e->rt_lock);
            break;
        }
        iface = rt_iface(rt, egress);
        if (!iface || iface->kind == TR_IF_TUNNEL) {
            fprintf(f, "ping: unsupported egress interface\n");
            pthread_rwlock_unlock(&e->rt_lock);
            break;
        }
        if (source && source->family) {
            if (source->family != tgt.family ||
                !is_local_if(rt, egress, source)) {
                fprintf(f, "ping: source address is not local to the "
                           "egress interface\n");
                pthread_rwlock_unlock(&e->rt_lock);
                break;
            }
            chosen = *source;
        } else if (pick_addr(rt, egress, tgt.family,
                             tr_ip_is_linklocal(&tgt), &chosen)) {
            fprintf(f, "ping: no source address on %s\n", iface->name);
            pthread_rwlock_unlock(&e->rt_lock);
            break;
        }

        pthread_mutex_lock(&e->ping.lock);
        e->ping.seq = (uint16_t)i;
        e->ping.replied = false;
        e->ping.source = chosen;
        e->ping.sent_ns = tr_monotonic_ns();
        send_ms = tr_monotonic_ms();
        pthread_mutex_unlock(&e->ping.lock);

        int rc = ping_send_packet(e, rt, egress, &next_hop, &chosen, &tgt,
                                  id, (uint16_t)i, payload_len, 64);
        pthread_rwlock_unlock(&e->rt_lock);
        if (rc) {
            fprintf(f, "ping: send failed\n");
            break;
        }
        sent++;

        bool replied = false;
        uint64_t rtt_ns = 0;
        uint8_t ttl = 0;
        uint64_t deadline = send_ms + (uint64_t)timeout_ms;
        for (;;) {
            pthread_mutex_lock(&e->ping.lock);
            replied = e->ping.replied;
            rtt_ns = e->ping.rtt_ns;
            ttl = e->ping.ttl;
            pthread_mutex_unlock(&e->ping.lock);
            if (replied || tr_monotonic_ms() >= deadline)
                break;
            usleep(10000);
        }
        if (replied) {
            char abuf[96];
            tr_ip_ntop(&tgt, abuf, sizeof(abuf));
            fprintf(f, "%zu bytes from %s: icmp_seq=%d ttl=%u time=%.3f ms\n",
                    payload_len + 8, abuf, i, ttl,
                    (double)rtt_ns / 1e6);
            received++;
        } else {
            fprintf(f, "Request timeout for icmp_seq=%d\n", i);
        }
        if (i + 1 < count) {
            uint64_t elapsed = tr_monotonic_ms() - send_ms;
            if (elapsed < 1000)
                usleep((useconds_t)((1000 - elapsed) * 1000));
        }
    }

    fprintf(f, "--- %s ping statistics ---\n", tbuf);
    fprintf(f, "%d packets transmitted, %d received, %d%% packet loss\n",
            sent, received, sent ? (sent - received) * 100 / sent : 100);
    fclose(f);
    pthread_mutex_lock(&e->ping.lock);
    atomic_store_explicit(&e->ping.active, false, memory_order_release);
    pthread_mutex_unlock(&e->ping.lock);
    *out = buf;
    return 0;
}

int tr_engine_traceroute(struct tr_engine *e, const struct tr_ip *target,
                         const char *interface, const struct tr_ip *source,
                         int max_hops, int probes, int timeout_ms,
                         size_t payload_len, char **out)
{
    char *buf = NULL;
    size_t blen = 0;
    FILE *f;
    struct tr_ip tgt;
    char tbuf[96];
    uint16_t id;

    if (!e || !target || !out || max_hops < 1 ||
        max_hops > TR_TRACE_MAX_HOPS || probes < 1 ||
        probes > TR_TRACE_MAX_PROBES || timeout_ms < 100 ||
        payload_len < 8 || payload_len > 1400)
        return -1;
    *out = NULL;
    tr_ip_ntop(target, tbuf, sizeof(tbuf));
    pthread_mutex_lock(&e->trace.lock);
    if (e->trace.active || atomic_load_explicit(&e->ping.active,
                                                memory_order_relaxed)) {
        pthread_mutex_unlock(&e->trace.lock);
        if (asprintf(out, "traceroute: another probe is already running\n") < 0)
            *out = NULL;
        return -1;
    }
    id = ++e->trace_id;
    if (id == 0)
        id = ++e->trace_id;
    tgt = *target;
    e->trace.id = id;
    e->trace.target = tgt;
    e->trace.replied = false;
    e->trace.reply_kind = 0;
    atomic_store_explicit(&e->trace.active, true, memory_order_release);
    pthread_mutex_unlock(&e->trace.lock);

    f = open_memstream(&buf, &blen);
    if (!f) {
        atomic_store_explicit(&e->trace.active, false, memory_order_release);
        return -1;
    }
    fprintf(f, "traceroute to %s, %d hops max, %zu byte packets\n", tbuf,
            max_hops, payload_len);
    uint16_t seq = 0;
    bool reached = false;

    for (int ttl = 1; ttl <= max_hops && !reached; ttl++) {
        struct tr_ip responder = {0};
        bool got = false;
        bool hop_dest = false;
        double times[TR_TRACE_MAX_PROBES];
        bool got_probe[TR_TRACE_MAX_PROBES];
        memset(times, 0, sizeof(times));
        memset(got_probe, 0, sizeof(got_probe));

        for (int p = 0; p < probes; p++) {
            struct tr_runtime *rt;
            struct tr_ip chosen = {0}, next_hop;
            int egress = -1;
            char err[128];
            uint64_t sent_ns, deadline;
            int kind = 0;
            uint64_t rtt_ns = 0;

            pthread_rwlock_rdlock(&e->rt_lock);
            rt = e->rt;
            if (trace_select_path(e, rt, &tgt, interface, source, &egress,
                                  &chosen, &next_hop, err, sizeof(err))) {
                fprintf(f, "traceroute: %s\n", err);
                pthread_rwlock_unlock(&e->rt_lock);
                goto done;
            }
            pthread_mutex_lock(&e->trace.lock);
            e->trace.seq = seq;
            e->trace.replied = false;
            e->trace.reply_kind = 0;
            e->trace.source = chosen;
            e->trace.sent_ns = tr_monotonic_ns();
            sent_ns = e->trace.sent_ns;
            pthread_mutex_unlock(&e->trace.lock);
            int rc = ping_send_packet(e, rt, egress, &next_hop, &chosen,
                                      &tgt, id, seq, payload_len,
                                      (uint8_t)ttl);
            pthread_rwlock_unlock(&e->rt_lock);
            seq++;
            if (rc) {
                fprintf(f, "traceroute: send failed\n");
                goto done;
            }
            deadline = tr_monotonic_ms() + (uint64_t)timeout_ms;
            bool replied = false;
            for (;;) {
                pthread_mutex_lock(&e->trace.lock);
                replied = e->trace.replied;
                kind = e->trace.reply_kind;
                responder = e->trace.responder;
                rtt_ns = e->trace.rtt_ns;
                pthread_mutex_unlock(&e->trace.lock);
                if (replied || tr_monotonic_ms() >= deadline)
                    break;
                usleep(10000);
            }
            (void)sent_ns;
            if (replied) {
                got = true;
                got_probe[p] = true;
                times[p] = (double)rtt_ns / 1e6;
                if (kind == 2) {
                    hop_dest = true;
                    reached = true;
                } else {
                    responder = e->trace.responder;
                }
            }
            if (hop_dest)
                break;
        }

        fprintf(f, "%2d", ttl);
        if (!got) {
            for (int p = 0; p < probes; p++)
                fprintf(f, "  *");
            fprintf(f, "\n");
        } else {
            char rbuf[96];
            tr_ip_ntop(&responder, rbuf, sizeof(rbuf));
            fprintf(f, "  %-40s", rbuf);
            for (int p = 0; p < probes; p++) {
                if (got_probe[p])
                    fprintf(f, "  %.3f ms", times[p]);
                else
                    fprintf(f, "  *");
            }
            fprintf(f, "\n");
        }
        if (hop_dest)
            fprintf(f, "Trace complete.\n");
        if (!hop_dest && ttl == max_hops)
            fprintf(f, "Trace stopped at max hops.\n");
    }
done:
    fclose(f);
    pthread_mutex_lock(&e->trace.lock);
    atomic_store_explicit(&e->trace.active, false, memory_order_release);
    pthread_mutex_unlock(&e->trace.lock);
    *out = buf;
    return 0;
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
        uint64_t why[TR_DROP_COUNT] = {0};
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
            for (int r = 0; r < TR_DROP_COUNT; r++)
                why[r] += atomic_load_explicit(&s->drop_reason[r],
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
        /* Drop breakdown: only the reasons that actually fired.  This is what
         * separates "the underlay is full of packets we do not route" from
         * "our own frames are too big for the egress MTU". */
        if (drop) {
            bool first = true;

            for (int r = 0; r < TR_DROP_COUNT; r++) {
                if (!why[r])
                    continue;
                fprintf(f, first ? "  drops:" : ",");
                fprintf(f, " %s %llu", tr_drop_reason_name(r),
                        (unsigned long long)why[r]);
                first = false;
            }
            if (!first)
                fprintf(f, "\n");
        }
    }
    pthread_rwlock_unlock(&e->rt_lock);
    fclose(f);
    *out = buf;
    return 0;
}

static int resolve_show_route(const struct tr_fib *fib, const struct tr_ip *addr,
                              int depth, int *if_slot, struct tr_ip *next_hop)
{
    struct tr_fib_result res;

    if (depth > 8 || tr_fib_lookup(fib, addr, &res))
        return -1;
    if (res.route->connected) {
        *if_slot = res.route->if_slot;
        *next_hop = *addr;
        return 0;
    }
    if (!res.route->has_via)
        return -1;
    if (depth == 0)
        *next_hop = res.route->via;
    return resolve_show_route(fib, &res.route->via, depth + 1, if_slot,
                              next_hop);
}

static int show_route_table(struct tr_engine *e, char **out)
{
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

int tr_engine_show(struct tr_engine *e, int argc, char **argv, char **out)
{
    if (!e || !argc || !argv || !out)
        return -1;
    if (strcmp(argv[0], "statistics") == 0)
        return tr_engine_stats_text(e, out);
    if (strcmp(argv[0], "route") == 0) {
        if (argc < 2 || strcmp(argv[1], "all") == 0)
            return show_route_table(e, out);
        struct tr_ip dst;
        const char *arg = argv[1];
        if (strchr(arg, '/')) {
            struct tr_prefix pfx;
            if (tr_prefix_parse_host(arg, &pfx))
                return -1;
            dst = pfx.addr;
        } else if (tr_ip_parse(arg, &dst)) {
            return -1;
        }
        char *buf = NULL;
        size_t n = 0;
        FILE *f = open_memstream(&buf, &n);
        if (!f)
            return -1;
        pthread_rwlock_rdlock(&e->rt_lock);
        struct tr_fib_result res;
        char dstbuf[96], pfxbuf[96], viabuf[96], nhbuf[96];
        tr_ip_ntop(&dst, dstbuf, sizeof(dstbuf));
        if (tr_fib_lookup(&e->rt->fib, &dst, &res)) {
            fprintf(f, "Destination: %s\nNo matching route\n", dstbuf);
        } else {
            const struct tr_fib_route *r = res.route;
            const struct tr_iface *iface = rt_iface(e->rt, r->if_slot);
            tr_prefix_ntop(&r->prefix, pfxbuf, sizeof(pfxbuf));
            const char *kind = r->connected ? "connected"
                               : r->route_id <= -10000 ? "dynamic (RA/SLAAC)"
                                                      : "static";
            fprintf(f, "Destination: %s\nMatched prefix: %s\n"
                       "Route type: %s\n",
                    dstbuf, pfxbuf, kind);
            if (r->has_via) {
                tr_ip_ntop(&r->via, viabuf, sizeof(viabuf));
                fprintf(f, "Via: %s\n", viabuf);
            }
            int egress = r->if_slot;
            struct tr_ip nh;
            bool have_nh = false;
            if (resolve_show_route(&e->rt->fib, &dst, 0, &egress, &nh) == 0) {
                tr_ip_ntop(&nh, nhbuf, sizeof(nhbuf));
                have_nh = true;
                iface = rt_iface(e->rt, egress);
            }
            if (iface)
                fprintf(f, "Egress: %s (ifindex %d)\n", iface->name,
                        iface->slot);
            else
                fprintf(f, "Egress: unresolved\n");
            if (have_nh) {
                if (r->connected || (!r->has_via && egress == r->if_slot))
                    fprintf(f, "Next-hop: directly connected\n");
                else
                    fprintf(f, "Next-hop: %s\n", nhbuf);
            } else if (r->has_via) {
                fprintf(f, "Next-hop: unresolved\n");
            } else {
                fprintf(f, "Next-hop: directly connected\n");
            }
        }
        pthread_rwlock_unlock(&e->rt_lock);
        fclose(f);
        *out = buf;
        return 0;
    }
    if (strcmp(argv[0], "routes") == 0)
        return show_route_table(e, out);
    if (strcmp(argv[0], "neighbors") == 0) {
        char *n4 = NULL, *n6 = NULL, *mac = NULL, *buf = NULL;
        size_t n = 0;
        FILE *f;
        uint64_t now = tr_monotonic_ms();
        pthread_rwlock_rdlock(&e->rt_lock);
        if (tr_neigh_show(&e->neigh4, &e->rt->cfg, now, &n4) ||
            tr_neigh_show(&e->neigh6, &e->rt->cfg, now, &n6) ||
            tr_bridge_show(&e->bridges, &e->rt->cfg, now, &mac)) {
            pthread_rwlock_unlock(&e->rt_lock);
            free(n4);
            free(n6);
            free(mac);
            return -1;
        }
        f = open_memstream(&buf, &n);
        if (!f) {
            pthread_rwlock_unlock(&e->rt_lock);
            free(n4);
            free(n6);
            free(mac);
            return -1;
        }
        fprintf(f, "IPv4 neighbors:\n%s\nIPv6 neighbors:\n%s\n"
                   "MAC table (bridge forwarding):\n%s%s",
                n4, n6, mac && mac[0] ? mac : "", mac && mac[0] ? "" : "(empty)\n");
        free(n4);
        free(n6);
        free(mac);
        fclose(f);
        pthread_rwlock_unlock(&e->rt_lock);
        *out = buf;
        return 0;
    }
    if (strcmp(argv[0], "bridge") == 0) {
        int rc;
        pthread_rwlock_rdlock(&e->rt_lock);
        rc = tr_bridge_show(&e->bridges, &e->rt->cfg, tr_monotonic_ms(), out);
        pthread_rwlock_unlock(&e->rt_lock);
        return rc;
    }
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
        bool printed_header = false;
        for (int i = 0; i < e->rt->nlocals; i++) {
            const struct tr_local_addr *l = &e->rt->locals[i];
            if (!l->linklocal && !l->dynamic)
                continue;
            const struct tr_iface *iface = rt_iface(e->rt, l->if_slot);
            if (!iface)
                continue;
            if (argc >= 2 && strcmp(argv[1], iface->name) != 0)
                continue;
            if (!printed_header) {
                fprintf(xf,
                        "\nRuntime IPv6 addresses (link-local / autoconf):\n");
                printed_header = true;
            }
            char a[96];
            tr_ip_ntop(&l->ip, a, sizeof(a));
            fprintf(xf, "  %-16s %s/64 %s\n", iface->name, a,
                    l->dynamic ? "autoconf" : "link-local");
        }
        pthread_rwlock_unlock(&e->rt_lock);
        fclose(xf);
        char note[160] = "";
        if (base && strstr(base, "No interfaces configured."))
            snprintf(note, sizeof(note),
                     "DPDK ports detected: %d. Check the startup log "
                     "(auto-port/warning lines).\n",
                     e->n_ports);
        if (asprintf(out, "%s%s%s", base ? base : "", extra ? extra : "",
                     note) < 0) {
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

int tr_engine_capture_start(struct tr_engine *e, const char *ifname,
                            const char *file, unsigned direction,
                            uint32_t snaplen, uint64_t count,
                            const char *filter, char *err, size_t errlen)
{
    int slot = -1;
    char name[TR_CAP_IFNAME_LEN];
    const struct tr_iface *iface = NULL;

    if (!e || !e->capture) {
        snprintf(err, errlen, "capture is unavailable");
        return -1;
    }
    snprintf(name, sizeof(name), "%s",
             ifname && *ifname ? ifname : "any");
    if (strcmp(name, "any") != 0) {
        pthread_rwlock_rdlock(&e->rt_lock);
        iface = tr_config_find_const(&e->rt->cfg, name);
        if (!iface) {
            pthread_rwlock_unlock(&e->rt_lock);
            snprintf(err, errlen, "unknown interface '%s'", name);
            return -1;
        }
        if (iface->kind == TR_IF_BRIDGE) {
            pthread_rwlock_unlock(&e->rt_lock);
            snprintf(err, errlen,
                     "capture a bridge member, not the bridge itself");
            return -1;
        }
        slot = iface->slot;
        pthread_rwlock_unlock(&e->rt_lock);
    }
    return tr_capture_start(e->capture, slot, name, file, direction, snaplen,
                            count, filter, err, errlen);
}

int tr_engine_capture_stop(struct tr_engine *e, char *err, size_t errlen)
{
    if (!e || !e->capture) {
        snprintf(err, errlen, "capture is unavailable");
        return -1;
    }
    return tr_capture_stop(e->capture, err, errlen);
}

int tr_engine_capture_status(struct tr_engine *e, char **out)
{
    if (!e || !e->capture)
        return -1;
    return tr_capture_status_text(e->capture, out);
}
