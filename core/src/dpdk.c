#include "dpdk.h"

#include "config.h"
#include "util.h"

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TR_PORT_MAX 256
#define TR_IFACE_MAX TR_MAX_IFACES
#define TR_RX_BURST 64
#define TR_TX_BURST 32
#define TR_RX_DESC 512
#define TR_TX_DESC 512
#define TR_PORT_MTU_MAX 9600

struct tr_tx_batch {
    uint16_t port;
    uint16_t q;
    uint16_t n;
    struct rte_mbuf *m[TR_TX_BURST];
};

struct tr_dpdk {
    struct tr_engine *engine;
    int workers;
    int nports;
    struct rte_mempool *mp;
    _Atomic int port_slot[TR_PORT_MAX];
    _Atomic int slot_port[TR_IFACE_MAX];
    int port_nq[TR_PORT_MAX];
    _Atomic int active_ports[TR_PORT_MAX];
    _Atomic int nactive;
    bool port_tx_ipv4_cksum[TR_PORT_MAX];
    _Atomic bool stop;
    _Atomic bool workers_running;
    struct tr_tx_batch tx[TR_MAX_WORKERS][TR_PORT_MAX];
    bool started;
    int lcores[TR_MAX_WORKERS];
};

static void tx_flush_batch(struct tr_dpdk *d, struct tr_tx_batch *b)
{
    if (b->n == 0)
        return;
    uint16_t sent = rte_eth_tx_burst(b->port, b->q, b->m, b->n);
    for (uint16_t i = sent; i < b->n; i++)
        rte_pktmbuf_free(b->m[i]);
    b->n = 0;
}

static void tx_flush_all(struct tr_dpdk *d, int worker)
{
    if (worker < 0 || worker >= d->workers)
        return;
    for (int port = 0; port < d->nports; port++)
        tx_flush_batch(d, &d->tx[worker][port]);
}

static void tx_burst(void *arg, int worker, int if_slot, struct rte_mbuf *m)
{
    struct tr_dpdk *d = arg;
    int port;
    int q;

    if (!m)
        return;
    if (if_slot < 0 || if_slot >= TR_IFACE_MAX) {
        rte_pktmbuf_free(m);
        return;
    }
    port = atomic_load_explicit(&d->slot_port[if_slot], memory_order_relaxed);
    if (port < 0 || port >= d->nports) {
        rte_pktmbuf_free(m);
        return;
    }
    q = worker % (d->port_nq[port] > 0 ? d->port_nq[port] : 1);
    if (!atomic_load_explicit(&d->workers_running, memory_order_relaxed)) {
        if (rte_eth_tx_burst((uint16_t)port, (uint16_t)q, &m, 1) != 1)
            rte_pktmbuf_free(m);
        return;
    }
    if (worker < 0 || worker >= d->workers) {
        rte_pktmbuf_free(m);
        return;
    }
    struct tr_tx_batch *b = &d->tx[worker][port];
    if (b->n > 0 && (b->port != (uint16_t)port || b->q != (uint16_t)q))
        tx_flush_batch(d, b);
    b->port = (uint16_t)port;
    b->q = (uint16_t)q;
    b->m[b->n++] = m;
    if (b->n == TR_TX_BURST)
        tx_flush_batch(d, b);
}

int tr_dpdk_refresh(struct tr_dpdk *d)
{
    struct tr_config cfg;

    if (tr_engine_config_copy(d->engine, &cfg))
        return -1;
    for (int i = 0; i < TR_PORT_MAX; i++)
        atomic_store_explicit(&d->port_slot[i], -1, memory_order_relaxed);
    for (int i = 0; i < TR_IFACE_MAX; i++)
        atomic_store_explicit(&d->slot_port[i], -1, memory_order_relaxed);
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        const struct tr_iface *iface = &cfg.ifaces[i];
        if (!iface->present)
            continue;
        int port = -1;
        if (iface->kind == TR_IF_ETHERNET) {
            port = iface->port_id;
        } else if (iface->kind == TR_IF_VLAN) {
            const struct tr_iface *p =
                tr_config_find_slot_const(&cfg, iface->parent);
            if (p && p->kind == TR_IF_ETHERNET)
                port = p->port_id;
        }
        if (port >= 0 && port < d->nports) {
            atomic_store_explicit(&d->slot_port[i], port,
                                  memory_order_relaxed);
            if (iface->kind == TR_IF_ETHERNET) {
                atomic_store_explicit(&d->port_slot[port], i,
                                      memory_order_release);
            }
        }
    }
    int na = 0;
    for (int port = 0; port < d->nports; port++) {
        if (atomic_load_explicit(&d->port_slot[port], memory_order_acquire) >= 0 &&
            d->port_nq[port] > 0)
            atomic_store_explicit(&d->active_ports[na++], port,
                                  memory_order_relaxed);
    }
    atomic_store_explicit(&d->nactive, na, memory_order_release);
    return 0;
}

static int configure_port(struct tr_dpdk *d, uint16_t port, uint32_t mtu,
                          char *err, size_t errlen)
{
    struct rte_eth_dev_info info;
    struct rte_eth_conf conf;
    struct rte_eth_rxconf rxq;
    struct rte_eth_txconf txq;
    uint16_t nq;
    uint16_t rx_desc = TR_RX_DESC, tx_desc = TR_TX_DESC;
    int socket = rte_socket_id();
    int ret;

    if (rte_eth_dev_info_get(port, &info) != 0) {
        snprintf(err, errlen, "port %u: cannot get device info", port);
        return -1;
    }
    if (!rte_eth_dev_is_valid_port(port)) {
        snprintf(err, errlen, "port %u is not valid", port);
        return -1;
    }
    nq = (uint16_t)TR_MIN(d->workers, 16);
    if (info.max_rx_queues < nq)
        nq = info.max_rx_queues;
    if (info.max_tx_queues < nq)
        nq = info.max_tx_queues;
    if (nq == 0) {
        snprintf(err, errlen, "port %u has no queues", port);
        return -1;
    }
    d->port_nq[port] = nq;

    memset(&conf, 0, sizeof(conf));
    if (info.max_mtu == 0)
        mtu = 1500;
    else if (mtu > info.max_mtu)
        mtu = info.max_mtu;
    if (mtu < info.min_mtu)
        mtu = info.min_mtu;
    conf.rxmode.mtu = mtu;
    conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
    uint64_t wanted = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP |
                      RTE_ETH_RSS_IPV6;
    uint64_t rss_hf = wanted & info.flow_type_rss_offloads;
    if (nq > 1 && rss_hf != 0) {
        conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
        conf.rx_adv_conf.rss_conf.rss_hf = rss_hf;
        conf.rx_adv_conf.rss_conf.rss_key = NULL;
    } else {
        /* virtio-net and some virtual PMDs advertise multiple queues but no
         * RSS offloads.  Requesting RSS then fails with EINVAL.  Without
         * RSS every packet lands on queue 0, so use a single RX queue. */
        conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
        conf.rx_adv_conf.rss_conf.rss_hf = 0;
        nq = 1;
        d->port_nq[port] = nq;
        fprintf(stderr,
                "port %u: RSS unsupported by PMD; using 1 RX queue\n", port);
    }
    if (info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_CHECKSUM)
        conf.rxmode.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM;
    else
        conf.rxmode.offloads = 0;
    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
        conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
        d->port_tx_ipv4_cksum[port] = true;
    } else {
        conf.txmode.offloads = 0;
        d->port_tx_ipv4_cksum[port] = false;
    }

    ret = rte_eth_dev_configure(port, nq, nq, &conf);
    if (ret != 0) {
        /* Some PMDs advertise jumbo support but reject an MTU at configure
         * time, and some accept multiple queues but not RSS.  Retry with a
         * conservative configuration before failing. */
        conf.rxmode.mtu = 1500;
        conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
        conf.rx_adv_conf.rss_conf.rss_hf = 0;
        conf.rxmode.offloads = 0;
        conf.txmode.offloads = 0;
        d->port_tx_ipv4_cksum[port] = false;
        ret = rte_eth_dev_configure(port, nq, nq, &conf);
        if (ret != 0 && nq > 1) {
            nq = 1;
            d->port_nq[port] = 1;
            fprintf(stderr,
                    "port %u: multi-queue configure failed; using 1 queue\n",
                    port);
            ret = rte_eth_dev_configure(port, nq, nq, &conf);
        }
        if (ret != 0) {
            snprintf(err, errlen, "port %u: configure failed: %s", port,
                     rte_strerror(-ret));
            return -1;
        }
    }
    if (rte_eth_dev_adjust_nb_rx_tx_desc(port, &rx_desc, &tx_desc) != 0) {
        rx_desc = TR_RX_DESC;
        tx_desc = TR_TX_DESC;
    }
    memset(&rxq, 0, sizeof(rxq));
    rxq = info.default_rxconf;
    rxq.offloads = conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_CHECKSUM;
    for (uint16_t q = 0; q < nq; q++) {
        if (rte_eth_rx_queue_setup(port, q, rx_desc,
                                   (unsigned int)socket, &rxq, d->mp) != 0) {
            snprintf(err, errlen, "port %u: RX queue %u setup failed", port,
                     q);
            return -1;
        }
    }
    memset(&txq, 0, sizeof(txq));
    txq = info.default_txconf;
    txq.offloads = 0;
    for (uint16_t q = 0; q < nq; q++) {
        if (rte_eth_tx_queue_setup(port, q, tx_desc,
                                   (unsigned int)socket, &txq) != 0) {
            snprintf(err, errlen, "port %u: TX queue %u setup failed", port,
                     q);
            return -1;
        }
    }
    if (rte_eth_dev_start(port) != 0) {
        snprintf(err, errlen, "port %u: start failed", port);
        return -1;
    }
    rte_eth_promiscuous_enable(port);
    rte_eth_allmulticast_enable(port);
    return 0;
}

struct tr_dpdk *tr_dpdk_create(struct tr_engine *engine,
                               const struct tr_dpdk_params *params, char *err,
                               size_t errlen)
{
    struct tr_dpdk *d;
    struct tr_config cfg;

    if (!engine || !params || !params->mp) {
        snprintf(err, errlen, "invalid DPDK parameters");
        return NULL;
    }
    d = calloc(1, sizeof(*d));
    if (!d) {
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    d->engine = engine;
    d->workers = params->workers;
    d->mp = params->mp;
    d->nports = (int)rte_eth_dev_count_avail();
    if (d->nports > TR_PORT_MAX)
        d->nports = TR_PORT_MAX;
    atomic_store(&d->stop, false);
    atomic_store(&d->workers_running, false);
    for (int i = 0; i < TR_PORT_MAX; i++)
        atomic_store(&d->port_slot[i], -1);
    for (int i = 0; i < TR_IFACE_MAX; i++)
        atomic_store(&d->slot_port[i], -1);
    if (tr_engine_config_copy(engine, &cfg))
        snprintf(err, errlen, "no configuration");
    tr_engine_set_tx(engine, tx_burst, d);
    return d;
}

int tr_dpdk_start(struct tr_dpdk *d, char *err, size_t errlen)
{
    uint32_t mtu;

    /* Bring up every DPDK port, including ports that are currently not
     * bound to a logical interface.  This permits `set interfaces ethernet
     * <name> port <id>` on a running router without restarting the PMD. */
    bool all_tx_ipv4_cksum = d->nports > 0;
    for (int port = 0; port < d->nports; port++) {
        mtu = TR_PORT_MTU_MAX;
        if (configure_port(d, (uint16_t)port, mtu, err, errlen))
            return -1;
        if (!d->port_tx_ipv4_cksum[port])
            all_tx_ipv4_cksum = false;
    }
    tr_engine_set_tx_ipv4_cksum(d->engine, all_tx_ipv4_cksum);
    tr_dpdk_refresh(d);
    if (d->workers > 0) {
        int n = 0;
        unsigned int lcore;
        RTE_LCORE_FOREACH_WORKER(lcore) {
            if (n >= d->workers)
                break;
            d->lcores[n++] = (int)lcore;
        }
        if (n < d->workers) {
            snprintf(err, errlen,
                     "need %d worker lcores but only %d are available; pass "
                     "e.g. '-l 0-%d' before '--'",
                     d->workers, n, d->workers);
            return -1;
        }
    }
    d->started = true;
    return 0;
}

struct worker_arg {
    struct tr_dpdk *d;
    int worker;
};

static int worker_main(void *arg)
{
    struct worker_arg *wa = arg;
    struct tr_dpdk *d = wa->d;
    int worker = wa->worker;
    struct rte_mbuf *bufs[TR_RX_BURST];
    unsigned idle_loops = 0;

    while (!atomic_load_explicit(&d->stop, memory_order_relaxed)) {
        bool did_work = false;
        int nactive = atomic_load_explicit(&d->nactive, memory_order_acquire);
        for (int ai = 0; ai < nactive; ai++) {
            int port = atomic_load_explicit(&d->active_ports[ai],
                                            memory_order_relaxed);
            int if_slot = atomic_load_explicit(&d->port_slot[port],
                                               memory_order_acquire);
            int nq = d->port_nq[port];
            if (if_slot < 0 || nq <= 0 || worker >= nq)
                continue;
            uint16_t n = rte_eth_rx_burst((uint16_t)port, (uint16_t)worker,
                                          bufs, TR_RX_BURST);
            if (!n)
                continue;
            did_work = true;
            idle_loops = 0;
            tr_engine_input_burst(d->engine, worker, if_slot, bufs, n);
            tx_flush_all(d, worker);
        }
        if (!did_work) {
            tx_flush_all(d, worker);
            if (idle_loops++ < 64)
                rte_pause();
            else
                rte_delay_us_block(20);
        }
    }
    tx_flush_all(d, worker);
    return 0;
}

int tr_engine_start_workers(struct tr_engine *e); /* not used */

int tr_dpdk_launch_workers(struct tr_dpdk *d)
{
    static struct worker_arg args[TR_MAX_WORKERS];
    int rc = 0;

    atomic_store_explicit(&d->workers_running, true, memory_order_release);
    for (int i = 0; i < d->workers; i++) {
        args[i].d = d;
        args[i].worker = i;
        if (rte_eal_remote_launch(worker_main, &args[i],
                                  (unsigned)d->lcores[i]) != 0) {
            rc = -1;
            break;
        }
    }
    if (rc)
        atomic_store_explicit(&d->workers_running, false,
                              memory_order_release);
    return rc;
}

void tr_dpdk_stop(struct tr_dpdk *d)
{
    if (!d || !d->started)
        return;
    atomic_store(&d->stop, true);
    unsigned int lcore;
    RTE_LCORE_FOREACH_WORKER(lcore) {
        if (rte_eal_get_lcore_state(lcore) == WAIT)
            continue;
        rte_eal_wait_lcore(lcore);
    }
    atomic_store_explicit(&d->workers_running, false, memory_order_release);
    for (int port = 0; port < d->nports; port++)
        rte_eth_dev_stop((uint16_t)port);
    d->started = false;
}

void tr_dpdk_destroy(struct tr_dpdk *d)
{
    free(d);
}

int tr_dpdk_port_count(struct tr_dpdk *d)
{
    return d ? d->nports : 0;
}

int tr_dpdk_worker_count(struct tr_dpdk *d)
{
    return d ? d->workers : 0;
}

int tr_dpdk_status_text(struct tr_dpdk *d, char **out)
{
    char *buf = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&buf, &n);

    if (!f)
        return -1;
    fprintf(f, "workers %d, DPDK ports %d\n", d->workers, d->nports);
    for (int p = 0; p < d->nports; p++) {
        struct rte_eth_stats st;
        int slot = atomic_load_explicit(&d->port_slot[p],
                                        memory_order_relaxed);
        if (rte_eth_stats_get((uint16_t)p, &st) == 0)
            fprintf(f,
                    "port %d if%d: rx %llu tx %llu imissed %llu ierrors "
                    "%llu oerrors %llu\n",
                    p, slot, (unsigned long long)st.ipackets,
                    (unsigned long long)st.opackets,
                    (unsigned long long)st.imissed,
                    (unsigned long long)st.ierrors,
                    (unsigned long long)st.oerrors);
    }
    fclose(f);
    *out = buf;
    return 0;
}
