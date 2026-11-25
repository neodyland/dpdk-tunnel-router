#ifndef TR_ENGINE_H
#define TR_ENGINE_H

#include "config.h"

#include <rte_mbuf.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#define TR_MAX_WORKERS 32

struct tr_engine;

struct tr_if_stats {
    _Atomic uint64_t rx_pkts;
    _Atomic uint64_t rx_bytes;
    _Atomic uint64_t tx_pkts;
    _Atomic uint64_t tx_bytes;
    _Atomic uint64_t drops;
    _Atomic uint64_t arp_tx;
    _Atomic uint64_t ndp_tx;
    _Atomic uint64_t frag_tx;
    _Atomic uint64_t reasm_ok;
    _Atomic uint64_t reasm_fail;
    _Atomic uint64_t mss_clamped;
};

struct tr_engine_params {
    int n_ports;
    int workers;
    struct rte_mempool *mp;
};

typedef void (*tr_tx_fn)(void *arg, int worker, int if_slot,
                         struct rte_mbuf *m);

struct tr_engine *tr_engine_create(const struct tr_engine_params *params,
                                   char *err, size_t errlen);
void tr_engine_destroy(struct tr_engine *e);
void tr_engine_set_tx(struct tr_engine *e, tr_tx_fn tx, void *arg);

int tr_engine_apply(struct tr_engine *e, const struct tr_config *cfg,
                    char *err, size_t errlen);
void tr_engine_config_env(struct tr_engine *e, struct tr_config_env *env);

/* Snapshot helpers (safe while workers run). */
int tr_engine_config_copy(struct tr_engine *e, struct tr_config *out);
int tr_engine_show(struct tr_engine *e, int argc, char **argv, char **out);

int tr_engine_input(struct tr_engine *e, int worker, int if_slot,
                    struct rte_mbuf *m);
void tr_engine_housekeeping(struct tr_engine *e, uint64_t now_ms);
void tr_engine_send_router_solicitations(struct tr_engine *e);

int tr_engine_stats_text(struct tr_engine *e, char **out);

#endif
