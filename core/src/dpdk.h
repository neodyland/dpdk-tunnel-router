#ifndef TR_DPDK_H
#define TR_DPDK_H

#include "engine.h"

#include <stdint.h>

struct tr_dpdk;

struct tr_dpdk_params {
    int workers;
    struct rte_mempool *mp;
};

struct tr_dpdk *tr_dpdk_create(struct tr_engine *engine,
                               const struct tr_dpdk_params *params, char *err,
                               size_t errlen);
int tr_dpdk_start(struct tr_dpdk *d, char *err, size_t errlen);
int tr_dpdk_launch_workers(struct tr_dpdk *d);
void tr_dpdk_stop(struct tr_dpdk *d);
void tr_dpdk_destroy(struct tr_dpdk *d);
int tr_dpdk_refresh(struct tr_dpdk *d);
int tr_dpdk_port_count(struct tr_dpdk *d);
int tr_dpdk_worker_count(struct tr_dpdk *d);
int tr_dpdk_status_text(struct tr_dpdk *d, char **out);

#endif
