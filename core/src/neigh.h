#ifndef TR_NEIGH_H
#define TR_NEIGH_H

#include "addr.h"

struct tr_config;

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TR_NEIGH_BUCKETS 64
#define TR_NEIGH_PER_BUCKET 8
#define TR_NEIGH_PENDING 8

enum tr_neigh_state {
    TR_NEIGH_INCOMPLETE = 0,
    TR_NEIGH_REACHABLE,
    TR_NEIGH_STALE,
};

struct tr_neigh_entry {
    bool used;
    int if_slot;
    struct tr_ip ip;
    uint8_t mac[6];
    uint8_t state;
    uint64_t last_seen;
    uint64_t last_request;
    void *pending[TR_NEIGH_PENDING];
    int npending;
};

struct tr_neigh_bucket {
    pthread_spinlock_t lock;
    struct tr_neigh_entry entries[TR_NEIGH_PER_BUCKET];
};

struct tr_neigh_table {
    struct tr_neigh_bucket buckets[TR_NEIGH_BUCKETS];
    void (*free_pkt)(void *pkt);
};

void tr_neigh_init(struct tr_neigh_table *t, void (*free_pkt)(void *));
void tr_neigh_fini(struct tr_neigh_table *t);

/* Returns 1 if a usable entry exists, 0 otherwise. */
int tr_neigh_get(struct tr_neigh_table *t, int if_slot,
                 const struct tr_ip *ip, uint8_t mac[6], uint64_t now,
                 uint8_t *state);
int tr_neigh_learn(struct tr_neigh_table *t, int if_slot,
                   const struct tr_ip *ip, const uint8_t mac[6],
                   uint64_t now, void **pending, int max_pending,
                   int *npending);
int tr_neigh_queue(struct tr_neigh_table *t, int if_slot,
                   const struct tr_ip *ip, void *pkt, uint64_t now);
int tr_neigh_request_allowed(struct tr_neigh_table *t, int if_slot,
                             const struct tr_ip *ip, uint64_t now,
                             uint64_t min_interval_ms);
void tr_neigh_expire(struct tr_neigh_table *t, uint64_t now);
void tr_neigh_clear_iface(struct tr_neigh_table *t, int if_slot);
void tr_neigh_clear(struct tr_neigh_table *t);
int tr_neigh_show(struct tr_neigh_table *t, const struct tr_config *cfg,
                  uint64_t now, char **out);

#endif
