#ifndef TR_BRIDGE_H
#define TR_BRIDGE_H

#include "config.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#define TR_BRIDGE_BUCKETS 64
#define TR_BRIDGE_PER_BUCKET 4

struct tr_bridge_mac {
    bool used;
    uint8_t mac[6];
    int if_slot;
    uint64_t last_seen;
};

struct tr_bridge_bucket {
    pthread_spinlock_t lock;
    struct tr_bridge_mac entries[TR_BRIDGE_PER_BUCKET];
};

struct tr_bridge_table {
    struct tr_bridge_bucket buckets[TR_BRIDGE_BUCKETS];
};

struct tr_bridge_db {
    struct tr_bridge_table tables[TR_MAX_IFACES];
};

void tr_bridge_db_init(struct tr_bridge_db *db);
void tr_bridge_db_fini(struct tr_bridge_db *db);
void tr_bridge_learn(struct tr_bridge_db *db, int bridge_slot,
                     const uint8_t mac[6], int if_slot, uint64_t now);
int tr_bridge_lookup(struct tr_bridge_db *db, int bridge_slot,
                     const uint8_t mac[6]);
void tr_bridge_expire(struct tr_bridge_db *db, uint64_t now);
void tr_bridge_clear(struct tr_bridge_db *db, int bridge_slot);
void tr_bridge_clear_iface(struct tr_bridge_db *db, int if_slot);
int tr_bridge_show(struct tr_bridge_db *db, const struct tr_config *cfg,
                   uint64_t now, char **out);

#endif
