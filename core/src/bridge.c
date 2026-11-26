#include "bridge.h"

#include "config.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned mac_bucket(const uint8_t mac[6])
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < 6; i++) {
        h ^= mac[i];
        h *= 16777619u;
    }
    return h % TR_BRIDGE_BUCKETS;
}

void tr_bridge_db_init(struct tr_bridge_db *db)
{
    memset(db, 0, sizeof(*db));
    for (int t = 0; t < TR_MAX_IFACES; t++)
        for (int i = 0; i < TR_BRIDGE_BUCKETS; i++)
            pthread_spin_init(&db->tables[t].buckets[i].lock,
                              PTHREAD_PROCESS_PRIVATE);
}

void tr_bridge_db_fini(struct tr_bridge_db *db)
{
    for (int t = 0; t < TR_MAX_IFACES; t++)
        for (int i = 0; i < TR_BRIDGE_BUCKETS; i++)
            pthread_spin_destroy(&db->tables[t].buckets[i].lock);
}

void tr_bridge_learn(struct tr_bridge_db *db, int bridge_slot,
                     const uint8_t mac[6], int if_slot, uint64_t now)
{
    struct tr_bridge_table *t;
    struct tr_bridge_bucket *b;
    struct tr_bridge_mac *e = NULL;

    if (bridge_slot < 0 || bridge_slot >= TR_MAX_IFACES ||
        tr_mac_is_multicast(mac) || tr_mac_is_zero(mac))
        return;
    t = &db->tables[bridge_slot];
    b = &t->buckets[mac_bucket(mac)];
    pthread_spin_lock(&b->lock);
    for (int i = 0; i < TR_BRIDGE_PER_BUCKET; i++) {
        if (b->entries[i].used &&
            memcmp(b->entries[i].mac, mac, 6) == 0) {
            e = &b->entries[i];
            break;
        }
    }
    if (!e) {
        for (int i = 0; i < TR_BRIDGE_PER_BUCKET; i++) {
            if (!b->entries[i].used) {
                e = &b->entries[i];
                break;
            }
        }
    }
    if (!e) {
        e = &b->entries[0];
        for (int i = 1; i < TR_BRIDGE_PER_BUCKET; i++) {
            if (b->entries[i].last_seen < e->last_seen)
                e = &b->entries[i];
        }
    }
    e->used = true;
    memcpy(e->mac, mac, 6);
    e->if_slot = if_slot;
    e->last_seen = now;
    pthread_spin_unlock(&b->lock);
}

int tr_bridge_lookup(struct tr_bridge_db *db, int bridge_slot,
                     const uint8_t mac[6])
{
    struct tr_bridge_table *t;
    struct tr_bridge_bucket *b;
    int rc = -1;

    if (bridge_slot < 0 || bridge_slot >= TR_MAX_IFACES)
        return -1;
    t = &db->tables[bridge_slot];
    b = &t->buckets[mac_bucket(mac)];
    pthread_spin_lock(&b->lock);
    for (int i = 0; i < TR_BRIDGE_PER_BUCKET; i++) {
        if (b->entries[i].used &&
            memcmp(b->entries[i].mac, mac, 6) == 0) {
            rc = b->entries[i].if_slot;
            break;
        }
    }
    pthread_spin_unlock(&b->lock);
    return rc;
}

void tr_bridge_expire(struct tr_bridge_db *db, uint64_t now)
{
    for (int t = 0; t < TR_MAX_IFACES; t++) {
        for (int i = 0; i < TR_BRIDGE_BUCKETS; i++) {
            struct tr_bridge_bucket *b = &db->tables[t].buckets[i];
            pthread_spin_lock(&b->lock);
            for (int j = 0; j < TR_BRIDGE_PER_BUCKET; j++) {
                struct tr_bridge_mac *e = &b->entries[j];
                if (e->used && now > e->last_seen &&
                    now - e->last_seen > 300000)
                    e->used = false;
            }
            pthread_spin_unlock(&b->lock);
        }
    }
}

void tr_bridge_clear(struct tr_bridge_db *db, int bridge_slot)
{
    if (bridge_slot < 0 || bridge_slot >= TR_MAX_IFACES)
        return;
    for (int i = 0; i < TR_BRIDGE_BUCKETS; i++) {
        struct tr_bridge_bucket *b = &db->tables[bridge_slot].buckets[i];
        pthread_spin_lock(&b->lock);
        memset(b->entries, 0, sizeof(b->entries));
        pthread_spin_unlock(&b->lock);
    }
}

void tr_bridge_clear_iface(struct tr_bridge_db *db, int if_slot)
{
    for (int t = 0; t < TR_MAX_IFACES; t++) {
        for (int i = 0; i < TR_BRIDGE_BUCKETS; i++) {
            struct tr_bridge_bucket *b = &db->tables[t].buckets[i];
            pthread_spin_lock(&b->lock);
            for (int j = 0; j < TR_BRIDGE_PER_BUCKET; j++) {
                if (b->entries[j].used &&
                    b->entries[j].if_slot == if_slot)
                    b->entries[j].used = false;
            }
            pthread_spin_unlock(&b->lock);
        }
    }
}

int tr_bridge_show(struct tr_bridge_db *db, const struct tr_config *cfg,
                   uint64_t now, char **out)
{
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);
    char mac[18];

    if (!buf)
        return -1;
    buf[0] = '\0';
    for (int t = 0; t < TR_MAX_IFACES; t++) {
        for (int i = 0; i < TR_BRIDGE_BUCKETS; i++) {
            struct tr_bridge_bucket *b = &db->tables[t].buckets[i];
            pthread_spin_lock(&b->lock);
            for (int j = 0; j < TR_BRIDGE_PER_BUCKET; j++) {
                struct tr_bridge_mac *e = &b->entries[j];
                char bridge[TR_IFNAME_LEN], port[TR_IFNAME_LEN];
                if (!e->used)
                    continue;
                snprintf(bridge, sizeof(bridge), "if%d", t);
                if (cfg && t < TR_MAX_IFACES && cfg->ifaces[t].present)
                    snprintf(bridge, sizeof(bridge), "%s", cfg->ifaces[t].name);
                snprintf(port, sizeof(port), "if%d", e->if_slot);
                if (cfg && e->if_slot >= 0 && e->if_slot < TR_MAX_IFACES &&
                    cfg->ifaces[e->if_slot].present)
                    snprintf(port, sizeof(port), "%s",
                             cfg->ifaces[e->if_slot].name);
                tr_format_mac(e->mac, mac);
                uint64_t age = 0;
                if (e->last_seen && now >= e->last_seen)
                    age = now - e->last_seen;
                char line[160];
                int n = snprintf(line, sizeof(line),
                                 "bridge %-12s mac %s port %-12s age %llums\n",
                                 bridge, mac, port,
                                 (unsigned long long)age);
                if (n < 0)
                    continue;
                if (len + (size_t)n + 1 > cap) {
                    cap *= 2;
                    char *nb = realloc(buf, cap);
                    if (!nb) {
                        pthread_spin_unlock(&b->lock);
                        free(buf);
                        return -1;
                    }
                    buf = nb;
                }
                memcpy(buf + len, line, (size_t)n + 1);
                len += (size_t)n;
            }
            pthread_spin_unlock(&b->lock);
        }
    }
    *out = buf;
    return 0;
}
