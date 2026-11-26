#include "neigh.h"

#include "config.h"

#include "util.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned bucket_of(int if_slot, const struct tr_ip *ip)
{
    uint32_t h = tr_ip_hash(ip) ^ ((uint32_t)if_slot * 2654435761u);
    return h % TR_NEIGH_BUCKETS;
}

static struct tr_neigh_entry *find_entry(struct tr_neigh_bucket *b,
                                         int if_slot,
                                         const struct tr_ip *ip)
{
    for (int i = 0; i < TR_NEIGH_PER_BUCKET; i++) {
        struct tr_neigh_entry *e = &b->entries[i];
        if (e->used && e->if_slot == if_slot && tr_ip_equal(&e->ip, ip))
            return e;
    }
    return NULL;
}

static void entry_clear(struct tr_neigh_table *t, struct tr_neigh_entry *e)
{
    if (t->free_pkt) {
        for (int i = 0; i < e->npending; i++)
            t->free_pkt(e->pending[i]);
    }
    memset(e, 0, sizeof(*e));
}

static struct tr_neigh_entry *find_or_create(struct tr_neigh_table *t,
                                             struct tr_neigh_bucket *b,
                                             int if_slot,
                                             const struct tr_ip *ip)
{
    struct tr_neigh_entry *e = find_entry(b, if_slot, ip);

    if (e)
        return e;
    for (int i = 0; i < TR_NEIGH_PER_BUCKET; i++) {
        if (!b->entries[i].used) {
            e = &b->entries[i];
            memset(e, 0, sizeof(*e));
            e->used = true;
            e->if_slot = if_slot;
            e->ip = *ip;
            return e;
        }
    }
    /* Replace the oldest entry in this bucket. */
    e = &b->entries[0];
    for (int i = 1; i < TR_NEIGH_PER_BUCKET; i++) {
        if (b->entries[i].last_seen < e->last_seen)
            e = &b->entries[i];
    }
    entry_clear(t, e);
    e->used = true;
    e->if_slot = if_slot;
    e->ip = *ip;
    return e;
}

void tr_neigh_init(struct tr_neigh_table *t, void (*free_pkt)(void *))
{
    memset(t, 0, sizeof(*t));
    t->free_pkt = free_pkt;
    for (int i = 0; i < TR_NEIGH_BUCKETS; i++)
        pthread_spin_init(&t->buckets[i].lock, PTHREAD_PROCESS_PRIVATE);
}

void tr_neigh_fini(struct tr_neigh_table *t)
{
    tr_neigh_clear(t);
    for (int i = 0; i < TR_NEIGH_BUCKETS; i++)
        pthread_spin_destroy(&t->buckets[i].lock);
}

int tr_neigh_get(struct tr_neigh_table *t, int if_slot,
                 const struct tr_ip *ip, uint8_t mac[6], uint64_t now,
                 uint8_t *state)
{
    struct tr_neigh_bucket *b = &t->buckets[bucket_of(if_slot, ip)];
    int rc = 0;

    pthread_spin_lock(&b->lock);
    struct tr_neigh_entry *e = find_entry(b, if_slot, ip);
    if (e && e->state != TR_NEIGH_INCOMPLETE) {
        memcpy(mac, e->mac, 6);
        e->last_seen = now;
        if (state)
            *state = e->state;
        rc = 1;
    } else if (e && state) {
        *state = e->state;
    }
    pthread_spin_unlock(&b->lock);
    return rc;
}

int tr_neigh_learn(struct tr_neigh_table *t, int if_slot,
                   const struct tr_ip *ip, const uint8_t mac[6],
                   uint64_t now, void **pending, int max_pending,
                   int *npending)
{
    struct tr_neigh_bucket *b = &t->buckets[bucket_of(if_slot, ip)];
    int n = 0;

    pthread_spin_lock(&b->lock);
    struct tr_neigh_entry *e = find_or_create(t, b, if_slot, ip);
    if (tr_mac_is_multicast(mac) || tr_mac_is_zero(mac)) {
        pthread_spin_unlock(&b->lock);
        return -1;
    }
    memcpy(e->mac, mac, 6);
    e->state = TR_NEIGH_REACHABLE;
    e->last_seen = now;
    while (e->npending > 0 && n < max_pending) {
        pending[n++] = e->pending[0];
        memmove(&e->pending[0], &e->pending[1],
                (size_t)(e->npending - 1) * sizeof(e->pending[0]));
        e->npending--;
    }
    if (e->npending > 0 && t->free_pkt) {
        for (int i = 0; i < e->npending; i++)
            t->free_pkt(e->pending[i]);
        e->npending = 0;
    }
    pthread_spin_unlock(&b->lock);
    if (npending)
        *npending = n;
    return 0;
}

int tr_neigh_queue(struct tr_neigh_table *t, int if_slot,
                   const struct tr_ip *ip, void *pkt, uint64_t now)
{
    struct tr_neigh_bucket *b = &t->buckets[bucket_of(if_slot, ip)];
    int rc = 0;

    pthread_spin_lock(&b->lock);
    struct tr_neigh_entry *e = find_or_create(t, b, if_slot, ip);
    if (e->npending >= TR_NEIGH_PENDING) {
        if (t->free_pkt)
            t->free_pkt(e->pending[0]);
        memmove(&e->pending[0], &e->pending[1],
                (size_t)(TR_NEIGH_PENDING - 1) * sizeof(e->pending[0]));
        e->npending--;
    }
    e->pending[e->npending++] = pkt;
    e->last_seen = now;
    if (e->state != TR_NEIGH_INCOMPLETE)
        e->state = TR_NEIGH_INCOMPLETE;
    pthread_spin_unlock(&b->lock);
    return rc;
}

int tr_neigh_request_allowed(struct tr_neigh_table *t, int if_slot,
                             const struct tr_ip *ip, uint64_t now,
                             uint64_t min_interval_ms)
{
    struct tr_neigh_bucket *b = &t->buckets[bucket_of(if_slot, ip)];
    int allowed = 0;

    pthread_spin_lock(&b->lock);
    struct tr_neigh_entry *e = find_or_create(t, b, if_slot, ip);
    if (e->last_request == 0 || now < e->last_request ||
        now - e->last_request >= min_interval_ms) {
        e->last_request = now;
        allowed = 1;
    }
    e->last_seen = now;
    pthread_spin_unlock(&b->lock);
    return allowed;
}

void tr_neigh_expire(struct tr_neigh_table *t, uint64_t now)
{
    for (int i = 0; i < TR_NEIGH_BUCKETS; i++) {
        struct tr_neigh_bucket *b = &t->buckets[i];
        pthread_spin_lock(&b->lock);
        for (int j = 0; j < TR_NEIGH_PER_BUCKET; j++) {
            struct tr_neigh_entry *e = &b->entries[j];
            if (!e->used)
                continue;
            uint64_t age = now > e->last_seen ? now - e->last_seen : 0;
            uint64_t limit = e->state == TR_NEIGH_INCOMPLETE ? 5000 : 300000;
            if (age > limit)
                entry_clear(t, e);
        }
        pthread_spin_unlock(&b->lock);
    }
}

void tr_neigh_clear_iface(struct tr_neigh_table *t, int if_slot)
{
    for (int i = 0; i < TR_NEIGH_BUCKETS; i++) {
        struct tr_neigh_bucket *b = &t->buckets[i];
        pthread_spin_lock(&b->lock);
        for (int j = 0; j < TR_NEIGH_PER_BUCKET; j++) {
            if (b->entries[j].used && b->entries[j].if_slot == if_slot)
                entry_clear(t, &b->entries[j]);
        }
        pthread_spin_unlock(&b->lock);
    }
}

void tr_neigh_clear(struct tr_neigh_table *t)
{
    for (int i = 0; i < TR_NEIGH_BUCKETS; i++) {
        struct tr_neigh_bucket *b = &t->buckets[i];
        pthread_spin_lock(&b->lock);
        for (int j = 0; j < TR_NEIGH_PER_BUCKET; j++) {
            if (b->entries[j].used)
                entry_clear(t, &b->entries[j]);
        }
        pthread_spin_unlock(&b->lock);
    }
}

static const char *state_name(uint8_t state)
{
    switch (state) {
    case TR_NEIGH_REACHABLE:
        return "reachable";
    case TR_NEIGH_STALE:
        return "stale";
    default:
        return "incomplete";
    }
}

int tr_neigh_show(struct tr_neigh_table *t, const struct tr_config *cfg,
                  uint64_t now, char **out)
{
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);

    if (!buf)
        return -1;
    buf[0] = '\0';
    for (int i = 0; i < TR_NEIGH_BUCKETS; i++) {
        struct tr_neigh_bucket *b = &t->buckets[i];
        pthread_spin_lock(&b->lock);
        for (int j = 0; j < TR_NEIGH_PER_BUCKET; j++) {
            struct tr_neigh_entry *e = &b->entries[j];
            char ip[INET6_ADDRSTRLEN], mac[18], ifname[TR_IFNAME_LEN];
            if (!e->used)
                continue;
            snprintf(ifname, sizeof(ifname), "if%d", e->if_slot);
            if (cfg && e->if_slot >= 0 && e->if_slot < TR_MAX_IFACES &&
                cfg->ifaces[e->if_slot].present)
                snprintf(ifname, sizeof(ifname), "%s",
                         cfg->ifaces[e->if_slot].name);
            tr_ip_ntop(&e->ip, ip, sizeof(ip));
            tr_format_mac(e->mac, mac);
            uint64_t age = 0;
            if (e->last_seen && now >= e->last_seen)
                age = now - e->last_seen;
            char line[192];
            int n = snprintf(line, sizeof(line),
                             "%-12s %-40s lladdr %s %-10s age %llums "
                             "pending %d\n",
                             ifname, ip, mac, state_name(e->state),
                             (unsigned long long)age, e->npending);
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
    *out = buf;
    return 0;
}
