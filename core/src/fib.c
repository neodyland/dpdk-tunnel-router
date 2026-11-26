#include "fib.h"

#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int node_alloc(struct tr_fib_node **nodes, int *nnodes, int *cap)
{
    if (*nnodes >= *cap) {
        int ncap = *cap ? *cap * 2 : 1024;
        struct tr_fib_node *p = realloc(*nodes, (size_t)ncap * sizeof(*p));
        if (!p)
            return -1;
        *nodes = p;
        *cap = ncap;
    }
    int idx = (*nnodes)++;
    memset(&(*nodes)[idx], 0, sizeof((*nodes)[idx]));
    (*nodes)[idx].child[0] = -1;
    (*nodes)[idx].child[1] = -1;
    (*nodes)[idx].route = -1;
    return idx;
}

void tr_fib_init(struct tr_fib *fib)
{
    memset(fib, 0, sizeof(*fib));
    fib->root4 = -1;
    fib->root6 = -1;
}

void tr_fib_destroy(struct tr_fib *fib)
{
    free(fib->nodes4);
    free(fib->nodes6);
    tr_fib_init(fib);
}

static int insert_route(struct tr_fib_node **nodes, int *nnodes, int *cap,
                        int *root, const uint8_t *bits, int plen, int route)
{
    int cur;

    if (*root < 0) {
        *root = node_alloc(nodes, nnodes, cap);
        if (*root < 0)
            return -1;
    }
    cur = *root;
    for (int i = 0; i < plen; i++) {
        int bit = (bits[i / 8] >> (7 - (i % 8))) & 1;
        if ((*nodes)[cur].child[bit] < 0) {
            int n = node_alloc(nodes, nnodes, cap);
            if (n < 0)
                return -1;
            (*nodes)[cur].child[bit] = n;
        }
        cur = (*nodes)[cur].child[bit];
    }
    (*nodes)[cur].route = route;
    return 0;
}

static int add_internal(struct tr_fib *fib, const struct tr_prefix *prefix,
                        const struct tr_ip *via, bool connected, int if_slot,
                        int route_id)
{
    struct tr_fib_route *r;
    uint8_t bits[16];
    int idx;

    if (fib->nroutes >= TR_FIB_MAX_ROUTES)
        return -1;
    r = &fib->routes[fib->nroutes];
    memset(r, 0, sizeof(*r));
    r->prefix = *prefix;
    tr_prefix_canonical(&r->prefix);
    if (via)
        r->via = *via;
    r->has_via = via != NULL;
    r->connected = connected;
    r->if_slot = if_slot;
    r->route_id = route_id;
    idx = fib->nroutes++;

    if (prefix->addr.family == TR_AF_INET) {
        uint32_t a = ntohl(prefix->addr.u.v4.s_addr);
        for (int i = 0; i < 4; i++)
            bits[i] = (uint8_t)(a >> (24 - i * 8));
        return insert_route(&fib->nodes4, &fib->nnodes4, &fib->cap4,
                            &fib->root4, bits, prefix->plen, idx);
    }
    memcpy(bits, prefix->addr.u.v6.s6_addr, 16);
    return insert_route(&fib->nodes6, &fib->nnodes6, &fib->cap6, &fib->root6,
                        bits, prefix->plen, idx);
}

int tr_fib_add(struct tr_fib *fib, const struct tr_prefix *prefix,
               const struct tr_ip *via, bool connected, int if_slot,
               int route_id)
{
    return add_internal(fib, prefix, via, connected, if_slot, route_id);
}

static int lookup_bits(const struct tr_fib_node *nodes, int root,
                       const uint8_t *bits, int plen)
{
    int cur = root;
    int best = -1;

    if (cur < 0)
        return -1;
    if (nodes[cur].route >= 0)
        best = nodes[cur].route;
    for (int i = 0; i < plen; i++) {
        int bit = (bits[i / 8] >> (7 - (i % 8))) & 1;
        if (nodes[cur].child[bit] < 0)
            break;
        cur = nodes[cur].child[bit];
        if (nodes[cur].route >= 0)
            best = nodes[cur].route;
    }
    return best;
}

int tr_fib_lookup4(const struct tr_fib *fib, const struct in_addr *dst,
                   struct tr_fib_result *out)
{
    uint8_t bits[4];
    uint32_t a = ntohl(dst->s_addr);
    int idx;

    for (int i = 0; i < 4; i++)
        bits[i] = (uint8_t)(a >> (24 - i * 8));
    idx = lookup_bits(fib->nodes4, fib->root4, bits, 32);
    if (idx < 0)
        return -1;
    out->route = &fib->routes[idx];
    out->prefix_len = fib->routes[idx].prefix.plen;
    return 0;
}

int tr_fib_lookup6(const struct tr_fib *fib, const struct in6_addr *dst,
                   struct tr_fib_result *out)
{
    int idx = lookup_bits(fib->nodes6, fib->root6, dst->s6_addr, 128);

    if (idx < 0)
        return -1;
    out->route = &fib->routes[idx];
    out->prefix_len = fib->routes[idx].prefix.plen;
    return 0;
}

int tr_fib_lookup(const struct tr_fib *fib, const struct tr_ip *dst,
                  struct tr_fib_result *out)
{
    if (dst->family == TR_AF_INET)
        return tr_fib_lookup4(fib, &dst->u.v4, out);
    if (dst->family == TR_AF_INET6)
        return tr_fib_lookup6(fib, &dst->u.v6, out);
    return -1;
}

static int resolve_via(const struct tr_fib *fib, const struct tr_ip *via,
                       int depth, int *if_slot, struct tr_ip *next_hop)
{
    struct tr_fib_result res;

    if (depth > 8)
        return -1;
    if (tr_fib_lookup(fib, via, &res))
        return -1;
    if (res.route->connected) {
        *if_slot = res.route->if_slot;
        *next_hop = *via;
        return 0;
    }
    if (!res.route->has_via)
        return -1;
    if (depth == 0)
        *next_hop = *via;
    return resolve_via(fib, &res.route->via, depth + 1, if_slot, next_hop);
}


int tr_fib_build(struct tr_fib *fib, const struct tr_config *cfg,
                 const struct tr_fib_extra *extras, int nextras, char *err,
                 size_t errlen)
{
    struct tr_route statics[TR_MAX_ROUTES];
    int nstatics = 0;

    /* Rebuild in place so lookups never see a half-built table during
     * configuration apply.  Callers hold the runtime write lock. */
    tr_fib_destroy(fib);

    for (int i = 0; i < TR_MAX_IFACES; i++) {
        const struct tr_iface *iface = &cfg->ifaces[i];
        if (!iface->present || iface->kind == TR_IF_BRIDGE)
            continue;
        if (iface->bridge >= 0)
            continue;
        for (int a = 0; a < iface->naddrs; a++) {
            if (add_internal(fib, &iface->addrs[a], NULL, true, i,
                             -(i + 1) * 16 - a)) {
                snprintf(err, errlen, "FIB is full");
                goto fail;
            }
        }
    }
    for (int i = 0; i < nextras; i++) {
        if (add_internal(fib, &extras[i].prefix,
                         extras[i].has_via ? &extras[i].via : NULL,
                         !extras[i].has_via, extras[i].if_slot,
                         extras[i].route_id)) {
            snprintf(err, errlen, "FIB is full");
            goto fail;
        }
    }

    for (int i = 0; i < cfg->nroutes; i++)
        statics[nstatics++] = cfg->routes[i];

    /* Insert every static route first with its configured next hop.  A
     * second pass then resolves each next hop against the complete table,
     * which permits recursive static routes regardless of insertion
     * order. */
    int static_idx[TR_MAX_ROUTES];
    for (int i = 0; i < nstatics; i++) {
        if (fib->nroutes >= TR_FIB_MAX_ROUTES) {
            snprintf(err, errlen, "FIB is full");
            goto fail;
        }
        struct tr_fib_route *r = &fib->routes[fib->nroutes];
        memset(r, 0, sizeof(*r));
        r->prefix = statics[i].prefix;
        r->via = statics[i].via;
        r->has_via = true;
        r->connected = false;
        r->if_slot = -1;
        r->route_id = statics[i].route_id;
        int idx = fib->nroutes++;
        static_idx[i] = idx;
        uint8_t bits[16];
        int pret;
        if (statics[i].prefix.addr.family == TR_AF_INET) {
            uint32_t a = ntohl(statics[i].prefix.addr.u.v4.s_addr);
            for (int b = 0; b < 4; b++)
                bits[b] = (uint8_t)(a >> (24 - b * 8));
            pret = insert_route(&fib->nodes4, &fib->nnodes4, &fib->cap4,
                                &fib->root4, bits, statics[i].prefix.plen,
                                idx);
        } else {
            memcpy(bits, statics[i].prefix.addr.u.v6.s6_addr, 16);
            pret = insert_route(&fib->nodes6, &fib->nnodes6, &fib->cap6,
                                &fib->root6, bits, statics[i].prefix.plen,
                                idx);
        }
        if (pret) {
            snprintf(err, errlen, "FIB is full");
            goto fail;
        }
    }
    for (int i = 0; i < nstatics; i++) {
        struct tr_fib_route *r = &fib->routes[static_idx[i]];
        struct tr_ip next_hop = statics[i].via;
        int if_slot = -1;
        if (resolve_via(fib, &statics[i].via, 0, &if_slot, &next_hop) == 0) {
            r->via = next_hop;
            r->if_slot = if_slot;
        }
    }
    return 0;
fail:
    tr_fib_destroy(fib);
    return -1;
}
