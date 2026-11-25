#ifndef TR_FIB_H
#define TR_FIB_H

#include "config.h"

#include <stdbool.h>
#include <stdint.h>

#define TR_FIB_MAX_ROUTES (TR_MAX_ROUTES + TR_MAX_IFACES * TR_MAX_ADDRS + 160)

struct tr_fib_route {
    struct tr_prefix prefix;
    struct tr_ip via;
    bool has_via;
    bool connected;
    int if_slot;
    int route_id;
};

struct tr_fib_extra {
    struct tr_prefix prefix;
    struct tr_ip via;
    bool has_via;
    int if_slot;
    int route_id;
};

struct tr_fib_node {
    int32_t child[2];
    int32_t route; /* index into routes, -1 if none */
};

struct tr_fib {
    struct tr_fib_node *nodes4;
    int nnodes4;
    int cap4;
    struct tr_fib_node *nodes6;
    int nnodes6;
    int cap6;
    int root4;
    int root6;
    struct tr_fib_route routes[TR_FIB_MAX_ROUTES];
    int nroutes;
};

struct tr_fib_result {
    const struct tr_fib_route *route;
    int prefix_len;
};

void tr_fib_init(struct tr_fib *fib);
void tr_fib_destroy(struct tr_fib *fib);
int tr_fib_build(struct tr_fib *fib, const struct tr_config *cfg,
                 const struct tr_fib_extra *extras, int nextras, char *err,
                 size_t errlen);
int tr_fib_add(struct tr_fib *fib, const struct tr_prefix *prefix,
               const struct tr_ip *via, bool connected, int if_slot,
               int route_id);
int tr_fib_lookup4(const struct tr_fib *fib, const struct in_addr *dst,
                   struct tr_fib_result *out);
int tr_fib_lookup6(const struct tr_fib *fib, const struct in6_addr *dst,
                   struct tr_fib_result *out);
int tr_fib_lookup(const struct tr_fib *fib, const struct tr_ip *dst,
                  struct tr_fib_result *out);

#endif
