#ifndef TR_ADDR_H
#define TR_ADDR_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

enum tr_family {
    TR_AF_NONE = 0,
    TR_AF_INET = 4,
    TR_AF_INET6 = 6,
};

struct tr_ip {
    uint8_t family; /* TR_AF_* */
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } u;
};

struct tr_prefix {
    struct tr_ip addr;
    uint8_t plen;
};

int tr_ip_parse(const char *s, struct tr_ip *out);
int tr_prefix_parse(const char *s, struct tr_prefix *out);
int tr_prefix_parse_host(const char *s, struct tr_prefix *out);
int tr_ip_parse_family(const char *s, uint8_t family, struct tr_ip *out);
int tr_ip_ntop(const struct tr_ip *ip, char *buf, size_t len);
int tr_prefix_ntop(const struct tr_prefix *p, char *buf, size_t len);

static inline bool tr_ip_equal(const struct tr_ip *a, const struct tr_ip *b)
{
    if (!a || !b || a->family != b->family)
        return false;
    switch (a->family) {
    case TR_AF_INET:
        return a->u.v4.s_addr == b->u.v4.s_addr;
    case TR_AF_INET6:
        return memcmp(&a->u.v6, &b->u.v6, sizeof(a->u.v6)) == 0;
    default:
        return true;
    }
}

bool tr_ip_is_unspecified(const struct tr_ip *a);
bool tr_ip_is_multicast(const struct tr_ip *a);
bool tr_ip_is_linklocal(const struct tr_ip *a);
bool tr_ip_is_v4_mapped(const struct tr_ip *a);
bool tr_prefix_contains(const struct tr_prefix *p, const struct tr_ip *a);
void tr_prefix_canonical(struct tr_prefix *p);
void tr_ip_to_v6(const struct tr_ip *src, struct in6_addr *out);
uint32_t tr_ip_hash(const struct tr_ip *a);

void tr_ip6_linklocal(const uint8_t mac[6], struct in6_addr *out);
void tr_ip6_solicited_node(const struct in6_addr *target, struct in6_addr *out);
void tr_ip6_from_eui64(const struct in6_addr *prefix, uint8_t plen,
                       const uint8_t mac[6], struct in6_addr *out);
bool tr_ip6_is_solicited_node(const struct in6_addr *addr,
                             const struct in6_addr *target);

/* IPv4 network byte order helpers. */
uint32_t tr_ip4_u32(const struct in_addr *a);
void tr_ip4_from_u32(uint32_t host, struct in_addr *a);

#endif
