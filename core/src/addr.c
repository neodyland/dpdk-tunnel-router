#include "addr.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_prefix_len(const char *s, uint8_t max, uint8_t *plen)
{
    uint32_t v;

    if (!s || !*s)
        return -1;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9')
            return -1;
    }
    v = (uint32_t)strtoul(s, NULL, 10);
    if (v > max)
        return -1;
    *plen = (uint8_t)v;
    return 0;
}

int tr_ip_parse(const char *s, struct tr_ip *out)
{
    char buf[INET6_ADDRSTRLEN + 16];
    char *slash;
    size_t n;

    if (!s || !*s || !out)
        return -1;
    n = strlen(s);
    if (n >= sizeof(buf))
        return -1;
    memcpy(buf, s, n + 1);
    slash = strchr(buf, '/');
    if (slash)
        *slash = '\0';

    memset(out, 0, sizeof(*out));
    if (inet_pton(AF_INET, buf, &out->u.v4) == 1) {
        out->family = TR_AF_INET;
    } else if (inet_pton(AF_INET6, buf, &out->u.v6) == 1) {
        out->family = TR_AF_INET6;
    } else {
        return -1;
    }
    return 0;
}

int tr_ip_parse_family(const char *s, uint8_t family, struct tr_ip *out)
{
    if (tr_ip_parse(s, out))
        return -1;
    if (out->family != family)
        return -1;
    return 0;
}

static int prefix_parse_internal(const char *s, struct tr_prefix *out,
                                 bool canonical)
{
    char buf[INET6_ADDRSTRLEN + 16];
    char *slash;
    size_t n;

    if (!s || !*s || !out)
        return -1;
    n = strlen(s);
    if (n >= sizeof(buf))
        return -1;
    memcpy(buf, s, n + 1);
    slash = strchr(buf, '/');
    if (slash)
        *slash = '\0';

    memset(out, 0, sizeof(*out));
    if (inet_pton(AF_INET, buf, &out->addr.u.v4) == 1) {
        out->addr.family = TR_AF_INET;
        out->plen = 32;
        if (slash && parse_prefix_len(slash + 1, 32, &out->plen))
            return -1;
    } else if (inet_pton(AF_INET6, buf, &out->addr.u.v6) == 1) {
        out->addr.family = TR_AF_INET6;
        out->plen = 128;
        if (slash && parse_prefix_len(slash + 1, 128, &out->plen))
            return -1;
    } else {
        return -1;
    }
    if (canonical)
        tr_prefix_canonical(out);
    return 0;
}

int tr_prefix_parse(const char *s, struct tr_prefix *out)
{
    return prefix_parse_internal(s, out, true);
}

int tr_prefix_parse_host(const char *s, struct tr_prefix *out)
{
    return prefix_parse_internal(s, out, false);
}

int tr_ip_ntop(const struct tr_ip *ip, char *buf, size_t len)
{
    const char *rc;

    if (!ip)
        return -1;
    switch (ip->family) {
    case TR_AF_INET:
        rc = inet_ntop(AF_INET, &ip->u.v4, buf, (socklen_t)len);
        break;
    case TR_AF_INET6:
        rc = inet_ntop(AF_INET6, &ip->u.v6, buf, (socklen_t)len);
        break;
    default:
        if (len < 2)
            return -1;
        buf[0] = '-';
        buf[1] = '\0';
        return 0;
    }
    return rc ? 0 : -1;
}

int tr_prefix_ntop(const struct tr_prefix *p, char *buf, size_t len)
{
    char a[INET6_ADDRSTRLEN];
    int n;

    if (tr_ip_ntop(&p->addr, a, sizeof(a)))
        return -1;
    n = snprintf(buf, len, "%s/%u", a, p->plen);
    return n < 0 || (size_t)n >= len ? -1 : 0;
}

bool tr_ip_is_unspecified(const struct tr_ip *a)
{
    if (!a)
        return true;
    switch (a->family) {
    case TR_AF_INET:
        return a->u.v4.s_addr == htonl(INADDR_ANY);
    case TR_AF_INET6:
        return IN6_IS_ADDR_UNSPECIFIED(&a->u.v6);
    default:
        return true;
    }
}

bool tr_ip_is_multicast(const struct tr_ip *a)
{
    if (!a)
        return false;
    if (a->family == TR_AF_INET)
        return (ntohl(a->u.v4.s_addr) & 0xf0000000u) == 0xe0000000u;
    if (a->family == TR_AF_INET6)
        return IN6_IS_ADDR_MULTICAST(&a->u.v6);
    return false;
}

bool tr_ip_is_linklocal(const struct tr_ip *a)
{
    if (!a || a->family != TR_AF_INET6)
        return false;
    return IN6_IS_ADDR_LINKLOCAL(&a->u.v6);
}

bool tr_ip_is_v4_mapped(const struct tr_ip *a)
{
    return a && a->family == TR_AF_INET6 && IN6_IS_ADDR_V4MAPPED(&a->u.v6);
}

void tr_prefix_canonical(struct tr_prefix *p)
{
    if (!p)
        return;
    if (p->addr.family == TR_AF_INET) {
        uint32_t mask = p->plen ? (0xffffffffu << (32 - p->plen)) : 0;
        p->addr.u.v4.s_addr &= htonl(mask);
    } else if (p->addr.family == TR_AF_INET6) {
        uint8_t *b = p->addr.u.v6.s6_addr;
        for (int i = 0; i < 16; i++) {
            int bits = (int)p->plen - i * 8;
            if (bits >= 8)
                continue;
            if (bits <= 0) {
                b[i] = 0;
            } else {
                b[i] &= (uint8_t)(0xff << (8 - bits));
            }
        }
    }
}

bool tr_prefix_contains(const struct tr_prefix *p, const struct tr_ip *a)
{
    if (!p || !a || p->addr.family != a->family)
        return false;
    if (a->family == TR_AF_INET) {
        uint32_t mask = p->plen ? (0xffffffffu << (32 - p->plen)) : 0;
        return (a->u.v4.s_addr & htonl(mask)) == p->addr.u.v4.s_addr;
    }
    uint8_t full = p->plen / 8;
    uint8_t rem = p->plen % 8;
    if (memcmp(a->u.v6.s6_addr, p->addr.u.v6.s6_addr, full) != 0)
        return false;
    if (!rem)
        return true;
    uint8_t mask = (uint8_t)(0xff << (8 - rem));
    return (a->u.v6.s6_addr[full] & mask) ==
           (p->addr.u.v6.s6_addr[full] & mask);
}

void tr_ip_to_v6(const struct tr_ip *src, struct in6_addr *out)
{
    memset(out, 0, sizeof(*out));
    if (src->family == TR_AF_INET6) {
        *out = src->u.v6;
    } else if (src->family == TR_AF_INET) {
        out->s6_addr[10] = 0xff;
        out->s6_addr[11] = 0xff;
        memcpy(&out->s6_addr[12], &src->u.v4, 4);
    }
}

uint32_t tr_ip_hash(const struct tr_ip *a)
{
    uint32_t h = 2166136261u;
    const uint8_t *p;
    size_t n;

    if (!a)
        return 0;
    if (a->family == TR_AF_INET) {
        p = (const uint8_t *)&a->u.v4;
        n = 4;
    } else {
        p = a->u.v6.s6_addr;
        n = 16;
    }
    h ^= a->family;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

void tr_ip6_linklocal(const uint8_t mac[6], struct in6_addr *out)
{
    memset(out, 0, sizeof(*out));
    out->s6_addr[0] = 0xfe;
    out->s6_addr[1] = 0x80;
    out->s6_addr[8] = (uint8_t)(mac[0] ^ 0x02);
    out->s6_addr[9] = mac[1];
    out->s6_addr[10] = mac[2];
    out->s6_addr[11] = 0xff;
    out->s6_addr[12] = 0xfe;
    out->s6_addr[13] = mac[3];
    out->s6_addr[14] = mac[4];
    out->s6_addr[15] = mac[5];
}

void tr_ip6_solicited_node(const struct in6_addr *target, struct in6_addr *out)
{
    memset(out, 0, sizeof(*out));
    out->s6_addr[0] = 0xff;
    out->s6_addr[1] = 0x02;
    out->s6_addr[11] = 0x01;
    out->s6_addr[12] = 0xff;
    out->s6_addr[13] = target->s6_addr[13];
    out->s6_addr[14] = target->s6_addr[14];
    out->s6_addr[15] = target->s6_addr[15];
}

void tr_ip6_from_eui64(const struct in6_addr *prefix, uint8_t plen,
                       const uint8_t mac[6], struct in6_addr *out)
{
    *out = *prefix;
    if (plen <= 64) {
        out->s6_addr[8] = (uint8_t)(mac[0] ^ 0x02);
        out->s6_addr[9] = mac[1];
        out->s6_addr[10] = mac[2];
        out->s6_addr[11] = 0xff;
        out->s6_addr[12] = 0xfe;
        out->s6_addr[13] = mac[3];
        out->s6_addr[14] = mac[4];
        out->s6_addr[15] = mac[5];
    }
}

bool tr_ip6_is_solicited_node(const struct in6_addr *addr,
                             const struct in6_addr *target)
{
    struct in6_addr sn;

    tr_ip6_solicited_node(target, &sn);
    return memcmp(addr, &sn, sizeof(sn)) == 0;
}

uint32_t tr_ip4_u32(const struct in_addr *a)
{
    return ntohl(a->s_addr);
}

void tr_ip4_from_u32(uint32_t host, struct in_addr *a)
{
    a->s_addr = htonl(host);
}
