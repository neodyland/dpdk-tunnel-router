#include "config_internal.h"

#include "tunnel.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct sbuf {
    char *data;
    size_t len;
    size_t cap;
};

static int sb_reserve(struct sbuf *sb, size_t extra)
{
    size_t need = sb->len + extra + 1;
    size_t cap;
    char *p;

    if (need <= sb->cap)
        return 0;
    cap = sb->cap ? sb->cap : 4096;
    while (cap < need) {
        if (cap > (1u << 20))
            return -1;
        cap *= 2;
    }
    p = realloc(sb->data, cap);
    if (!p)
        return -1;
    sb->data = p;
    sb->cap = cap;
    return 0;
}

static int sb_appendf(struct sbuf *sb, const char *fmt, ...)
{
    va_list ap, ap2;
    int n;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        va_end(ap2);
        return -1;
    }
    if (sb_reserve(sb, (size_t)n)) {
        va_end(ap2);
        return -1;
    }
    vsnprintf(sb->data + sb->len, sb->cap - sb->len, fmt, ap2);
    va_end(ap2);
    sb->len += (size_t)n;
    return 0;
}

static int sb_addrs(struct sbuf *sb, const char *prefix,
                    const struct tr_iface *iface)
{
    for (int i = 0; i < iface->naddrs; i++) {
        char a[96];
        if (tr_prefix_ntop(&iface->addrs[i], a, sizeof(a)))
            return -1;
        if (sb_appendf(sb, "%s address %s\n", prefix, a))
            return -1;
    }
    if (iface->ipv6_autoconf &&
        sb_appendf(sb, "%s address ipv6 autoconf\n", prefix))
        return -1;
    return 0;
}

static const char *mss_string(const struct tr_iface *iface, char *buf,
                              size_t len)
{
    if (iface->tunnel.tcp_mss < 0)
        return "none";
    if (iface->tunnel.tcp_mss == 0)
        return "auto";
    snprintf(buf, len, "%d", iface->tunnel.tcp_mss);
    return buf;
}

int tr_config_serialize(const struct tr_config *cfg, char **out)
{
    struct sbuf sb = {0};
    char a[96], b[96], mss[16];

    if (!cfg || !out)
        return -1;
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        const struct tr_iface *iface = &cfg->ifaces[i];
        if (!iface->present || iface->kind != TR_IF_ETHERNET)
            continue;
        if (sb_appendf(&sb, "set interfaces ethernet %s port %d\n",
                       iface->name, iface->port_id) ||
            sb_appendf(&sb, "set interfaces ethernet %s mtu %u\n",
                       iface->name, iface->mtu))
            goto fail;
        char pfx[TR_IFNAME_LEN + 16];
        snprintf(pfx, sizeof(pfx), "set interfaces ethernet %s", iface->name);
        if (sb_addrs(&sb, pfx, iface))
            goto fail;
        for (int v = 0; v < TR_MAX_IFACES; v++) {
            const struct tr_iface *vlan = &cfg->ifaces[v];
            if (!vlan->present || vlan->kind != TR_IF_VLAN ||
                vlan->parent != iface->slot)
                continue;
            if (sb_appendf(&sb,
                           "set interfaces ethernet %s vlan-id %d mtu %u\n",
                           iface->name, vlan->vlan_id, vlan->mtu))
                goto fail;
            char vpfx[TR_IFNAME_LEN + 32];
            snprintf(vpfx, sizeof(vpfx),
                     "set interfaces ethernet %s vlan-id %d", iface->name,
                     vlan->vlan_id);
            if (sb_addrs(&sb, vpfx, vlan))
                goto fail;
        }
    }
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        const struct tr_iface *iface = &cfg->ifaces[i];
        if (!iface->present || iface->kind != TR_IF_TUNNEL)
            continue;
        if (sb_appendf(&sb, "set interfaces tunnel %s encapsulation %s\n",
                       iface->name, iface->tunnel.driver))
            goto fail;
        if (iface->tunnel.remote.family) {
            tr_ip_ntop(&iface->tunnel.remote, a, sizeof(a));
            if (sb_appendf(&sb, "set interfaces tunnel %s remote %s\n",
                           iface->name, a))
                goto fail;
        }
        if (iface->tunnel.local.family) {
            tr_ip_ntop(&iface->tunnel.local, a, sizeof(a));
            if (sb_appendf(&sb,
                           "set interfaces tunnel %s local-address %s\n",
                           iface->name, a))
                goto fail;
        }
        if (iface->tunnel.local_if[0] &&
            sb_appendf(&sb,
                       "set interfaces tunnel %s local-interface %s\n",
                       iface->name, iface->tunnel.local_if))
            goto fail;
        if (sb_appendf(&sb, "set interfaces tunnel %s mtu %u\n", iface->name,
                       iface->mtu) ||
            sb_appendf(&sb, "set interfaces tunnel %s tcp-mss %s\n",
                       iface->name, mss_string(iface, mss, sizeof(mss))))
            goto fail;
        char pfx[TR_IFNAME_LEN + 16];
        snprintf(pfx, sizeof(pfx), "set interfaces tunnel %s", iface->name);
        if (sb_addrs(&sb, pfx, iface))
            goto fail;
    }
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        const struct tr_iface *br = &cfg->ifaces[i];
        if (!br->present || br->kind != TR_IF_BRIDGE)
            continue;
        for (int c = 0; c < br->nchildren; c++) {
            const struct tr_iface *child =
                tr_config_find_slot_const(cfg, br->children[c]);
            if (!child)
                continue;
            if (sb_appendf(&sb, "set interfaces bridge %s children %s\n",
                           br->name, child->name))
                goto fail;
        }
        if (sb_appendf(&sb, "set interfaces bridge %s mtu %u\n", br->name,
                       br->mtu))
            goto fail;
    }
    for (int i = 0; i < cfg->nroutes; i++) {
        const struct tr_route *r = &cfg->routes[i];
        if (!r->has_via)
            continue;
        if (tr_prefix_ntop(&r->prefix, a, sizeof(a)) ||
            tr_ip_ntop(&r->via, b, sizeof(b)))
            goto fail;
        if (sb_appendf(&sb, "set protocols static route %s via %s\n", a, b))
            goto fail;
    }
    if (!sb.data && sb_reserve(&sb, 0))
        goto fail;
    sb.data[sb.len] = '\0';
    *out = sb.data;
    return 0;
fail:
    free(sb.data);
    return -1;
}

int tr_config_save(const struct tr_config *cfg, const char *path, char *err,
                   size_t errlen)
{
    char *body = NULL;
    struct sbuf sb = {0};
    int rc;

    if (tr_config_serialize(cfg, &body)) {
        snprintf(err, errlen, "cannot serialize configuration");
        return -1;
    }
    if (sb_appendf(&sb, "# dpdk-tunnel-router running configuration\n") ||
        sb_appendf(&sb, "# generated atomically; edit with routerctl\n") ||
        sb_appendf(&sb, "%s", body)) {
        free(body);
        free(sb.data);
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    rc = tr_write_file_atomic(path, sb.data, sb.len, 0640);
    if (rc)
        snprintf(err, errlen, "cannot write %s: %s", path, strerror(errno));
    free(body);
    free(sb.data);
    return rc;
}

int tr_config_load(struct tr_config *cfg, const struct tr_config_env *env,
                   const char *path, char *err, size_t errlen)
{
    char *data = NULL;
    size_t len = 0;
    char *save = NULL;
    char *line;
    unsigned lineno = 0;
    int rc = 0;

    if (tr_read_file(path, &data, &len)) {
        snprintf(err, errlen, "cannot read %s: %s", path, strerror(errno));
        return -1;
    }
    for (line = strtok_r(data, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char *argv[64];
        int argc;
        char *trimmed;
        char local_err[256];

        lineno++;
        trimmed = tr_trim(line);
        if (!*trimmed || *trimmed == '#')
            continue;
        if (strlen(trimmed) >= 1024) {
            snprintf(err, errlen, "%s:%u: line too long", path, lineno);
            rc = -1;
            break;
        }
        argc = tr_split(trimmed, argv, (int)TR_ARRAY_SIZE(argv));
        if (argc == 0)
            continue;
        if (tr_config_apply(cfg, env, argc, argv, local_err,
                            sizeof(local_err))) {
            snprintf(err, errlen, "%s:%u: %s", path, lineno, local_err);
            rc = -1;
            break;
        }
    }
    free(data);
    return rc;
}

void tr_config_format_addr(const struct tr_ip *ip, char *buf, size_t len)
{
    if (tr_ip_ntop(ip, buf, len))
        snprintf(buf, len, "?");
}

void tr_config_format_iface(const struct tr_iface *iface, char *buf,
                            size_t len)
{
    char a[96];

    if (tr_ip_ntop(&iface->tunnel.remote, a, sizeof(a)))
        snprintf(a, sizeof(a), "-");
    snprintf(buf, len, "%s %s mtu %u remote %s", iface->name,
             iface->kind == TR_IF_TUNNEL    ? "tunnel"
             : iface->kind == TR_IF_BRIDGE  ? "bridge"
             : iface->kind == TR_IF_VLAN    ? "vlan"
                                            : "ethernet",
             iface->mtu, a);
}

static int show_one_interface(struct sbuf *sb, const struct tr_config *cfg,
                              const struct tr_iface *iface)
{
    char mac[18], a[96], b[96];

    tr_format_mac(iface->mac, mac);
    if (sb_appendf(sb, "%s (%s, mtu %u, mac %s)\n", iface->name,
                   iface->kind == TR_IF_TUNNEL    ? "tunnel"
                   : iface->kind == TR_IF_BRIDGE  ? "bridge"
                   : iface->kind == TR_IF_VLAN    ? "vlan"
                                                  : "ethernet",
                   iface->mtu, mac))
        return -1;
    if (sb_appendf(sb, "  ifindex %d\n", iface->slot))
        return -1;
    if (iface->kind == TR_IF_ETHERNET &&
        sb_appendf(sb, "  port %d\n", iface->port_id))
        return -1;
    if (iface->kind == TR_IF_VLAN)
        if (sb_appendf(sb, "  vlan-id %d parent %s\n", iface->vlan_id,
                       cfg->ifaces[iface->parent].name))
            return -1;
    for (int i = 0; i < iface->naddrs; i++) {
        tr_prefix_ntop(&iface->addrs[i], a, sizeof(a));
        if (sb_appendf(sb, "  address %s\n", a))
            return -1;
    }
    if (iface->ipv6_autoconf && sb_appendf(sb, "  address ipv6 autoconf\n"))
        return -1;
    if (iface->kind == TR_IF_TUNNEL) {
        if (iface->tunnel.remote.family) {
            tr_ip_ntop(&iface->tunnel.remote, a, sizeof(a));
        } else {
            snprintf(a, sizeof(a), "-");
        }
        if (iface->tunnel.local.family) {
            tr_ip_ntop(&iface->tunnel.local, b, sizeof(b));
        } else {
            snprintf(b, sizeof(b), "-");
        }
        if (sb_appendf(sb,
                       "  encapsulation %s remote %s local %s "
                       "local-interface %s tcp-mss %d\n",
                       iface->tunnel.driver, a, b,
                       iface->tunnel.local_if[0] ? iface->tunnel.local_if
                                                 : "-",
                       iface->tunnel.tcp_mss))
            return -1;
    }
    if (iface->kind == TR_IF_BRIDGE) {
        if (sb_appendf(sb, "  children:"))
            return -1;
        for (int c = 0; c < iface->nchildren; c++) {
            const struct tr_iface *child =
                tr_config_find_slot_const(cfg, iface->children[c]);
            if (child && sb_appendf(sb, " %s", child->name))
                return -1;
        }
        if (sb_appendf(sb, "\n"))
            return -1;
    }
    if (iface->bridge >= 0 &&
        sb_appendf(sb, "  bridge %s\n", cfg->ifaces[iface->bridge].name))
        return -1;
    return 0;
}

int tr_config_show(const struct tr_config *cfg, int argc, char **argv,
                   char **out)
{
    struct sbuf sb = {0};
    int rc = -1;

    if (argc < 1)
        return -1;
    if (strcmp(argv[0], "configuration") == 0) {
        if (tr_config_serialize(cfg, &sb.data))
            return -1;
        *out = sb.data;
        return 0;
    }
    if (strcmp(argv[0], "interfaces") != 0)
        return -1;
    if (argc >= 2) {
        const struct tr_iface *iface = tr_config_find_const(cfg, argv[1]);
        if (!iface) {
            if (sb_appendf(&sb, "error: unknown interface '%s'\n", argv[1]))
                goto done;
        } else if (show_one_interface(&sb, cfg, iface)) {
            goto done;
        }
    } else {
        for (int i = 0; i < TR_MAX_IFACES; i++) {
            if (cfg->ifaces[i].present &&
                show_one_interface(&sb, cfg, &cfg->ifaces[i]))
                goto done;
        }
    }
    if (!sb.data && sb_reserve(&sb, 0))
        goto done;
    *out = sb.data;
    sb.data = NULL;
    rc = 0;
done:
    free(sb.data);
    return rc;
}
