#include "config_internal.h"

#include "tunnel.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

void tr_config_iface_clear(struct tr_iface *iface)
{
    memset(iface, 0, sizeof(*iface));
    iface->present = false;
    iface->mtu = 1500;
    iface->port_id = -1;
    iface->vlan_id = -1;
    iface->parent = -1;
    iface->bridge = -1;
    iface->tunnel.tcp_mss = -1;
}

void tr_config_init(struct tr_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->next_slot = 0;
    cfg->next_route_id = 1;
    for (int i = 0; i < TR_MAX_IFACES; i++)
        tr_config_iface_clear(&cfg->ifaces[i]);
    for (int i = 0; i < TR_MAX_IFACES; i++)
        cfg->ifaces[i].slot = i;
}

void tr_config_copy(struct tr_config *dst, const struct tr_config *src)
{
    memcpy(dst, src, sizeof(*dst));
}

bool tr_config_name_valid(const char *name)
{
    size_t n;

    if (!name || !*name)
        return false;
    n = strlen(name);
    if (n >= TR_IFNAME_LEN || n == 0)
        return false;
    for (const char *p = name; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '_' &&
            *p != '-')
            return false;
    }
    return true;
}

struct tr_iface *tr_config_find(struct tr_config *cfg, const char *name)
{
    if (!cfg || !name)
        return NULL;
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        if (cfg->ifaces[i].present &&
            strcmp(cfg->ifaces[i].name, name) == 0)
            return &cfg->ifaces[i];
    }
    return NULL;
}

const struct tr_iface *tr_config_find_const(const struct tr_config *cfg,
                                            const char *name)
{
    return tr_config_find((struct tr_config *)cfg, name);
}

struct tr_iface *tr_config_find_slot(struct tr_config *cfg, int slot)
{
    if (!cfg || slot < 0 || slot >= TR_MAX_IFACES)
        return NULL;
    return cfg->ifaces[slot].present ? &cfg->ifaces[slot] : NULL;
}

const struct tr_iface *tr_config_find_slot_const(const struct tr_config *cfg,
                                                 int slot)
{
    return tr_config_find_slot((struct tr_config *)cfg, slot);
}

struct tr_iface *tr_config_create(struct tr_config *cfg, const char *name,
                                  enum tr_if_kind kind, char *err,
                                  size_t errlen)
{
    struct tr_iface *iface;
    int slot = -1;

    if (!tr_config_name_valid(name)) {
        snprintf(err, errlen, "invalid interface name '%s'", name ? name : "");
        return NULL;
    }
    if (tr_config_find(cfg, name)) {
        snprintf(err, errlen, "interface '%s' already exists", name);
        return NULL;
    }
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        if (!cfg->ifaces[i].present) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        snprintf(err, errlen, "interface table is full (max %d)",
                 TR_MAX_IFACES);
        return NULL;
    }
    iface = &cfg->ifaces[slot];
    tr_config_iface_clear(iface);
    iface->slot = slot;
    iface->present = true;
    iface->kind = kind;
    iface->mtu = 1500;
    snprintf(iface->name, sizeof(iface->name), "%s", name);
    tr_mac_from_name(name, iface->mac);
    if (kind == TR_IF_TUNNEL) {
        /* EtherIP (RFC 3378) over IPv4/IPv6 is the permissive default so
         * that commands may arrive in any order.  An operator can switch to
         * the IPv6-only "etherip6" driver at any time. */
        snprintf(iface->tunnel.driver, sizeof(iface->tunnel.driver), "%s",
                 "etherip");
        iface->tunnel.tcp_mss = -1;
    }
    cfg->nifaces++;
    if (slot + 1 > cfg->next_slot)
        cfg->next_slot = slot + 1;
    return iface;
}

int tr_config_del_iface(struct tr_config *cfg, struct tr_iface *iface,
                        char *err, size_t errlen)
{
    if (!cfg || !iface || !iface->present) {
        snprintf(err, errlen, "no such interface");
        return -1;
    }

    if (iface->kind == TR_IF_ETHERNET) {
        for (int i = 0; i < TR_MAX_IFACES; i++) {
            struct tr_iface *child = &cfg->ifaces[i];
            if (child->present && child->kind == TR_IF_VLAN &&
                child->parent == iface->slot) {
                if (tr_config_del_iface(cfg, child, err, errlen))
                    return -1;
            }
        }
    }
    if (iface->kind == TR_IF_BRIDGE) {
        for (int i = 0; i < iface->nchildren; i++) {
            struct tr_iface *child =
                tr_config_find_slot(cfg, iface->children[i]);
            if (child)
                child->bridge = -1;
        }
        iface->nchildren = 0;
    } else if (iface->bridge >= 0) {
        tr_config_detach_bridge(cfg, iface);
    }
    tr_config_iface_clear(iface);
    if (cfg->nifaces > 0)
        cfg->nifaces--;
    return 0;
}

void tr_config_detach_bridge(struct tr_config *cfg, struct tr_iface *iface)
{
    if (!iface || iface->bridge < 0)
        return;
    if (iface->bridge < TR_MAX_IFACES) {
        struct tr_iface *br = &cfg->ifaces[iface->bridge];
        for (int i = 0; i < br->nchildren; i++) {
            if (br->children[i] == iface->slot) {
                memmove(&br->children[i], &br->children[i + 1],
                        (size_t)(br->nchildren - i - 1) *
                            sizeof(br->children[0]));
                br->nchildren--;
                break;
            }
        }
    }
    iface->bridge = -1;
}

int tr_config_add_child(struct tr_config *cfg, struct tr_iface *bridge,
                        struct tr_iface *child, char *err, size_t errlen)
{
    if (!bridge || !child || !bridge->present || !child->present) {
        snprintf(err, errlen, "no such interface");
        return -1;
    }
    if (bridge->kind != TR_IF_BRIDGE) {
        snprintf(err, errlen, "'%s' is not a bridge", bridge->name);
        return -1;
    }
    if (child->kind == TR_IF_BRIDGE) {
        snprintf(err, errlen, "nested bridges are not supported");
        return -1;
    }
    if (child->slot == bridge->slot) {
        snprintf(err, errlen, "bridge cannot contain itself");
        return -1;
    }
    if (child->bridge == bridge->slot)
        return 0;
    if (child->bridge >= 0)
        tr_config_detach_bridge(cfg, child);
    if (bridge->nchildren >= TR_MAX_CHILDREN) {
        snprintf(err, errlen, "bridge '%s' has too many children",
                 bridge->name);
        return -1;
    }
    bridge->children[bridge->nchildren++] = child->slot;
    child->bridge = bridge->slot;
    return 0;
}

struct tr_iface *tr_config_ensure_vlan(struct tr_config *cfg,
                                       struct tr_iface *parent, int vlan_id,
                                       char *err, size_t errlen)
{
    char name[64];
    struct tr_iface *vlan;

    if (!parent || parent->kind != TR_IF_ETHERNET) {
        snprintf(err, errlen, "vlan-id requires an ethernet interface");
        return NULL;
    }
    if (vlan_id < 1 || vlan_id > 4094) {
        snprintf(err, errlen, "VLAN ID must be 1..4094");
        return NULL;
    }
    snprintf(name, sizeof(name), "%s.%d", parent->name, vlan_id);
    if (strlen(name) >= TR_IFNAME_LEN) {
        snprintf(err, errlen, "VLAN interface name is too long");
        return NULL;
    }
    vlan = tr_config_find(cfg, name);
    if (vlan) {
        if (vlan->kind != TR_IF_VLAN || vlan->parent != parent->slot) {
            snprintf(err, errlen, "interface '%s' already exists", name);
            return NULL;
        }
        return vlan;
    }
    vlan = tr_config_create(cfg, name, TR_IF_VLAN, err, errlen);
    if (!vlan)
        return NULL;
    vlan->parent = parent->slot;
    vlan->vlan_id = vlan_id;
    vlan->mtu = parent->mtu;
    return vlan;
}

struct tr_iface *tr_config_ensure_bridge(struct tr_config *cfg,
                                         const char *name, char *err,
                                         size_t errlen)
{
    struct tr_iface *br = tr_config_find(cfg, name);

    if (br) {
        if (br->kind != TR_IF_BRIDGE) {
            snprintf(err, errlen, "interface '%s' is not a bridge", name);
            return NULL;
        }
        return br;
    }
    return tr_config_create(cfg, name, TR_IF_BRIDGE, err, errlen);
}

int tr_config_add_ethernet(struct tr_config *cfg, const char *name, int port_id,
                           uint8_t mac[6])
{
    char err[128];
    struct tr_iface *iface = tr_config_find(cfg, name);

    if (iface) {
        if (iface->kind != TR_IF_ETHERNET)
            return -1;
    } else {
        iface = tr_config_create(cfg, name, TR_IF_ETHERNET, err,
                                 sizeof(err));
        if (!iface)
            return -1;
    }
    iface->port_id = port_id;
    if (mac)
        memcpy(iface->mac, mac, 6);
    return 0;
}

struct tr_iface *tr_config_ensure_ethernet(struct tr_config *cfg,
                                           const char *name,
                                           const struct tr_config_env *env,
                                           char *err, size_t errlen)
{
    struct tr_iface *iface = tr_config_find(cfg, name);

    if (iface) {
        if (iface->kind != TR_IF_ETHERNET) {
            snprintf(err, errlen, "interface '%s' is not ethernet", name);
            return NULL;
        }
        return iface;
    }
    iface = tr_config_create(cfg, name, TR_IF_ETHERNET, err, errlen);
    if (!iface)
        return NULL;
    (void)env;
    return iface;
}

const struct tr_iface *tr_config_bridge_of(const struct tr_config *cfg,
                                           const struct tr_iface *iface)
{
    if (!iface || iface->bridge < 0)
        return NULL;
    return tr_config_find_slot_const(cfg, iface->bridge);
}

bool tr_config_iface_has_l3(const struct tr_iface *iface)
{
    return iface && (iface->naddrs > 0 || iface->ipv6_autoconf);
}

int tr_config_add_addr(struct tr_iface *iface, const struct tr_prefix *addr,
                       char *err, size_t errlen)
{
    if (!iface || !addr || (addr->addr.family != TR_AF_INET &&
                            addr->addr.family != TR_AF_INET6)) {
        snprintf(err, errlen, "invalid address");
        return -1;
    }
    if (iface->kind == TR_IF_BRIDGE) {
        snprintf(err, errlen, "bridges are layer-2 only");
        return -1;
    }
    if (iface->bridge >= 0) {
        snprintf(err, errlen,
                 "interface '%s' is a bridge member and cannot have an L3 "
                 "address",
                 iface->name);
        return -1;
    }
    if (addr->plen == 0 || tr_ip_is_unspecified(&addr->addr) ||
        tr_ip_is_multicast(&addr->addr)) {
        snprintf(err, errlen, "invalid interface address");
        return -1;
    }
    for (int i = 0; i < iface->naddrs; i++) {
        if (tr_ip_equal(&iface->addrs[i].addr, &addr->addr)) {
            iface->addrs[i] = *addr;
            return 0;
        }
    }
    if (iface->naddrs >= TR_MAX_ADDRS) {
        snprintf(err, errlen, "too many addresses on '%s'", iface->name);
        return -1;
    }
    iface->addrs[iface->naddrs++] = *addr;
    return 0;
}

int tr_config_del_addr(struct tr_iface *iface, const struct tr_prefix *addr,
                       bool autoconf, char *err, size_t errlen)
{
    if (!iface) {
        snprintf(err, errlen, "no such interface");
        return -1;
    }
    if (autoconf) {
        iface->ipv6_autoconf = false;
        return 0;
    }
    for (int i = 0; i < iface->naddrs; i++) {
        if (tr_ip_equal(&iface->addrs[i].addr, &addr->addr) &&
            iface->addrs[i].plen == addr->plen) {
            memmove(&iface->addrs[i], &iface->addrs[i + 1],
                    (size_t)(iface->naddrs - i - 1) *
                        sizeof(iface->addrs[0]));
            iface->naddrs--;
            return 0;
        }
    }
    snprintf(err, errlen, "address not configured");
    return -1;
}

void tr_config_generate_macs(struct tr_config *cfg)
{
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        struct tr_iface *iface = &cfg->ifaces[i];
        if (iface->present && tr_mac_is_zero(iface->mac))
            tr_mac_from_name(iface->name, iface->mac);
    }
}

static bool iface_kind_supports_driver(const struct tr_iface *iface,
                                       const char *driver)
{
    bool ipv6_only = false;

    if (!iface || iface->kind != TR_IF_TUNNEL)
        return false;
    uint8_t family = TR_AF_NONE;
    if (iface->tunnel.remote.family)
        family = iface->tunnel.remote.family;
    else if (iface->tunnel.local.family)
        family = iface->tunnel.local.family;
    if (!family)
        return tr_tunnel_driver_find(driver) != NULL;
    return tr_tunnel_driver_supports(driver, family, &ipv6_only);
}

int tr_config_validate(const struct tr_config *cfg,
                       const struct tr_config_env *env, char *err,
                       size_t errlen)
{
    int port_owner[256];

    if (err && errlen)
        err[0] = '\0';
    for (int i = 0; i < 256; i++)
        port_owner[i] = -1;

    for (int i = 0; i < TR_MAX_IFACES; i++) {
        const struct tr_iface *iface = &cfg->ifaces[i];
        if (!iface->present)
            continue;
        if (!tr_config_name_valid(iface->name)) {
            snprintf(err, errlen, "invalid interface name '%s'",
                     iface->name);
            return -1;
        }
        if (iface->mtu < 68 || iface->mtu > 9000) {
            snprintf(err, errlen, "%s: MTU must be 68..9000", iface->name);
            return -1;
        }
        switch (iface->kind) {
        case TR_IF_ETHERNET:
            if (iface->port_id < 0 ||
                (env && iface->port_id >= env->n_ports) ||
                (env && env->port_valid && !env->port_valid(iface->port_id))) {
                snprintf(err, errlen, "%s: invalid DPDK port %d",
                         iface->name, iface->port_id);
                return -1;
            }
            if (iface->port_id >= 256 ||
                port_owner[iface->port_id] >= 0) {
                snprintf(err, errlen, "%s: DPDK port %d already used by %s",
                         iface->name, iface->port_id,
                         iface->port_id < 256 &&
                                 port_owner[iface->port_id] >= 0
                             ? cfg->ifaces[port_owner[iface->port_id]].name
                             : "?");
                return -1;
            }
            port_owner[iface->port_id] = i;
            break;
        case TR_IF_VLAN: {
            const struct tr_iface *parent =
                tr_config_find_slot_const(cfg, iface->parent);
            if (!parent || parent->kind != TR_IF_ETHERNET) {
                snprintf(err, errlen, "%s: missing ethernet parent",
                         iface->name);
                return -1;
            }
            if (iface->vlan_id < 1 || iface->vlan_id > 4094) {
                snprintf(err, errlen, "%s: invalid VLAN ID", iface->name);
                return -1;
            }
            break;
        }
        case TR_IF_TUNNEL:
            if (!tr_tunnel_driver_find(iface->tunnel.driver)) {
                snprintf(err, errlen, "%s: unknown encapsulation '%s'",
                         iface->name, iface->tunnel.driver);
                return -1;
            }
            if (iface->tunnel.remote.family &&
                iface->tunnel.local.family &&
                iface->tunnel.remote.family != iface->tunnel.local.family) {
                snprintf(err, errlen,
                         "%s: local-address and remote address families "
                         "differ",
                         iface->name);
                return -1;
            }
            if (!iface_kind_supports_driver(iface,
                                            iface->tunnel.driver)) {
                snprintf(err, errlen,
                         "%s: encapsulation '%s' does not support this outer "
                         "address family",
                         iface->name, iface->tunnel.driver);
                return -1;
            }
            if (iface->tunnel.local_if[0]) {
                const struct tr_iface *li =
                    tr_config_find_const(cfg, iface->tunnel.local_if);
                if (!li || (li->kind != TR_IF_ETHERNET &&
                            li->kind != TR_IF_VLAN)) {
                    snprintf(err, errlen,
                             "%s: local-interface '%s' must be ethernet or "
                             "VLAN",
                             iface->name, iface->tunnel.local_if);
                    return -1;
                }
            }
            if (iface->tunnel.tcp_mss < -1 ||
                (iface->tunnel.tcp_mss > 0 &&
                 (iface->tunnel.tcp_mss < 64 ||
                  iface->tunnel.tcp_mss > 8960))) {
                snprintf(err, errlen, "%s: invalid TCP MSS value", iface->name);
                return -1;
            }
            break;
        case TR_IF_BRIDGE:
            if (iface->nchildren > TR_MAX_CHILDREN) {
                snprintf(err, errlen, "%s: too many bridge children",
                         iface->name);
                return -1;
            }
            for (int c = 0; c < iface->nchildren; c++) {
                const struct tr_iface *child =
                    tr_config_find_slot_const(cfg, iface->children[c]);
                if (!child || child->kind == TR_IF_BRIDGE) {
                    snprintf(err, errlen, "%s: invalid bridge child",
                             iface->name);
                    return -1;
                }
                if (child->bridge != iface->slot) {
                    snprintf(err, errlen,
                             "%s: bridge membership is inconsistent for %s",
                             iface->name, child->name);
                    return -1;
                }
            }
            break;
        default:
            snprintf(err, errlen, "%s: invalid interface kind", iface->name);
            return -1;
        }

        for (int a = 0; a < iface->naddrs; a++) {
            const struct tr_prefix *addr = &iface->addrs[a];
            if ((addr->addr.family != TR_AF_INET &&
                 addr->addr.family != TR_AF_INET6) ||
                addr->plen == 0 || tr_ip_is_unspecified(&addr->addr) ||
                tr_ip_is_multicast(&addr->addr)) {
                snprintf(err, errlen, "%s: invalid address", iface->name);
                return -1;
            }
            if (iface->kind == TR_IF_BRIDGE) {
                snprintf(err, errlen, "%s: bridges cannot have addresses",
                         iface->name);
                return -1;
            }
        }
        if (tr_config_iface_has_l3(iface) && iface->bridge >= 0) {
            snprintf(err, errlen,
                     "%s: bridge member cannot have L3 configuration",
                     iface->name);
            return -1;
        }
        if (iface->ipv6_autoconf && iface->bridge >= 0) {
            snprintf(err, errlen,
                     "%s: bridge member cannot use IPv6 autoconf",
                     iface->name);
            return -1;
        }
        if (iface->bridge >= 0) {
            const struct tr_iface *br =
                tr_config_find_slot_const(cfg, iface->bridge);
            if (!br || br->kind != TR_IF_BRIDGE) {
                snprintf(err, errlen, "%s: invalid bridge membership",
                         iface->name);
                return -1;
            }
        }
    }

    for (int i = 0; i < cfg->nroutes; i++) {
        const struct tr_route *r = &cfg->routes[i];
        if (!r->has_via) {
            snprintf(err, errlen, "static route has no next hop");
            return -1;
        }
        if (r->prefix.addr.family != r->via.family ||
            r->prefix.addr.family == TR_AF_NONE) {
            char pbuf[64];
            tr_prefix_ntop(&r->prefix, pbuf, sizeof(pbuf));
            snprintf(err, errlen, "route %s: next-hop address family differs",
                     pbuf);
            return -1;
        }
        if (tr_ip_is_unspecified(&r->via)) {
            snprintf(err, errlen, "static route next hop cannot be unspecified");
            return -1;
        }
    }
    return 0;
}
