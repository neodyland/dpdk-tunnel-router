#include "config_internal.h"

#include "tunnel.h"
#include "util.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int errf(char *err, size_t errlen, const char *fmt, ...)
{
    if (err && errlen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, errlen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

static bool env_port_ok(const struct tr_config_env *env, int port)
{
    if (port < 0 || port > 255)
        return false;
    if (!env)
        return true;
    if (env->n_ports > 0 && port >= env->n_ports)
        return false;
    if (env->port_valid && !env->port_valid(port))
        return false;
    return true;
}

static int parse_mtu(const char *s, uint32_t *out, char *err, size_t errlen)
{
    if (tr_parse_u32(s, 68, 9000, out))
        return errf(err, errlen, "MTU must be 68..9000");
    return 0;
}

static int parse_autoconf(struct tr_config *cfg, struct tr_iface *iface,
                          bool on, char *err, size_t errlen)
{
    (void)cfg;
    if (!iface)
        return errf(err, errlen, "no such interface");
    if (iface->kind == TR_IF_BRIDGE)
        return errf(err, errlen, "bridges cannot use IPv6 autoconf");
    if (iface->bridge >= 0)
        return errf(err, errlen,
                    "bridge member '%s' cannot use IPv6 autoconf",
                    iface->name);
    iface->ipv6_autoconf = on;
    return 0;
}

static int add_address(struct tr_config *cfg, struct tr_iface *iface,
                       int argc, char **argv, int *idx, char *err,
                       size_t errlen)
{
    int i = *idx;

    if (i >= argc)
        return errf(err, errlen, "address requires a value");
    if (strcmp(argv[i], "ipv6") == 0 && i + 1 < argc &&
        strcmp(argv[i + 1], "autoconf") == 0) {
        *idx = i + 2;
        return parse_autoconf(cfg, iface, true, err, errlen);
    }
    if (strcmp(argv[i], "autoconf") == 0) {
        *idx = i + 1;
        return parse_autoconf(cfg, iface, true, err, errlen);
    }
    struct tr_prefix addr;
    if (tr_prefix_parse_host(argv[i], &addr))
        return errf(err, errlen, "invalid address '%s'", argv[i]);
    *idx = i + 1;
    return tr_config_add_addr(iface, &addr, err, errlen);
}

static int del_address(struct tr_iface *iface, int argc, char **argv, int *idx,
                       char *err, size_t errlen)
{
    int i = *idx;

    if (i >= argc)
        return errf(err, errlen, "address requires a value");
    if (strcmp(argv[i], "ipv6") == 0 && i + 1 < argc &&
        strcmp(argv[i + 1], "autoconf") == 0) {
        *idx = i + 2;
        return tr_config_del_addr(iface, NULL, true, err, errlen);
    }
    if (strcmp(argv[i], "autoconf") == 0) {
        *idx = i + 1;
        return tr_config_del_addr(iface, NULL, true, err, errlen);
    }
    struct tr_prefix addr;
    if (tr_prefix_parse_host(argv[i], &addr))
        return errf(err, errlen, "invalid address '%s'", argv[i]);
    *idx = i + 1;
    return tr_config_del_addr(iface, &addr, false, err, errlen);
}

static int set_tunnel(struct tr_config *cfg, const struct tr_config_env *env,
                      int argc, char **argv, char *err, size_t errlen)
{
    struct tr_iface *iface;
    const char *name;
    int i = 4;

    (void)env;
    if (argc < 4)
        return errf(err, errlen, "set interfaces tunnel <name> ...");
    name = argv[3];
    iface = tr_config_find(cfg, name);
    if (iface && iface->kind != TR_IF_TUNNEL)
        return errf(err, errlen, "interface '%s' is not a tunnel", name);
    if (!iface) {
        iface = tr_config_create(cfg, name, TR_IF_TUNNEL, err, errlen);
        if (!iface)
            return -1;
    }

    while (i < argc) {
        const char *op = argv[i++];
        if (strcmp(op, "remote") == 0) {
            if (i >= argc)
                return errf(err, errlen, "remote requires an address");
            struct tr_ip ip;
            if (tr_ip_parse(argv[i], &ip))
                return errf(err, errlen, "invalid remote address '%s'",
                            argv[i]);
            iface->tunnel.remote = ip;
            i++;
        } else if (strcmp(op, "local-address") == 0) {
            if (i >= argc)
                return errf(err, errlen, "local-address requires an address");
            struct tr_ip ip;
            if (tr_ip_parse(argv[i], &ip))
                return errf(err, errlen, "invalid local address '%s'",
                            argv[i]);
            iface->tunnel.local = ip;
            i++;
        } else if (strcmp(op, "local-interface") == 0) {
            if (i >= argc)
                return errf(err, errlen,
                            "local-interface requires an interface name");
            if (!tr_config_name_valid(argv[i]))
                return errf(err, errlen, "invalid interface name '%s'",
                            argv[i]);
            snprintf(iface->tunnel.local_if, sizeof(iface->tunnel.local_if),
                     "%s", argv[i]);
            i++;
        } else if (strcmp(op, "mtu") == 0) {
            if (i >= argc)
                return errf(err, errlen, "mtu requires a value");
            if (parse_mtu(argv[i], &iface->mtu, err, errlen))
                return -1;
            i++;
        } else if (strcmp(op, "encapsulation") == 0) {
            if (i >= argc)
                return errf(err, errlen, "encapsulation requires a value");
            if (!tr_tunnel_driver_find(argv[i]))
                return errf(err, errlen, "unknown encapsulation '%s'",
                            argv[i]);
            snprintf(iface->tunnel.driver, sizeof(iface->tunnel.driver), "%s",
                     argv[i]);
            i++;
        } else if (strcmp(op, "tcp-mss") == 0) {
            if (i >= argc)
                return errf(err, errlen, "tcp-mss requires a value");
            if (strcmp(argv[i], "auto") == 0) {
                iface->tunnel.tcp_mss = 0;
            } else if (strcmp(argv[i], "none") == 0 ||
                       strcmp(argv[i], "off") == 0 ||
                       strcmp(argv[i], "disabled") == 0) {
                iface->tunnel.tcp_mss = -1;
            } else {
                uint32_t v;
                if (tr_parse_u32(argv[i], 64, 8960, &v))
                    return errf(err, errlen,
                                "tcp-mss must be auto, none, or 64..8960");
                iface->tunnel.tcp_mss = (int)v;
            }
            i++;
        } else if (strcmp(op, "address") == 0) {
            if (add_address(cfg, iface, argc, argv, &i, err, errlen))
                return -1;
        } else {
            return errf(err, errlen, "unknown tunnel property '%s'", op);
        }
    }
    return 0;
}

static int port_from_eth_name(const char *name, int nports, int *port)
{
    const char *p;
    uint32_t v;

    if (strncmp(name, "eth", 3) != 0)
        return -1;
    p = name + 3;
    if (!*p)
        return -1;
    for (const char *q = p; *q; q++) {
        if (*q < '0' || *q > '9')
            return -1;
    }
    if (tr_parse_u32(p, 0, 255, &v))
        return -1;
    if (nports > 0 && (int)v >= nports)
        return -1;
    *port = (int)v;
    return 0;
}

static int set_ethernet(struct tr_config *cfg, const struct tr_config_env *env,
                        int argc, char **argv, char *err, size_t errlen)
{
    struct tr_iface *iface;
    struct tr_iface *target;
    const char *name;
    int i = 4;

    if (argc < 4)
        return errf(err, errlen, "set interfaces ethernet <name> ...");
    name = argv[3];
    iface = tr_config_find(cfg, name);
    if (iface && iface->kind != TR_IF_ETHERNET)
        return errf(err, errlen, "interface '%s' is not ethernet", name);
    if (!iface) {
        int inferred = -1;
        if (i < argc && strcmp(argv[i], "port") == 0) {
            iface = tr_config_create(cfg, name, TR_IF_ETHERNET, err, errlen);
            if (!iface)
                return -1;
        } else if (port_from_eth_name(name,
                                      env ? env->n_ports : -1,
                                      &inferred) == 0 &&
                   env_port_ok(env, inferred)) {
            /* `eth0` maps to DPDK port 0 automatically. */
            iface = tr_config_create(cfg, name, TR_IF_ETHERNET, err, errlen);
            if (!iface)
                return -1;
            iface->port_id = inferred;
        } else {
            return errf(err, errlen,
                        "unknown ethernet interface '%s' (use eth<DPDK port> "
                        "or 'set interfaces ethernet %s port <id>')",
                        name, name);
        }
    }
    target = iface;

    while (i < argc) {
        const char *op = argv[i++];
        if (strcmp(op, "port") == 0) {
            uint32_t port;
            if (i >= argc)
                return errf(err, errlen, "port requires a value");
            if (tr_parse_u32(argv[i], 0, 255, &port))
                return errf(err, errlen, "invalid DPDK port '%s'", argv[i]);
            if (!env_port_ok(env, (int)port))
                return errf(err, errlen, "DPDK port %u is not available",
                            port);
            iface->port_id = (int)port;
            i++;
        } else if (strcmp(op, "mtu") == 0) {
            if (i >= argc)
                return errf(err, errlen, "mtu requires a value");
            if (parse_mtu(argv[i], &target->mtu, err, errlen))
                return -1;
            i++;
        } else if (strcmp(op, "address") == 0) {
            if (add_address(cfg, target, argc, argv, &i, err, errlen))
                return -1;
        } else if (strcmp(op, "vlan-id") == 0) {
            uint32_t vid;
            if (i >= argc)
                return errf(err, errlen, "vlan-id requires a value");
            if (tr_parse_u32(argv[i], 1, 4094, &vid))
                return errf(err, errlen, "VLAN ID must be 1..4094");
            i++;
            target = tr_config_ensure_vlan(cfg, iface, (int)vid, err, errlen);
            if (!target)
                return -1;
        } else {
            return errf(err, errlen, "unknown ethernet property '%s'", op);
        }
    }
    return 0;
}

static int set_bridge(struct tr_config *cfg, const struct tr_config_env *env,
                      int argc, char **argv, char *err, size_t errlen)
{
    struct tr_iface *bridge;
    const char *name;
    int i = 4;

    (void)env;
    if (argc < 4)
        return errf(err, errlen, "set interfaces bridge <name> ...");
    name = argv[3];
    bridge = tr_config_ensure_bridge(cfg, name, err, errlen);
    if (!bridge)
        return -1;

    while (i < argc) {
        const char *op = argv[i++];
        if (strcmp(op, "children") == 0) {
            if (i >= argc)
                return errf(err, errlen, "children requires an interface");
            struct tr_iface *child = tr_config_find(cfg, argv[i]);
            if (!child)
                return errf(err, errlen, "unknown interface '%s'", argv[i]);
            if (tr_config_add_child(cfg, bridge, child, err, errlen))
                return -1;
            i++;
        } else if (strcmp(op, "mtu") == 0) {
            if (i >= argc)
                return errf(err, errlen, "mtu requires a value");
            if (parse_mtu(argv[i], &bridge->mtu, err, errlen))
                return -1;
            i++;
        } else {
            return errf(err, errlen, "unknown bridge property '%s'", op);
        }
    }
    return 0;
}

static int add_route(struct tr_config *cfg, const struct tr_prefix *prefix,
                     const struct tr_ip *via, char *err, size_t errlen)
{
    struct tr_route *route = NULL;

    if (prefix->addr.family != via->family)
        return errf(err, errlen,
                    "route and next-hop address families differ");
    for (int i = 0; i < cfg->nroutes; i++) {
        if (cfg->routes[i].prefix.addr.family == prefix->addr.family &&
            cfg->routes[i].prefix.plen == prefix->plen &&
            tr_ip_equal(&cfg->routes[i].prefix.addr, &prefix->addr)) {
            route = &cfg->routes[i];
            break;
        }
    }
    if (!route) {
        if (cfg->nroutes >= TR_MAX_ROUTES)
            return errf(err, errlen, "static route table is full");
        route = &cfg->routes[cfg->nroutes++];
        memset(route, 0, sizeof(*route));
        route->prefix = *prefix;
        route->route_id = cfg->next_route_id++;
        route->if_slot = -1;
    }
    route->via = *via;
    route->has_via = true;
    route->connected = false;
    return 0;
}

static int set_route(struct tr_config *cfg, int argc, char **argv, char *err,
                     size_t errlen)
{
    struct tr_prefix prefix;
    struct tr_ip via;

    if (argc != 7 || strcmp(argv[3], "route") != 0)
        return errf(err, errlen,
                    "set protocols static route <prefix> via <address>");
    if (strcmp(argv[5], "via") != 0 && strcmp(argv[5], "next-hop") != 0)
        return errf(err, errlen, "expected 'via <address>'");
    if (tr_prefix_parse(argv[4], &prefix))
        return errf(err, errlen, "invalid route prefix '%s'", argv[4]);
    if (tr_ip_parse(argv[6], &via))
        return errf(err, errlen, "invalid next hop '%s'", argv[6]);
    return add_route(cfg, &prefix, &via, err, errlen);
}

static int apply_set(struct tr_config *cfg, const struct tr_config_env *env,
                     int argc, char **argv, char *err, size_t errlen)
{
    if (argc < 2)
        return errf(err, errlen, "missing configuration path");
    if (strcmp(argv[1], "interfaces") == 0) {
        if (argc < 3)
            return errf(err, errlen, "missing interface type");
        if (strcmp(argv[2], "tunnel") == 0)
            return set_tunnel(cfg, env, argc, argv, err, errlen);
        if (strcmp(argv[2], "ethernet") == 0)
            return set_ethernet(cfg, env, argc, argv, err, errlen);
        if (strcmp(argv[2], "bridge") == 0)
            return set_bridge(cfg, env, argc, argv, err, errlen);
        return errf(err, errlen, "unknown interface type '%s'", argv[2]);
    }
    if (strcmp(argv[1], "protocols") == 0) {
        if (argc >= 4 && strcmp(argv[2], "static") == 0 &&
            strcmp(argv[3], "route") == 0)
            return set_route(cfg, argc, argv, err, errlen);
        return errf(err, errlen, "unknown protocols command");
    }
    return errf(err, errlen, "unknown configuration path '%s'", argv[1]);
}

static int delete_iface(struct tr_config *cfg, int argc, char **argv,
                        char *err, size_t errlen)
{
    struct tr_iface *iface;
    const char *name;

    if (argc < 4)
        return errf(err, errlen, "missing interface name");
    name = argv[3];
    iface = tr_config_find(cfg, name);
    if (!iface)
        return errf(err, errlen, "unknown interface '%s'", name);

    if (argc == 4)
        return tr_config_del_iface(cfg, iface, err, errlen);

    const char *op = argv[4];
    if (strcmp(op, "vlan-id") == 0) {
        uint32_t vid;
        if (argc < 6)
            return errf(err, errlen, "vlan-id requires a value");
        if (tr_parse_u32(argv[5], 1, 4094, &vid))
            return errf(err, errlen, "VLAN ID must be 1..4094");
        char child_name[TR_IFNAME_LEN];
        snprintf(child_name, sizeof(child_name), "%s.%u", name, vid);
        struct tr_iface *child = tr_config_find(cfg, child_name);
        if (!child)
            return errf(err, errlen, "VLAN interface '%s' does not exist",
                        child_name);
        if (argc == 6)
            return tr_config_del_iface(cfg, child, err, errlen);
        if (strcmp(argv[6], "address") == 0)
            return del_address(child, argc, argv, &(int){7}, err, errlen);
        return errf(err, errlen, "unknown VLAN delete operation");
    }
    if (strcmp(op, "address") == 0)
        return del_address(iface, argc, argv, &(int){5}, err, errlen);
    if (strcmp(op, "children") == 0 && iface->kind == TR_IF_BRIDGE) {
        if (argc < 6)
            return errf(err, errlen, "children requires an interface");
        struct tr_iface *child = tr_config_find(cfg, argv[5]);
        if (!child)
            return errf(err, errlen, "unknown interface '%s'", argv[5]);
        if (child->bridge != iface->slot)
            return errf(err, errlen, "interface '%s' is not a child of '%s'",
                        child->name, iface->name);
        tr_config_detach_bridge(cfg, child);
        return 0;
    }
    return errf(err, errlen, "unknown delete operation '%s'", op);
}

static int apply_delete(struct tr_config *cfg, int argc, char **argv,
                        char *err, size_t errlen)
{
    if (argc < 2)
        return errf(err, errlen, "missing configuration path");
    if (strcmp(argv[1], "interfaces") == 0) {
        if (argc >= 3 && strcmp(argv[2], "ethernet") == 0)
            return delete_iface(cfg, argc, argv, err, errlen);
        if (argc >= 3 && strcmp(argv[2], "tunnel") == 0)
            return delete_iface(cfg, argc, argv, err, errlen);
        if (argc >= 3 && strcmp(argv[2], "bridge") == 0)
            return delete_iface(cfg, argc, argv, err, errlen);
        return errf(err, errlen, "unknown interface type");
    }
    if (strcmp(argv[1], "protocols") == 0) {
        if (argc >= 4 && strcmp(argv[2], "static") == 0 &&
            strcmp(argv[3], "route") == 0) {
            if (argc != 5)
                return errf(err, errlen,
                            "delete protocols static route <prefix>");
            struct tr_prefix prefix;
            if (tr_prefix_parse(argv[4], &prefix))
                return errf(err, errlen, "invalid route prefix '%s'",
                            argv[4]);
            for (int i = 0; i < cfg->nroutes; i++) {
                if (cfg->routes[i].prefix.addr.family ==
                        prefix.addr.family &&
                    cfg->routes[i].prefix.plen == prefix.plen &&
                    tr_ip_equal(&cfg->routes[i].prefix.addr,
                                &prefix.addr)) {
                    memmove(&cfg->routes[i], &cfg->routes[i + 1],
                            (size_t)(cfg->nroutes - i - 1) *
                                sizeof(cfg->routes[0]));
                    cfg->nroutes--;
                    return 0;
                }
            }
            return errf(err, errlen, "route not found");
        }
        return errf(err, errlen, "unknown protocols delete command");
    }
    return errf(err, errlen, "unknown configuration path '%s'", argv[1]);
}

int tr_config_apply(struct tr_config *cfg, const struct tr_config_env *env,
                    int argc, char **argv, char *err, size_t errlen)
{
    int rc;

    if (!cfg || argc <= 0 || !argv)
        return errf(err, errlen, "empty command");
    if (strcmp(argv[0], "set") == 0)
        rc = apply_set(cfg, env, argc, argv, err, errlen);
    else if (strcmp(argv[0], "delete") == 0)
        rc = apply_delete(cfg, argc, argv, err, errlen);
    else
        return errf(err, errlen, "not a configuration command");
    if (rc)
        return rc;
    tr_config_generate_macs(cfg);
    return tr_config_validate(cfg, env, err, errlen);
}
