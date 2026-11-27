#ifndef TR_CONFIG_H
#define TR_CONFIG_H

#include "addr.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TR_MAX_IFACES 64
#define TR_MAX_ADDRS 8
#define TR_MAX_ROUTES 512
#define TR_MAX_CHILDREN 32
#define TR_IFNAME_LEN 48
#define TR_DRIVER_LEN 32

enum tr_if_kind {
    TR_IF_ETHERNET = 1,
    TR_IF_VLAN,
    TR_IF_TUNNEL,
    TR_IF_BRIDGE,
};

struct tr_tunnel_cfg {
    char driver[TR_DRIVER_LEN];
    struct tr_ip remote;
    struct tr_ip local;
    char local_if[TR_IFNAME_LEN];
    int tcp_mss; /* -1 = disabled, 0 = auto, > 0 = fixed MSS */
};

struct tr_iface {
    int slot;
    char name[TR_IFNAME_LEN];
    enum tr_if_kind kind;
    bool present;
    uint32_t mtu;

    int port_id;   /* ethernet */
    int vlan_id;   /* vlan C-tag, or single tag */
    int vlan_outer; /* 802.1ad S-tag, -1 for a single-tagged VLAN */
    int parent;    /* vlan parent slot */

    struct tr_prefix addrs[TR_MAX_ADDRS];
    int naddrs;
    bool ipv6_autoconf;
    uint8_t mac[6];

    struct tr_tunnel_cfg tunnel;

    int children[TR_MAX_CHILDREN];
    int nchildren;
    int bridge; /* member's bridge slot, -1 if none */
};

struct tr_route {
    struct tr_prefix prefix;
    struct tr_ip via;
    bool has_via;
    bool connected;
    int if_slot;      /* connected route / resolved static egress */
    int route_id;
};

struct tr_config {
    uint64_t generation;
    int next_slot;
    int next_route_id;
    struct tr_iface ifaces[TR_MAX_IFACES];
    int nifaces;
    struct tr_route routes[TR_MAX_ROUTES];
    int nroutes;
};

struct tr_config_env {
    int n_ports;
    bool (*port_valid)(int port_id);
    const char **port_names; /* optional, for diagnostics */
};

void tr_config_init(struct tr_config *cfg);
void tr_config_copy(struct tr_config *dst, const struct tr_config *src);

struct tr_iface *tr_config_find(struct tr_config *cfg, const char *name);
const struct tr_iface *tr_config_find_const(const struct tr_config *cfg,
                                            const char *name);
struct tr_iface *tr_config_find_slot(struct tr_config *cfg, int slot);
const struct tr_iface *tr_config_find_slot_const(const struct tr_config *cfg,
                                                 int slot);
struct tr_iface *tr_config_create(struct tr_config *cfg, const char *name,
                                  enum tr_if_kind kind, char *err,
                                  size_t errlen);
int tr_config_del_iface(struct tr_config *cfg, struct tr_iface *iface,
                        char *err, size_t errlen);

int tr_config_add_ethernet(struct tr_config *cfg, const char *name, int port_id,
                           uint8_t mac[6]);
struct tr_iface *tr_config_ensure_vlan(struct tr_config *cfg,
                                       struct tr_iface *parent, int vlan_id,
                                       char *err, size_t errlen);
struct tr_iface *tr_config_ensure_qinq(struct tr_config *cfg,
                                       struct tr_iface *parent, int outer,
                                       int inner, char *err, size_t errlen);
struct tr_iface *tr_config_ensure_bridge(struct tr_config *cfg,
                                         const char *name, char *err,
                                         size_t errlen);

int tr_config_apply(struct tr_config *cfg, const struct tr_config_env *env,
                    int argc, char **argv, char *err, size_t errlen);
int tr_config_serialize(const struct tr_config *cfg, char **out);
const struct tr_iface *tr_config_bridge_of(const struct tr_config *cfg,
                                           const struct tr_iface *iface);
bool tr_config_iface_has_l3(const struct tr_iface *iface);
void tr_config_generate_macs(struct tr_config *cfg);

/* show helpers: all return 0 and allocate *out (caller frees). */
int tr_config_show(const struct tr_config *cfg, int argc, char **argv,
                   char **out);
int tr_config_save(const struct tr_config *cfg, const char *path,
                   char *err, size_t errlen);
int tr_config_load(struct tr_config *cfg, const struct tr_config_env *env,
                   const char *path, char *err, size_t errlen);

void tr_config_format_addr(const struct tr_ip *ip, char *buf, size_t len);
void tr_config_format_iface(const struct tr_iface *iface, char *buf,
                            size_t len);

#endif
