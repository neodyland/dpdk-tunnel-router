#ifndef TR_TUNNEL_H
#define TR_TUNNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TR_TUNNEL_MAX_DRIVERS 16

/*
 * Tunnel driver ABI.
 *
 * A frame is a contiguous byte buffer.  For encapsulation `off` points at the
 * inner Ethernet frame and the driver may move `off` backwards (into reserved
 * headroom) and grow `len` to build the outer packet.  For decapsulation `off`
 * points at the outer IP header; the driver validates it and advances `off` /
 * shrinks `len` to the inner Ethernet frame.
 *
 * The ABI is deliberately independent of DPDK mbufs so the same driver can be
 * implemented in C or in the Rust `tunnel-driver` crate.
 */
struct tr_tnl_frame {
    uint8_t *base;
    uint32_t cap;
    uint32_t off;
    uint32_t len;
};

struct tr_tnl_flow {
    uint8_t family; /* 4 or 6 */
    uint8_t src[16];
    uint8_t dst[16];
    uint8_t hop_limit;
    uint8_t dscp;
    uint32_t tunnel_id;
};

struct tr_tnl_driver_ops {
    int (*encap)(void *ctx, struct tr_tnl_frame *frame,
                 const struct tr_tnl_flow *flow);
    int (*decap)(void *ctx, struct tr_tnl_frame *frame,
                 const struct tr_tnl_flow *flow);
    uint32_t (*overhead)(void *ctx, uint8_t family);
    void (*destroy)(void *ctx);
};

struct tr_tnl_driver {
    char name[32];
    bool builtin;
    bool ipv6_only;
    void *ctx;
    struct tr_tnl_driver_ops ops;
};

int tr_tunnel_drivers_init(void);
void tr_tunnel_drivers_fini(void);
struct tr_tnl_driver *tr_tunnel_driver_find(const char *name);
int tr_tunnel_driver_register(const struct tr_tnl_driver *driver,
                              char *err, unsigned errlen);
int tr_tunnel_driver_count(void);
const struct tr_tnl_driver *tr_tunnel_driver_at(int index);

#define TR_TNL_PLUGIN_ABI 1
struct tr_tnl_host_api {
    uint32_t abi_version;
    int (*register_driver)(const struct tr_tnl_driver *driver, char *err,
                           unsigned errlen, void *host_arg);
    void *host_arg;
};

int tr_tunnel_load_plugin(const char *path, char *err, size_t errlen);
bool tr_tunnel_driver_supports(const char *name, uint8_t family,
                               bool *ipv6_only);

uint32_t tr_tunnel_ip_overhead(uint8_t family);

#endif
