#include "tunnel.h"

#include "util.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(struct tr_tnl_frame) == 24, "tr_tnl_frame ABI");
_Static_assert(sizeof(struct tr_tnl_flow) == 40, "tr_tnl_flow ABI");
_Static_assert(sizeof(struct tr_tnl_driver) == 80, "tr_tnl_driver ABI");
_Static_assert(sizeof(struct tr_tnl_host_api) == 24, "tr_tnl_host_api ABI");

struct etherip_ctx {
    bool ipv6_only;
};

static struct tr_tnl_driver g_drivers[TR_TUNNEL_MAX_DRIVERS];
static int g_ndrivers;
static bool g_initialized;
static void *g_plugin_handles[8];
static int g_nplugins;

static int etherip_encap(void *ctx, struct tr_tnl_frame *f,
                         const struct tr_tnl_flow *flow)
{
    struct etherip_ctx *ec = ctx;
    uint32_t hlen;
    uint32_t newlen;
    uint32_t off;
    uint8_t *p;
    uint16_t total;

    if (!f || !flow || (flow->family != 4 && flow->family != 6))
        return -1;
    if (ec->ipv6_only && flow->family != 6)
        return -1;
    hlen = flow->family == 4 ? 20 : 40;
    if (f->off < hlen + 2)
        return -1;
    if (f->len > 65535 - hlen - 2)
        return -1;
    newlen = f->len + hlen + 2;
    off = f->off - hlen - 2;
    p = f->base + off;

    if (flow->family == 4) {
        uint16_t id = (uint16_t)(flow->tunnel_id ? flow->tunnel_id
                                                 : tr_random_u32());
        total = (uint16_t)newlen;
        memset(p, 0, 20);
        p[0] = 0x45;
        p[1] = (uint8_t)(flow->dscp & 0x3f) << 2;
        p[2] = (uint8_t)(total >> 8);
        p[3] = (uint8_t)total;
        p[4] = (uint8_t)(id >> 8);
        p[5] = (uint8_t)id;
        p[6] = 0; /* DF=0, MF=0: the core fragments if needed */
        p[7] = 0;
        p[8] = flow->hop_limit ? flow->hop_limit : 64;
        p[9] = 97;
        memcpy(p + 12, flow->src, 4);
        memcpy(p + 16, flow->dst, 4);
        uint16_t csum = tr_checksum16(p, 20, 0);
        p[10] = (uint8_t)(csum >> 8);
        p[11] = (uint8_t)csum;
    } else {
        uint16_t plen = (uint16_t)(newlen - 40);
        uint32_t vtf = (6u << 28) | ((uint32_t)flow->dscp << 22) |
                       (flow->tunnel_id & 0xfffffu);
        memset(p, 0, 40);
        p[0] = (uint8_t)(vtf >> 24);
        p[1] = (uint8_t)(vtf >> 16);
        p[2] = (uint8_t)(vtf >> 8);
        p[3] = (uint8_t)vtf;
        p[4] = (uint8_t)(plen >> 8);
        p[5] = (uint8_t)plen;
        p[6] = 97;
        p[7] = flow->hop_limit ? flow->hop_limit : 64;
        memcpy(p + 8, flow->src, 16);
        memcpy(p + 24, flow->dst, 16);
    }
    p[hlen] = 0x30; /* EtherIP version 3, reserved 0 */
    p[hlen + 1] = 0x00;

    f->off = off;
    f->len = newlen;
    return 0;
}

static int etherip_decap(void *ctx, struct tr_tnl_frame *f,
                         const struct tr_tnl_flow *flow)
{
    struct etherip_ctx *ec = ctx;
    uint8_t *p;
    uint32_t hlen;
    uint32_t inner_off;
    uint32_t inner_len;

    (void)flow;
    if (!f || f->off + f->len > f->cap)
        return -1;
    p = f->base + f->off;
    if (f->len < 20)
        return -1;
    if ((p[0] >> 4) == 4) {
        uint32_t ihl = (uint32_t)(p[0] & 0x0f) * 4;
        uint16_t total;
        if (ihl < 20 || f->len < ihl + 2 || p[9] != 97)
            return -1;
        total = (uint16_t)(p[2] << 8 | p[3]);
        if (total < ihl + 2 || total > f->len)
            return -1;
        hlen = ihl;
        inner_off = f->off + ihl + 2;
        inner_len = total - ihl - 2;
        if (ec->ipv6_only)
            return -1;
    } else if ((p[0] >> 4) == 6) {
        uint16_t plen;
        if (f->len < 40 || p[6] != 97)
            return -1;
        plen = (uint16_t)(p[4] << 8 | p[5]);
        if (plen < 2 || 40u + plen > f->len)
            return -1;
        hlen = 40;
        inner_off = f->off + 40 + 2;
        inner_len = plen - 2;
    } else {
        return -1;
    }
    if ((p[hlen] >> 4) != 3 || (p[hlen] & 0x0f) != 0 ||
        p[hlen + 1] != 0)
        return -1;
    if (inner_len < 14)
        return -1;
    f->off = inner_off;
    f->len = inner_len;
    return 0;
}

static uint32_t etherip_overhead(void *ctx, uint8_t family)
{
    (void)ctx;
    return (family == 4 ? 20u : 40u) + 2u;
}

static struct etherip_ctx g_etherip6_ctx = {.ipv6_only = true};
static struct etherip_ctx g_etherip_ctx = {.ipv6_only = false};

static const struct tr_tnl_driver g_builtins[] = {
    {
        .name = "etherip6",
        .builtin = true,
        .ipv6_only = true,
        .ctx = &g_etherip6_ctx,
        .ops = {.encap = etherip_encap,
                .decap = etherip_decap,
                .overhead = etherip_overhead},
    },
    {
        .name = "etherip",
        .builtin = true,
        .ipv6_only = false,
        .ctx = &g_etherip_ctx,
        .ops = {.encap = etherip_encap,
                .decap = etherip_decap,
                .overhead = etherip_overhead},
    },
};

int tr_tunnel_driver_register(const struct tr_tnl_driver *driver, char *err,
                              unsigned errlen)
{
    char name[sizeof(g_drivers[0].name)];
    struct tr_tnl_driver copy;

    if (!driver || !driver->ops.encap || !driver->ops.decap) {
        snprintf(err, errlen, "invalid tunnel driver descriptor");
        return -1;
    }
    size_t n = strnlen(driver->name, sizeof(driver->name));
    if (n == 0 || n >= sizeof(driver->name)) {
        snprintf(err, errlen, "invalid tunnel driver name");
        return -1;
    }
    memset(name, 0, sizeof(name));
    memcpy(name, driver->name, n);
    copy = *driver;
    memcpy(copy.name, name, sizeof(name));
    driver = &copy;
    if (tr_tunnel_driver_find(driver->name)) {
        snprintf(err, errlen, "tunnel driver '%s' already registered",
                 driver->name);
        return -1;
    }
    if (g_ndrivers >= TR_TUNNEL_MAX_DRIVERS) {
        snprintf(err, errlen, "tunnel driver table is full");
        return -1;
    }
    g_drivers[g_ndrivers++] = *driver;
    return 0;
}

int tr_tunnel_drivers_init(void)
{
    if (g_initialized)
        return 0;
    g_ndrivers = 0;
    g_nplugins = 0;
    for (size_t i = 0; i < TR_ARRAY_SIZE(g_builtins); i++) {
        char err[128];
        if (tr_tunnel_driver_register(&g_builtins[i], err, sizeof(err)))
            return -1;
    }
    g_initialized = true;
    return 0;
}

void tr_tunnel_drivers_fini(void)
{
    for (int i = 0; i < g_ndrivers; i++) {
        if (!g_drivers[i].builtin && g_drivers[i].ops.destroy)
            g_drivers[i].ops.destroy(g_drivers[i].ctx);
    }
    for (int i = 0; i < g_nplugins; i++) {
        if (g_plugin_handles[i])
            dlclose(g_plugin_handles[i]);
    }
    g_nplugins = 0;
    g_ndrivers = 0;
    g_initialized = false;
}

struct tr_tnl_driver *tr_tunnel_driver_find(const char *name)
{
    if (!name)
        return NULL;
    for (int i = 0; i < g_ndrivers; i++) {
        if (strcmp(g_drivers[i].name, name) == 0)
            return &g_drivers[i];
    }
    return NULL;
}

int tr_tunnel_driver_count(void)
{
    return g_ndrivers;
}

const struct tr_tnl_driver *tr_tunnel_driver_at(int index)
{
    if (index < 0 || index >= g_ndrivers)
        return NULL;
    return &g_drivers[index];
}

bool tr_tunnel_driver_supports(const char *name, uint8_t family,
                               bool *ipv6_only)
{
    struct tr_tnl_driver *d = tr_tunnel_driver_find(name);

    if (ipv6_only)
        *ipv6_only = d ? d->ipv6_only : false;
    if (!d)
        return false;
    if (family == 4)
        return !d->ipv6_only;
    if (family == 6)
        return true;
    return false;
}

uint32_t tr_tunnel_ip_overhead(uint8_t family)
{
    return (family == 4 ? 20u : 40u) + 2u;
}

static int plugin_register(const struct tr_tnl_driver *driver, char *err,
                           unsigned errlen, void *host_arg)
{
    (void)host_arg;
    return tr_tunnel_driver_register(driver, err, errlen);
}

int tr_tunnel_load_plugin(const char *path, char *err, size_t errlen)
{
    typedef int (*init_fn)(const struct tr_tnl_host_api *);
    struct tr_tnl_host_api api = {
        .abi_version = TR_TNL_PLUGIN_ABI,
        .register_driver = plugin_register,
        .host_arg = NULL,
    };
    void *handle;
    init_fn init;
    int rc;

    if (g_nplugins >= (int)TR_ARRAY_SIZE(g_plugin_handles)) {
        snprintf(err, errlen, "too many tunnel driver plugins");
        return -1;
    }
    handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        snprintf(err, errlen, "cannot load %s: %s", path, dlerror());
        return -1;
    }
    init = (init_fn)(uintptr_t)dlsym(handle, "tunnel_driver_plugin_init");
    if (!init) {
        snprintf(err, errlen, "%s: missing tunnel_driver_plugin_init",
                 path);
        dlclose(handle);
        return -1;
    }
    rc = init(&api);
    if (rc) {
        snprintf(err, errlen, "%s: plugin initialization failed (%d)", path,
                 rc);
        dlclose(handle);
        return -1;
    }
    g_plugin_handles[g_nplugins++] = handle;
    return 0;
}
