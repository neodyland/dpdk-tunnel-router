#include "test_common.h"

#include "tunnel.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>

static int try_plugin(const char *path, char *err, size_t errlen)
{
    if (access(path, R_OK) != 0)
        return -1;
    if (tr_tunnel_load_plugin(path, err, errlen))
        return -1;
    if (!tr_tunnel_driver_find("etherip6-rs"))
        return -1;
    return 0;
}

int main(void)
{
    char err[256] = {0};
    const char *env = getenv("TR_PLUGIN");
    int loaded = 0;

    if (tr_tunnel_drivers_init()) {
        fprintf(stderr, "driver init failed\n");
        return 1;
    }
    if (env && try_plugin(env, err, sizeof(err)) == 0)
        loaded = 1;
    if (!loaded && try_plugin("../build/rust/release/libtunnel_driver.so", err,
                              sizeof(err)) == 0)
        loaded = 1;
    if (!loaded && try_plugin("build/rust/release/libtunnel_driver.so", err,
                              sizeof(err)) == 0)
        loaded = 1;
    if (!loaded) {
        printf("test_plugin: skipped (libtunnel_driver.so not built)\n");
        tr_tunnel_drivers_fini();
        return 0;
    }

    struct tr_tnl_driver *d = tr_tunnel_driver_find("etherip6-rs");
    CHECK(d != NULL);
    CHECK(d->ops.encap != NULL && d->ops.decap != NULL);
    uint8_t buf[512];
    memset(buf, 0, sizeof(buf));
    for (int i = 0; i < 128; i++)
        buf[64 + i] = (uint8_t)(i * 3);
    struct tr_tnl_flow flow = {.family = 6, .hop_limit = 64};
    struct in6_addr src, dst;
    inet_pton(AF_INET6, "2001:db8::1", &src);
    inet_pton(AF_INET6, "2001:db8::2", &dst);
    memcpy(flow.src, &src, 16);
    memcpy(flow.dst, &dst, 16);
    struct tr_tnl_frame frame = {
        .base = buf, .cap = sizeof(buf), .off = 64, .len = 128};
    CHECK(d->ops.encap(d->ctx, &frame, &flow) == 0);
    CHECK(frame.off == 22);
    CHECK(frame.len == 128 + 42);
    CHECK(buf[frame.off] >> 4 == 6);
    CHECK(buf[frame.off + 6] == 97);
    CHECK(buf[frame.off + 40] == 0x30);
    CHECK(d->ops.decap(d->ctx, &frame, &flow) == 0);
    CHECK(frame.off == 64);
    CHECK(frame.len == 128);
    for (int i = 0; i < 128; i++)
        CHECK(buf[64 + i] == (uint8_t)(i * 3));
    tr_tunnel_drivers_fini();
    printf("test_plugin: ok\n");
    return 0;
}
