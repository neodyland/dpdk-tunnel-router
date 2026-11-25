#include "test_common.h"

#include "fib.h"

static int build(struct tr_config *cfg, struct tr_config_env *env)
{
    tr_config_init(cfg);
    env->n_ports = 4;
    const char *cmds[] = {
        "set interfaces ethernet eth0 port 0",
        "set interfaces ethernet eth0 address 10.0.0.1/24",
        "set interfaces ethernet eth1 port 1",
        "set interfaces ethernet eth1 address 192.0.2.1/24",
        "set interfaces ethernet eth1 address 2001:db8:2::2/64",
        "set protocols static route 0.0.0.0/0 via 192.0.2.254",
        "set protocols static route 172.16.0.0/12 via 10.0.0.254",
        "set protocols static route 203.0.113.0/24 via 172.16.0.1",
        "set protocols static route 2001:db8:ffff::/48 via 2001:db8:2::1",
        NULL,
    };
    for (int i = 0; cmds[i]; i++)
        if (test_apply_ok(cfg, env, cmds[i]))
            return 1;
    return 0;
}

static int check4(struct tr_fib *fib, const char *dst, const char *via,
                  const char *ifname, const struct tr_config *cfg,
                  int plen)
{
    struct tr_ip ip;
    struct tr_fib_result res;
    char buf[96];
    CHECK(tr_ip_parse(dst, &ip) == 0);
    CHECK(tr_fib_lookup(fib, &ip, &res) == 0);
    if (plen >= 0)
        CHECK(res.prefix_len == plen);
    if (via) {
        CHECK(res.route->has_via);
        tr_ip_ntop(&res.route->via, buf, sizeof(buf));
        CHECK(strcmp(buf, via) == 0);
    }
    if (ifname) {
        const struct tr_iface *iface =
            tr_config_find_slot_const(cfg, res.route->if_slot);
        CHECK(iface != NULL);
        CHECK(strcmp(iface->name, ifname) == 0);
    }
    return 0;
}

int main(void)
{
    struct tr_config cfg;
    struct tr_config_env env;
    struct tr_fib fib;
    char err[256];

    if (tr_tunnel_drivers_init())
        return 1;
    if (build(&cfg, &env))
        return 1;
    tr_fib_init(&fib);
    CHECK(tr_fib_build(&fib, &cfg, NULL, 0, err, sizeof(err)) == 0);
    CHECK(check4(&fib, "203.0.113.5", "10.0.0.254", "eth0", &cfg, 24) == 0);
    CHECK(check4(&fib, "172.16.1.1", "10.0.0.254", "eth0", &cfg, 12) == 0);
    CHECK(check4(&fib, "8.8.8.8", "192.0.2.254", "eth1", &cfg, 0) == 0);
    CHECK(check4(&fib, "10.0.0.5", NULL, "eth0", &cfg, 24) == 0);
    CHECK(check4(&fib, "198.51.100.1", "192.0.2.254", "eth1", &cfg, 0) == 0);
    CHECK(check4(&fib, "2001:db8:ffff::1", "2001:db8:2::1", "eth1", &cfg,
                 48) == 0);
    tr_fib_destroy(&fib);
    tr_tunnel_drivers_fini();
    printf("test_fib: ok\n");
    return 0;
}
