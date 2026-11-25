#include "test_common.h"

#include "help.h"

#include <stdlib.h>

static const char *commands[] = {
    "set interfaces ethernet eth0 port 0",
    "set interfaces ethernet eth0 mtu 1500",
    "set interfaces ethernet eth0 address 192.0.2.1/24",
    "set interfaces ethernet eth0 address 2001:db8:1::1/64",
    "set interfaces ethernet eth1 port 1",
    "set interfaces ethernet eth1 mtu 1400",
    "set interfaces ethernet eth0 vlan-id 10 mtu 1400",
    "set interfaces ethernet eth0 vlan-id 10 address 192.168.10.1/24",
    "set interfaces bridge br0 children eth1",
    "set interfaces bridge br0 mtu 1400",
    "set interfaces tunnel tun0 encapsulation etherip6",
    "set interfaces tunnel tun0 remote 2001:db8:2::2",
    "set interfaces tunnel tun0 local-address 2001:db8:2::1",
    "set interfaces tunnel tun0 local-interface eth0",
    "set interfaces tunnel tun0 mtu 9000",
    "set interfaces tunnel tun0 tcp-mss auto",
    "set interfaces tunnel tun0 address 10.0.0.1/30",
    "set protocols static route 0.0.0.0/0 via 192.0.2.254",
    "set protocols static route 203.0.113.0/24 via 192.0.2.253",
    NULL,
};

static int build(struct tr_config *cfg, struct tr_config_env *env)
{
    tr_config_init(cfg);
    env->n_ports = 4;
    env->port_valid = NULL;
    env->port_names = NULL;
    for (int i = 0; commands[i]; i++)
        if (test_apply_ok(cfg, env, commands[i]))
            return 1;
    return 0;
}

static int test_parse_and_serialize(void)
{
    struct tr_config cfg;
    struct tr_config_env env;
    struct tr_config copy;
    char *text = NULL;
    char err[256];

    if (build(&cfg, &env))
        return 1;
    const struct tr_iface *eth0 = tr_config_find_const(&cfg, "eth0");
    CHECK(eth0 != NULL);
    CHECK(eth0->kind == TR_IF_ETHERNET);
    CHECK(eth0->mtu == 1500);
    CHECK(eth0->naddrs == 2);
    char a[96];
    tr_prefix_ntop(&eth0->addrs[0], a, sizeof(a));
    CHECK(strcmp(a, "192.0.2.1/24") == 0);
    tr_prefix_ntop(&eth0->addrs[1], a, sizeof(a));
    CHECK(strcmp(a, "2001:db8:1::1/64") == 0);

    const struct tr_iface *vlan = tr_config_find_const(&cfg, "eth0.10");
    CHECK(vlan != NULL && vlan->kind == TR_IF_VLAN && vlan->vlan_id == 10);
    CHECK(vlan->mtu == 1400 && vlan->naddrs == 1);

    const struct tr_iface *br = tr_config_find_const(&cfg, "br0");
    CHECK(br != NULL && br->kind == TR_IF_BRIDGE && br->nchildren == 1);
    CHECK(br->children[0] == tr_config_find_const(&cfg, "eth1")->slot);

    const struct tr_iface *tun = tr_config_find_const(&cfg, "tun0");
    CHECK(tun != NULL && tun->kind == TR_IF_TUNNEL);
    CHECK(tun->mtu == 9000);
    CHECK(strcmp(tun->tunnel.driver, "etherip6") == 0);
    CHECK(tun->tunnel.tcp_mss == 0);
    CHECK(tun->tunnel.remote.family == TR_AF_INET6);
    CHECK(tun->naddrs == 1);

    CHECK(cfg.nroutes == 2);

    /* The default driver is family-agnostic EtherIP, so a v4 remote can be
     * configured before encapsulation is explicitly set. */
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun4 remote 198.51.100.2") == 0);
    const struct tr_iface *tun4 = tr_config_find_const(&cfg, "tun4");
    CHECK(tun4 != NULL && strcmp(tun4->tunnel.driver, "etherip") == 0);
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces tunnel tun4 encapsulation etherip") == 0);

    CHECK(tr_config_serialize(&cfg, &text) == 0);
    CHECK(text != NULL);
    CHECK(strstr(text, "set interfaces ethernet eth0 port 0") != NULL);
    CHECK(strstr(text, "set interfaces ethernet eth0 vlan-id 10") != NULL);
    CHECK(strstr(text, "set interfaces bridge br0 children eth1") != NULL);
    CHECK(strstr(text, "set interfaces tunnel tun0 remote 2001:db8:2::2") != NULL);
    CHECK(strstr(text, "set protocols static route 0.0.0.0/0 via 192.0.2.254") != NULL);

    tr_config_init(&copy);
    char *parse = strdup(text);
    char *save = NULL;
    char *line = strtok_r(parse, "\n", &save);
    while (line) {
        if (*line && test_apply(&copy, &env, line, err, sizeof(err))) {
            fprintf(stderr, "round-trip failed at '%s': %s\n", line, err);
            free(parse);
            free(text);
            return 1;
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(parse);
    char *text2 = NULL;
    CHECK(tr_config_serialize(&copy, &text2) == 0);
    CHECK(strcmp(text, text2) == 0);
    free(text);
    free(text2);
    return 0;
}

static int test_rejections(void)
{
    struct tr_config cfg;
    struct tr_config_env env;
    char err[256];

    if (build(&cfg, &env))
        return 1;
    CHECK(test_apply(&cfg, &env, "set interfaces ethernet eth0 mtu 20", err,
                     sizeof(err)) != 0);
    CHECK(test_apply(&cfg, &env,
                     "set interfaces ethernet eth0 vlan-id 5000", err,
                     sizeof(err)) != 0);
    CHECK(test_apply(&cfg, &env,
                     "set interfaces tunnel tun0 remote 192.0.2.1", err,
                     sizeof(err)) != 0);
    CHECK(test_apply(&cfg, &env,
                     "set interfaces tunnel tun0 encapsulation nope", err,
                     sizeof(err)) != 0);
    CHECK(test_apply(&cfg, &env,
                     "set protocols static route 10.0.0.0/8 via 2001:db8::1",
                     err, sizeof(err)) != 0);
    CHECK(test_apply(&cfg, &env,
                     "set interfaces ethernet eth7 port 7", err,
                     sizeof(err)) != 0);
    CHECK(test_apply(&cfg, &env,
                     "set interfaces bridge br0 children tun0", err,
                     sizeof(err)) != 0);
    return 0;
}

static int test_delete(void)
{
    struct tr_config cfg;
    struct tr_config_env env;
    char err[256];

    if (build(&cfg, &env))
        return 1;
    CHECK(test_apply(&cfg, &env, "delete interfaces ethernet eth0 vlan-id 10",
                     err, sizeof(err)) == 0);
    CHECK(tr_config_find_const(&cfg, "eth0.10") == NULL);
    CHECK(test_apply(&cfg, &env, "delete interfaces bridge br0 children eth1",
                     err, sizeof(err)) == 0);
    CHECK(tr_config_find_const(&cfg, "br0")->nchildren == 0);
    CHECK(test_apply(&cfg, &env,
                     "delete protocols static route 0.0.0.0/0", err,
                     sizeof(err)) == 0);
    CHECK(cfg.nroutes == 1);
    CHECK(test_apply(&cfg, &env, "delete interfaces tunnel tun0", err,
                     sizeof(err)) == 0);
    CHECK(tr_config_find_const(&cfg, "tun0") == NULL);
    return 0;
}


static int test_empty_show(void)
{
    struct tr_config cfg;
    char *out = NULL;
    char *argv[] = {"interfaces"};

    tr_config_init(&cfg);
    CHECK(tr_config_show(&cfg, 1, argv, &out) == 0);
    CHECK(out != NULL);
    CHECK(strstr(out, "No interfaces configured.") != NULL);
    free(out);
    return 0;
}


static int test_auto_eth(void)
{
    struct tr_config cfg;
    struct tr_config_env env;
    char *out = NULL;
    char *argv[] = {"interfaces"};
    char err[256];

    tr_config_init(&cfg);
    env.n_ports = 2;
    env.port_valid = NULL;
    env.port_names = NULL;
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth1 address 198.51.100.1/24") == 0);
    const struct tr_iface *eth1 = tr_config_find_const(&cfg, "eth1");
    CHECK(eth1 != NULL);
    CHECK(eth1->port_id == 1);
    CHECK(eth1->naddrs == 1);
    CHECK(test_apply(&cfg, &env,
                     "set interfaces ethernet eth2 address 203.0.113.1/24",
                     err, sizeof(err)) != 0);
    CHECK(tr_config_show(&cfg, 1, argv, &out) == 0);
    CHECK(out != NULL && strstr(out, "eth1 (ethernet") != NULL);
    free(out);
    return 0;
}


static int test_help(void)
{
    struct tr_config cfg;
    struct tr_config_env env;
    char *out = NULL;
    char *set_argv[] = {"set", "interfaces", "ethernet", "eth1"};
    char *show_argv[] = {"show"};
    char *cap_argv[] = {"tcpdump"};
    char err[256];

    tr_config_init(&cfg);
    env.n_ports = 2;
    env.port_valid = NULL;
    env.port_names = NULL;
    CHECK(test_apply_ok(&cfg, &env,
                        "set interfaces ethernet eth1 address "
                        "198.51.100.1/24") == 0);
    CHECK(tr_help_command(&cfg, 2, true, 4, set_argv, &out) == 0);
    CHECK(out != NULL && strstr(out, "Ethernet eth1") != NULL);
    CHECK(strstr(out, "vlan-id") != NULL);
    free(out);
    out = NULL;
    CHECK(tr_help_command(&cfg, 2, false, 1, show_argv, &out) == 0);
    CHECK(out != NULL && strstr(out, "show configuration") != NULL);
    free(out);
    out = NULL;
    CHECK(tr_help_command(&cfg, 2, false, 1, cap_argv, &out) == 0);
    CHECK(out != NULL && strstr(out, "tcpdump start") != NULL);
    free(out);
    (void)err;
    return 0;
}

int main(void)
{
    if (tr_tunnel_drivers_init()) {
        fprintf(stderr, "driver init failed\n");
        return 1;
    }
    int rc = 0;
    rc |= test_parse_and_serialize();
    rc |= test_rejections();
    rc |= test_delete();
    rc |= test_empty_show();
    rc |= test_auto_eth();
    rc |= test_help();
    tr_tunnel_drivers_fini();
    if (rc == 0)
        printf("test_config: ok\n");
    return rc;
}
