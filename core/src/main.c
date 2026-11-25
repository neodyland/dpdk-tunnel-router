#include "config.h"
#include "config_internal.h"
#include "control.h"
#include "dpdk.h"
#include "engine.h"
#include "tunnel.h"
#include "util.h"

#include <rte_eal.h>
#include <rte_version.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_ether.h>

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TR_VERSION "1.0.0"
#define TR_POOL_SIZE 8192
#define TR_PKT_ROOM 10240

struct app {
    struct tr_engine *engine;
    struct tr_dpdk *dpdk;
    struct tr_control *control;
    struct tr_config cfg;
    struct tr_config_env env;
    char config_path[256];
    char sock_path[160];
    int workers;
    int nports;
    bool persist;
};

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void mkdir_parent(const char *path)
{
    char tmp[256];
    char *slash;

    snprintf(tmp, sizeof(tmp), "%s", path);
    slash = strrchr(tmp, '/');
    if (!slash || slash == tmp)
        return;
    *slash = '\0';
    char *p = tmp;
    while (*p) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
        p++;
    }
    mkdir(tmp, 0755);
}

static void apply_port_macs(struct tr_config *cfg, int nports)
{
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        struct tr_iface *iface = &cfg->ifaces[i];
        if (!iface->present)
            continue;
        if (iface->kind == TR_IF_ETHERNET && iface->port_id >= 0 &&
            iface->port_id < nports) {
            struct rte_ether_addr ea;
            rte_eth_macaddr_get((uint16_t)iface->port_id, &ea);
            memcpy(iface->mac, ea.addr_bytes, 6);
        }
    }
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        struct tr_iface *iface = &cfg->ifaces[i];
        if (iface->present && iface->kind == TR_IF_VLAN) {
            const struct tr_iface *parent =
                tr_config_find_slot_const(cfg, iface->parent);
            if (parent)
                memcpy(iface->mac, parent->mac, 6);
        }
    }
}

static int prepare_config(struct app *a, const char *path, char *err,
                          size_t errlen)
{
    char *data = NULL;
    size_t len = 0;
    bool have_file = false;
    bool used[256] = {false};
    struct tr_config *cfg = &a->cfg;

    tr_config_init(cfg);
    a->env.n_ports = a->nports;
    a->env.port_valid = NULL;
    a->env.port_names = NULL;

    if (tr_read_file(path, &data, &len) == 0) {
        have_file = len > 0;
        char *save = NULL;
        char *line;
        for (line = strtok_r(data, "\n", &save); line;
             line = strtok_r(NULL, "\n", &save)) {
            char *argsv[32];
            char *trimmed = tr_trim(line);
            int argc;
            uint32_t port;
            if (!*trimmed || *trimmed == '#')
                continue;
            argc = tr_split(trimmed, argsv, (int)TR_ARRAY_SIZE(argsv));
            if (argc == 6 && strcmp(argsv[0], "set") == 0 &&
                strcmp(argsv[1], "interfaces") == 0 &&
                strcmp(argsv[2], "ethernet") == 0 &&
                strcmp(argsv[4], "port") == 0 &&
                tr_parse_u32(argsv[5], 0, 255, &port) == 0 &&
                (int)port < a->nports) {
                if (!tr_config_find(cfg, argsv[3])) {
                    if (!tr_config_create(cfg, argsv[3], TR_IF_ETHERNET, err,
                                          errlen)) {
                        free(data);
                        return -1;
                    }
                }
                struct tr_iface *iface = tr_config_find(cfg, argsv[3]);
                if (!iface) {
                    snprintf(err, errlen, "cannot create interface");
                    free(data);
                    return -1;
                }
                iface->port_id = (int)port;
                used[port] = true;
            }
        }
        free(data);
        data = NULL;
    }

    if (!have_file) {
        for (int p = 0; p < a->nports; p++) {
            char name[32];
            snprintf(name, sizeof(name), "eth%d", p);
            if (tr_config_add_ethernet(cfg, name, p, NULL)) {
                snprintf(err, errlen, "cannot create %s", name);
                return -1;
            }
            used[p] = true;
        }
    } else {
        for (int p = 0; p < a->nports; p++) {
            if (used[p])
                continue;
            /* Serialized configurations list every Ethernet port.  Do not
             * resurrect interfaces that were deliberately deleted. */
        }
    }

    if (have_file &&
        tr_config_load(cfg, &a->env, path, err, errlen))
        return -1;

    apply_port_macs(cfg, a->nports);
    if (tr_config_validate(cfg, &a->env, err, errlen))
        return -1;
    return 0;
}

static const char *help_text(void)
{
    return "Commands:\n"
           "  set interfaces tunnel <name> remote <ipv4|ipv6>\n"
           "  set interfaces tunnel <name> local-address <ipv4|ipv6>\n"
           "  set interfaces tunnel <name> local-interface <ifname>\n"
           "  set interfaces tunnel <name> mtu <68..9000>\n"
           "  set interfaces tunnel <name> encapsulation "
           "<etherip6|etherip|...>\n"
           "  set interfaces tunnel <name> tcp-mss <auto|none|N>\n"
           "  set interfaces tunnel <name> address "
           "<prefix|ipv6 autoconf>\n"
           "  set interfaces ethernet <name> port <dpdk-port>\n"
           "  set interfaces ethernet <name> address <prefix>\n"
           "  set interfaces ethernet <name> mtu <68..9000>\n"
           "  set interfaces ethernet <name> vlan-id <1..4094> "
           "address <prefix>\n"
           "  set interfaces ethernet <name> vlan-id <1..4094> mtu <N>\n"
           "  set interfaces bridge <name> children <ifname>\n"
           "  set interfaces bridge <name> mtu <68..9000>\n"
           "  set protocols static route <prefix> via <next-hop>\n"
           "  delete ...   (same paths, delete interfaces/routes/children)\n"
           "  show configuration | interfaces [name] | routes | neighbors\n"
           "  show bridge | statistics | tunnels | drivers | status\n"
           "  commit | help | quit\n";
}

static int control_execute(void *arg, const char *line, char **body,
                           char **error_text)
{
    struct app *a = arg;
    char *copy = strdup(line);
    char *argv[64];
    int argc;
    char err[512];
    int rc = 0;

    if (!copy) {
        *error_text = strdup("out of memory\n");
        return -1;
    }
    argc = tr_split(copy, argv, (int)TR_ARRAY_SIZE(argv));
    if (argc == 0) {
        free(copy);
        *body = strdup("");
        return 0;
    }
    err[0] = '\0';
    if (strcmp(argv[0], "show") == 0) {
        if (argc >= 2 && strcmp(argv[1], "version") == 0) {
            if (asprintf(body, "dpdk-tunnel-router %s (DPDK %s)\n",
                         TR_VERSION, rte_version()) < 0)
                rc = -1;
        } else if (argc >= 2 && strcmp(argv[1], "status") == 0) {
            char *status = NULL;
            if (tr_dpdk_status_text(a->dpdk, &status) == 0) {
                if (asprintf(body,
                             "dpdk-tunnel-router %s\n%s"
                             "tunnel drivers: %d registered\n",
                             TR_VERSION, status, tr_tunnel_driver_count()) < 0)
                    rc = -1;
                free(status);
            } else {
                rc = -1;
            }
        } else if (argc >= 2 && (strcmp(argv[1], "configuration") == 0 ||
                                 strcmp(argv[1], "running-config") == 0)) {
            if (strcmp(argv[1], "running-config") == 0)
                argv[1] = "configuration";
            rc = tr_engine_show(a->engine, argc - 1, argv + 1, body);
        } else if (argc >= 2) {
            rc = tr_engine_show(a->engine, argc - 1, argv + 1, body);
        } else {
            rc = -1;
        }
        if (rc) {
            *error_text = strdup("unknown or failed show command\n");
        }
    } else if (strcmp(argv[0], "set") == 0 ||
               strcmp(argv[0], "delete") == 0) {
        struct tr_config working, old;
        if (tr_engine_config_copy(a->engine, &old)) {
            *error_text = strdup("cannot read running configuration\n");
            rc = -1;
            goto out;
        }
        tr_config_copy(&working, &old);
        if (tr_config_apply(&working, &a->env, argc, argv, err,
                            sizeof(err))) {
            *error_text = strdup(err[0] ? err : "configuration error");
            if (*error_text) {
                size_t n = strlen(*error_text);
                *error_text = realloc(*error_text, n + 2);
                if (*error_text) {
                    (*error_text)[n] = '\n';
                    (*error_text)[n + 1] = '\0';
                }
            }
            rc = -1;
            goto out;
        }
        apply_port_macs(&working, a->nports);
        if (tr_config_validate(&working, &a->env, err, sizeof(err))) {
            if (asprintf(error_text, "%s\n", err) < 0)
                *error_text = NULL;
            rc = -1;
            goto out;
        }
        if (tr_engine_apply(a->engine, &working, err, sizeof(err))) {
            if (asprintf(error_text, "%s\n", err) < 0)
                *error_text = NULL;
            rc = -1;
            goto out;
        }
        tr_dpdk_refresh(a->dpdk);
        if (a->persist) {
            char save_err[256];
            if (tr_config_save(&working, a->config_path, save_err,
                               sizeof(save_err))) {
                /* Roll back to keep disk and data plane consistent. */
                tr_engine_apply(a->engine, &old, err, sizeof(err));
                tr_dpdk_refresh(a->dpdk);
                if (asprintf(error_text, "applied but not persisted: %s\n",
                             save_err) < 0)
                    *error_text = NULL;
                rc = -1;
                goto out;
            }
        }
        if (asprintf(body, "Committed.\n") < 0)
            rc = -1;
    } else if (strcmp(argv[0], "commit") == 0) {
        *body = strdup("Committed.\n");
    } else if (strcmp(argv[0], "help") == 0) {
        *body = strdup(help_text());
    } else if (strcmp(argv[0], "quit") == 0 ||
               strcmp(argv[0], "exit") == 0) {
        *body = strdup("Bye.\n");
    } else {
        if (asprintf(error_text, "unknown command '%s' (try 'help')\n",
                     argv[0]) < 0)
            *error_text = NULL;
        rc = -1;
    }
out:
    free(copy);
    return rc;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s <EAL args> -- [options]\n"
            "  --config PATH       running configuration (default "
            "run/running.conf)\n"
            "  --ctl-sock PATH     control socket (default run/ctl.sock)\n"
            "  --workers N         worker lcores (default 1)\n"
            "  --plugin PATH       load a Rust tunnel-driver .so\n"
            "  --no-persist        do not write the running configuration\n",
            prog);
}

int main(int argc, char **argv)
{
    struct app app = {0};
    struct tr_config_env env;
    struct tr_dpdk_params dparams;
    struct rte_mempool *mp = NULL;
    char err[512];
    int eal_ret;
    int rc = 1;

    snprintf(app.config_path, sizeof(app.config_path), "run/running.conf");
    snprintf(app.sock_path, sizeof(app.sock_path), "run/ctl.sock");
    app.workers = 1;
    app.persist = true;

    eal_ret = rte_eal_init(argc, argv);
    if (eal_ret < 0) {
        fprintf(stderr, "EAL initialization failed\n");
        return 1;
    }
    argc -= eal_ret;
    argv += eal_ret;
    if (tr_tunnel_drivers_init()) {
        fprintf(stderr, "cannot initialize tunnel drivers\n");
        goto cleanup;
    }
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            snprintf(app.config_path, sizeof(app.config_path), "%s",
                     argv[++i]);
        } else if (strcmp(argv[i], "--ctl-sock") == 0 && i + 1 < argc) {
            snprintf(app.sock_path, sizeof(app.sock_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) {
            uint32_t v;
            if (tr_parse_u32(argv[++i], 1, TR_MAX_WORKERS, &v)) {
                fprintf(stderr, "invalid --workers\n");
                goto cleanup;
            }
            app.workers = (int)v;
        } else if (strcmp(argv[i], "--plugin") == 0 && i + 1 < argc) {
            if (tr_tunnel_load_plugin(argv[++i], err, sizeof(err))) {
                fprintf(stderr, "plugin: %s\n", err);
                goto cleanup;
            }
        } else if (strcmp(argv[i], "--no-persist") == 0) {
            app.persist = false;
        } else if (strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            rc = 0;
            goto cleanup;
        } else {
            fprintf(stderr, "unknown option '%s'\n", argv[i]);
            usage(argv[0]);
            goto cleanup;
        }
    }
    mkdir_parent(app.config_path);
    mkdir_parent(app.sock_path);
    app.nports = (int)rte_eth_dev_count_avail();
    if (app.nports > 256)
        app.nports = 256;
    if (prepare_config(&app, app.config_path, err, sizeof(err))) {
        fprintf(stderr, "configuration: %s\n", err);
        goto cleanup_drivers;
    }

    mp = rte_pktmbuf_pool_create("tr_pool", TR_POOL_SIZE, 256, 0,
                                 TR_PKT_ROOM, rte_socket_id());
    if (!mp) {
        fprintf(stderr, "cannot create mbuf pool: %s\n",
                rte_strerror(rte_errno));
        goto cleanup_drivers;
    }
    app.engine = tr_engine_create(
        &(struct tr_engine_params){.n_ports = app.nports,
                                   .workers = app.workers,
                                   .mp = mp},
        err, sizeof(err));
    if (!app.engine) {
        fprintf(stderr, "engine: %s\n", err);
        rte_mempool_free(mp);
        goto cleanup_drivers;
    }
    if (tr_engine_apply(app.engine, &app.cfg, err, sizeof(err))) {
        fprintf(stderr, "apply: %s\n", err);
        goto cleanup_engine;
    }
    tr_engine_config_env(app.engine, &env);
    app.env = env;

    dparams.workers = app.workers;
    dparams.mp = mp;
    app.dpdk = tr_dpdk_create(app.engine, &dparams, err, sizeof(err));
    if (!app.dpdk) {
        fprintf(stderr, "dpdk: %s\n", err);
        goto cleanup_engine;
    }
    if (tr_dpdk_start(app.dpdk, err, sizeof(err))) {
        fprintf(stderr, "dpdk: %s\n", err);
        goto cleanup_dpdk;
    }
    tr_engine_send_router_solicitations(app.engine);
    if (tr_dpdk_launch_workers(app.dpdk)) {
        fprintf(stderr, "cannot launch workers\n");
        goto cleanup_dpdk;
    }

    struct tr_control_ops ops = {.execute = control_execute};
    app.control = tr_control_create(app.sock_path, &ops, &app, err,
                                    sizeof(err));
    if (!app.control) {
        fprintf(stderr, "control: %s\n", err);
        goto cleanup_dpdk;
    }

    if (app.persist && tr_config_save(&app.cfg, app.config_path, err,
                                      sizeof(err)))
        fprintf(stderr, "warning: cannot save %s: %s\n", app.config_path,
                err);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    fprintf(stderr,
            "dpdk-tunnel-router %s: %d ports, %d workers, control %s\n",
            TR_VERSION, app.nports, app.workers, app.sock_path);

    while (!g_stop) {
        tr_control_poll(app.control, 100);
        tr_engine_housekeeping(app.engine, tr_monotonic_ms());
    }

    tr_control_destroy(app.control);
    app.control = NULL;
    tr_dpdk_stop(app.dpdk);
    tr_dpdk_destroy(app.dpdk);
    app.dpdk = NULL;
    tr_engine_destroy(app.engine);
    app.engine = NULL;
    rte_mempool_free(mp);
    tr_tunnel_drivers_fini();
    rte_eal_cleanup();
    return 0;

cleanup_dpdk:
    if (app.dpdk) {
        tr_dpdk_stop(app.dpdk);
        tr_dpdk_destroy(app.dpdk);
    }
cleanup_engine:
    tr_engine_destroy(app.engine);
    if (mp)
        rte_mempool_free(mp);
cleanup_drivers:
    tr_tunnel_drivers_fini();
cleanup:
    rte_eal_cleanup();
    return rc;
}
