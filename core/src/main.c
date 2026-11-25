#include "config.h"
#include "capture.h"
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
    uint64_t revision;
};

struct cli_session {
    bool config_mode;
    bool dirty;
    uint64_t base_revision;
    struct tr_config candidate;
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

static const char *help_text(bool config_mode)
{
    if (!config_mode)
        return "Read mode commands:\n"
               "  show configuration | interfaces [name] | routes | neighbors\n"
               "  show bridge | statistics | tunnels | drivers | status | version\n"
               "  configure          enter configuration mode\n"
               "  tcpdump start|stop|status   packet capture (pcap)\n"
               "  help | exit | quit\n"
               "\n"
               "Configuration changes require configuration mode.\n";
    return "Configuration mode commands:\n"
           "  set interfaces tunnel <name> ...\n"
           "  set interfaces ethernet <name> ...\n"
           "  set interfaces bridge <name> ...\n"
           "  set protocols static route <prefix> via <next-hop>\n"
           "  delete ... / del ...\n"
           "  show configuration | interfaces [name]   (candidate)\n"
           "  show running-config                     (active configuration)\n"
           "  show routes | neighbors | bridge | statistics | tunnels | drivers\n"
           "  save | commit       apply candidate and persist it\n"
           "  discard | rollback  discard candidate changes\n"
           "  tcpdump start|stop|status   packet capture (pcap)\n"
           "  read | exit | end   return to read mode\n"
           "  help | quit\n"
           "\n"
           "save/commit is required before exiting with pending changes.\n";
}

static int fail_msg(char **error_text, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (vasprintf(error_text, fmt, ap) < 0)
        *error_text = NULL;
    va_end(ap);
    return -1;
}

static int body_msg(char **body, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (vasprintf(body, fmt, ap) < 0)
        *body = NULL;
    va_end(ap);
    return *body ? 0 : -1;
}

static void *control_session_open(void *arg)
{
    struct app *a = arg;
    struct cli_session *s = calloc(1, sizeof(*s));

    if (!s)
        return NULL;
    if (tr_engine_config_copy(a->engine, &s->candidate)) {
        free(s);
        return NULL;
    }
    s->base_revision = a->revision;
    return s;
}

static void control_session_close(void *arg, void *session)
{
    (void)arg;
    free(session);
}

static int reset_candidate(struct app *a, struct cli_session *s, char **error_text)
{
    if (tr_engine_config_copy(a->engine, &s->candidate))
        return fail_msg(error_text, "cannot read running configuration\n");
    s->base_revision = a->revision;
    s->dirty = false;
    return 0;
}

static int show_running(struct app *a, int argc, char **argv, char **body)
{
    if (argc >= 2 && strcmp(argv[1], "version") == 0) {
        if (asprintf(body, "dpdk-tunnel-router %s (DPDK %s)\n", TR_VERSION,
                     rte_version()) < 0)
            return -1;
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "status") == 0) {
        char *status = NULL;
        if (tr_dpdk_status_text(a->dpdk, &status))
            return -1;
        int rc = asprintf(body,
                          "dpdk-tunnel-router %s\n%s"
                          "tunnel drivers: %d registered\n",
                          TR_VERSION, status, tr_tunnel_driver_count());
        free(status);
        return rc < 0 ? -1 : 0;
    }
    if (argc >= 2 && (strcmp(argv[1], "configuration") == 0 ||
                      strcmp(argv[1], "running-config") == 0)) {
        if (strcmp(argv[1], "running-config") == 0)
            argv[1] = "configuration";
        return tr_engine_show(a->engine, argc - 1, argv + 1, body);
    }
    if (argc >= 2)
        return tr_engine_show(a->engine, argc - 1, argv + 1, body);
    return -1;
}

static int show_candidate(struct app *a, struct cli_session *s, int argc,
                          char **argv, char **body)
{
    if (argc >= 2 && (strcmp(argv[1], "configuration") == 0 ||
                      strcmp(argv[1], "candidate-config") == 0)) {
        return tr_config_serialize(&s->candidate, body);
    }
    if (argc >= 2 && strcmp(argv[1], "interfaces") == 0) {
        int rc = tr_config_show(&s->candidate, argc - 1, argv + 1, body);
        return rc;
    }
    if (argc >= 2 && strcmp(argv[1], "running-config") == 0)
        return show_running(a, argc, argv, body);
    /* Operational tables (FIB, neighbors, counters) describe the running
     * data plane; the candidate is not installed until save/commit. */
    return show_running(a, argc, argv, body);
}

static int edit_candidate(struct app *a, struct cli_session *s, int argc,
                          char **argv, char **body, char **error_text)
{
    struct tr_config working;
    char err[512];

    tr_config_copy(&working, &s->candidate);
    if (tr_config_apply(&working, &a->env, argc, argv, err, sizeof(err)))
        return fail_msg(error_text, "%s\n", err[0] ? err : "configuration error");
    apply_port_macs(&working, a->nports);
    if (tr_config_validate(&working, &a->env, err, sizeof(err)))
        return fail_msg(error_text, "%s\n", err[0] ? err : "configuration error");
    tr_config_copy(&s->candidate, &working);
    s->dirty = true;
    return body_msg(body, "Candidate updated.\n");
}

static int commit_candidate(struct app *a, struct cli_session *s, char **body,
                            char **error_text)
{
    struct tr_config working, old;
    char err[512];
    char save_err[256];

    if (!s->dirty)
        return body_msg(body, "No changes to save.\n");
    if (s->base_revision != a->revision) {
        return fail_msg(error_text,
                        "running configuration changed in another session; "
                        "use 'discard' and re-enter configuration mode\n");
    }
    tr_config_copy(&working, &s->candidate);
    apply_port_macs(&working, a->nports);
    if (tr_config_validate(&working, &a->env, err, sizeof(err)))
        return fail_msg(error_text, "%s\n", err[0] ? err : "configuration error");
    if (tr_engine_config_copy(a->engine, &old))
        return fail_msg(error_text, "cannot read running configuration\n");
    if (tr_engine_apply(a->engine, &working, err, sizeof(err)))
        return fail_msg(error_text, "%s\n", err[0] ? err : "apply failed");
    tr_dpdk_refresh(a->dpdk);
    if (a->persist &&
        tr_config_save(&working, a->config_path, save_err, sizeof(save_err))) {
        tr_engine_apply(a->engine, &old, err, sizeof(err));
        tr_dpdk_refresh(a->dpdk);
        return fail_msg(error_text, "cannot save configuration: %s\n",
                        save_err);
    }
    a->revision++;
    s->base_revision = a->revision;
    s->dirty = false;
    tr_config_copy(&s->candidate, &working);
    if (a->persist)
        return body_msg(body, "Configuration saved.\n");
    return body_msg(body, "Configuration applied (persistence disabled).\n");
}

static int capture_command(struct app *a, int argc, char **argv, char **body,
                           char **error_text)
{
    const char *sub = argc >= 2 ? argv[1] : "status";
    char err[512];

    if (strcmp(sub, "help") == 0 || strcmp(sub, "-h") == 0 ||
        strcmp(sub, "--help") == 0) {
        return body_msg(body,
                        "tcpdump start [interface <name>|any] -w <file>\n"
                        "              [-d rx|tx|both] [-s snaplen] [-c count]\n"
                        "              [filter <ip|ip6|arp|tcp|udp|icmp|icmp6|"
                        "host ADDR|src host ADDR|dst host ADDR|port N|"
                        "src port N|dst port N|vlan ID>]\n"
                        "tcpdump stop\n"
                        "tcpdump status\n"
                        "tcpdump -i <if> -w <file> ...   (start may be omitted)\n");
    }
    bool start_mode =
        strcmp(sub, "start") == 0 || strcmp(sub, "interface") == 0 ||
        strcmp(sub, "file") == 0 || strcmp(sub, "output") == 0 ||
        strcmp(sub, "direction") == 0 || strcmp(sub, "snaplen") == 0 ||
        strcmp(sub, "count") == 0 || strcmp(sub, "filter") == 0 ||
        strcmp(sub, "expression") == 0 || sub[0] == '-';
    if (start_mode) {
        const char *ifname = "any";
        const char *file = NULL;
        char filter_buf[TR_CAP_FILTER_LEN];
        const char *filter = "";
        unsigned direction = TR_CAP_BOTH;
        uint32_t snaplen = TR_CAP_SNAPLEN_MAX;
        uint64_t count = 0;
        int i = strcmp(sub, "start") == 0 ? 2 : 1;

        filter_buf[0] = '\0';

        while (i < argc) {
            const char *opt = argv[i++];
            if (strcmp(opt, "interface") == 0 || strcmp(opt, "-i") == 0) {
                if (i >= argc)
                    return fail_msg(error_text, "%s requires a name\n", opt);
                ifname = argv[i++];
            } else if (strcmp(opt, "file") == 0 ||
                       strcmp(opt, "output") == 0 ||
                       strcmp(opt, "-w") == 0) {
                if (i >= argc)
                    return fail_msg(error_text, "%s requires a path\n", opt);
                file = argv[i++];
            } else if (strcmp(opt, "direction") == 0 ||
                       strcmp(opt, "-d") == 0) {
                if (i >= argc)
                    return fail_msg(error_text,
                                    "direction requires rx/tx/both\n");
                if (strcmp(argv[i], "rx") == 0)
                    direction = TR_CAP_RX;
                else if (strcmp(argv[i], "tx") == 0)
                    direction = TR_CAP_TX;
                else if (strcmp(argv[i], "both") == 0)
                    direction = TR_CAP_BOTH;
                else
                    return fail_msg(error_text,
                                    "direction must be rx, tx, or both\n");
                i++;
            } else if (strcmp(opt, "snaplen") == 0 ||
                       strcmp(opt, "-s") == 0) {
                uint32_t v;
                if (i >= argc ||
                    tr_parse_u32(argv[i], 64, TR_CAP_SNAPLEN_MAX, &v))
                    return fail_msg(error_text,
                                    "snaplen must be 64..%d\n",
                                    TR_CAP_SNAPLEN_MAX);
                snaplen = v;
                i++;
            } else if (strcmp(opt, "count") == 0 ||
                       strcmp(opt, "-c") == 0) {
                uint32_t v;
                if (i >= argc ||
                    tr_parse_u32(argv[i], 0, 1000000000u, &v))
                    return fail_msg(error_text,
                                    "count must be 0..1000000000\n");
                count = v;
                i++;
            } else if (strcmp(opt, "filter") == 0 ||
                       strcmp(opt, "expression") == 0) {
                size_t off = 0;
                for (; i < argc; i++) {
                    int n = snprintf(filter_buf + off,
                                     sizeof(filter_buf) - off, "%s%s",
                                     off ? " " : "", argv[i]);
                    if (n < 0 || (size_t)n >= sizeof(filter_buf) - off)
                        return fail_msg(error_text,
                                        "capture filter is too long\n");
                    off += (size_t)n;
                }
                filter = filter_buf;
                break;
            } else {
                return fail_msg(error_text, "unknown capture option '%s'\n",
                                opt);
            }
        }
        if (!file)
            return fail_msg(error_text, "capture file is required (-w FILE)\n");
        if (tr_engine_capture_start(a->engine, ifname, file, direction,
                                    snaplen, count, filter, err, sizeof(err)))
            return fail_msg(error_text, "%s\n", err);
        char *status = NULL;
        if (tr_engine_capture_status(a->engine, &status) == 0) {
            int rc = asprintf(body, "Capture started.\n%s", status);
            free(status);
            return rc < 0 ? -1 : 0;
        }
        return body_msg(body, "Capture started.\n");
    }
    if (strcmp(sub, "stop") == 0) {
        if (tr_engine_capture_stop(a->engine, err, sizeof(err)))
            return fail_msg(error_text, "%s\n", err);
        char *status = NULL;
        if (tr_engine_capture_status(a->engine, &status) == 0) {
            int rc = asprintf(body, "Capture stopped.\n%s", status);
            free(status);
            return rc < 0 ? -1 : 0;
        }
        return body_msg(body, "Capture stopped.\n");
    }
    if (strcmp(sub, "status") == 0 || strcmp(sub, "show") == 0) {
        if (tr_engine_capture_status(a->engine, body))
            return fail_msg(error_text, "capture status unavailable\n");
        return 0;
    }
    return fail_msg(error_text, "unknown tcpdump command '%s'\n", sub);
}

static int control_execute(void *arg, void *session, const char *line,
                           char **body, char **error_text)
{
    struct app *a = arg;
    struct cli_session *s = session;
    char *copy;
    char *argv[64];
    int argc;
    int rc = 0;

    *body = NULL;
    *error_text = NULL;
    if (!s)
        return fail_msg(error_text, "control session unavailable\n");
    copy = strdup(line);
    if (!copy)
        return fail_msg(error_text, "out of memory\n");
    argc = tr_split(copy, argv, (int)TR_ARRAY_SIZE(argv));
    if (argc == 0) {
        free(copy);
        return body_msg(body, "");
    }
    if (strcmp(argv[0], "del") == 0)
        argv[0] = "delete";

    if (strcmp(argv[0], "configure") == 0 || strcmp(argv[0], "config") == 0) {
        if (s->config_mode) {
            rc = fail_msg(error_text, "already in configuration mode\n");
        } else if (reset_candidate(a, s, error_text)) {
            rc = -1;
        } else {
            s->config_mode = true;
            rc = body_msg(body, "Entering configuration mode.\n");
        }
        goto out;
    }
    if (strcmp(argv[0], "read") == 0) {
        if (!s->config_mode) {
            rc = body_msg(body, "Already in read mode.\n");
        } else if (s->dirty) {
            rc = fail_msg(error_text,
                          "unsaved changes; use 'save' or 'discard' first\n");
        } else {
            s->config_mode = false;
            rc = body_msg(body, "Read mode.\n");
        }
        goto out;
    }
    if (strcmp(argv[0], "exit") == 0 || strcmp(argv[0], "end") == 0) {
        if (!s->config_mode) {
            rc = body_msg(body, "Bye.\n");
        } else if (s->dirty) {
            rc = fail_msg(error_text,
                          "unsaved changes; use 'save' or 'discard' first\n");
        } else {
            s->config_mode = false;
            rc = body_msg(body, "Exiting configuration mode.\n");
        }
        goto out;
    }
    if (strcmp(argv[0], "save") == 0 || strcmp(argv[0], "commit") == 0) {
        if (!s->config_mode)
            rc = fail_msg(error_text,
                          "save is only available in configuration mode\n");
        else
            rc = commit_candidate(a, s, body, error_text);
        goto out;
    }
    if (strcmp(argv[0], "discard") == 0 ||
        strcmp(argv[0], "rollback") == 0) {
        if (!s->config_mode) {
            rc = fail_msg(error_text,
                          "discard is only available in configuration mode\n");
        } else if (reset_candidate(a, s, error_text)) {
            rc = -1;
        } else {
            rc = body_msg(body, "Candidate discarded.\n");
        }
        goto out;
    }
    if (strcmp(argv[0], "set") == 0 || strcmp(argv[0], "delete") == 0) {
        if (!s->config_mode) {
            rc = fail_msg(error_text,
                          "%s is only available in configuration mode; "
                          "enter 'configure' first\n",
                          argv[0]);
        } else {
            rc = edit_candidate(a, s, argc, argv, body, error_text);
        }
        goto out;
    }
    if (strcmp(argv[0], "show") == 0) {
        if (argc < 2) {
            rc = fail_msg(error_text, "show requires a topic\n");
        } else if (s->config_mode &&
                   (strcmp(argv[1], "configuration") == 0 ||
                    strcmp(argv[1], "candidate-config") == 0 ||
                    strcmp(argv[1], "interfaces") == 0)) {
            rc = show_candidate(a, s, argc, argv, body);
        } else {
            rc = show_running(a, argc, argv, body);
        }
        if (rc)
            rc = fail_msg(error_text, "unknown or failed show command\n");
        goto out;
    }
    if (strcmp(argv[0], "tcpdump") == 0 ||
        strcmp(argv[0], "capture") == 0) {
        rc = capture_command(a, argc, argv, body, error_text);
        goto out;
    }
    if (strcmp(argv[0], "help") == 0) {
        rc = body_msg(body, "%s", help_text(s->config_mode));
        goto out;
    }
    if (strcmp(argv[0], "quit") == 0) {
        if (s->config_mode && s->dirty) {
            rc = fail_msg(error_text,
                          "unsaved changes; use 'save' or 'discard' first\n");
        } else {
            s->config_mode = false;
            rc = body_msg(body, "Bye.\n");
        }
        goto out;
    }
    rc = fail_msg(error_text, "unknown command '%s' (try 'help')\n", argv[0]);
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

    struct tr_control_ops ops = {
        .session_open = control_session_open,
        .session_close = control_session_close,
        .execute = control_execute,
    };
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
