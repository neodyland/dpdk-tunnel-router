/* Statistical profiler for the forwarding path (development tool only).
 *
 * `perf record` is unavailable on many build hosts (perf_event_paranoid, no
 * CAP_PERFMON), so this harness samples the instruction pointer itself with
 * ITIMER_PROF / SIGPROF while running the same workload as engine_bench.
 * Samples are recorded as raw PCs and dumped at the end together with the
 * module they belong to; core/bench/prof_symbolize.py turns them into a
 * per-function profile with addr2line.
 *
 * The workload is identical to engine_bench's burst mode: 64-byte Ethernet
 * frame, ARP-resolved IPv4 next hop, 32-packet bursts through
 * tr_engine_input_burst().  Like the benchmark it therefore includes the
 * packet-construction cost of the harness, which shows up in the profile as
 * separate symbols, not as engine time.
 *
 *   make -C core prof            # build
 *   TR_PROF_ROUNDS=150 make -C core prof-run | core/bench/prof_symbolize.py
 *
 * Without TR_PROF_SAMPLE=1 it only reports per-round timings, which is the
 * low-noise A/B measurement this checkout uses: on a busy hypervisor host the
 * invariant TSC includes steal time, while the process' CPU time does not, so
 * "cpu-ns/pkt (best round)" is stable to well under a percent.
 */
#include "config.h"
#include "engine.h"
#include "tunnel.h"
#include "util.h"

#include <arpa/inet.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <ucontext.h>

#define PROF_TOTAL 1000000
#define PROF_BATCH 32
#define PROF_FRAME_LEN 64
#define PROF_MAX_SAMPLES (1u << 22)
#define PROF_MAX_MODULES 32

static uint8_t frame_template[PROF_FRAME_LEN];

/* Written from the signal handler: one writer, never read while running. */
static uint64_t samples[PROF_MAX_SAMPLES];
static volatile sig_atomic_t n_samples;

static struct {
    void *base;
    char path[256];
    uint32_t n;
} modules[PROF_MAX_MODULES];
static int n_modules;

static int module_slot(void *pc)
{
    Dl_info info;

    if (!dladdr(pc, &info) || !info.dli_fbase)
        return -1;
    for (int i = 0; i < n_modules; i++) {
        if (modules[i].base == info.dli_fbase)
            return i;
    }
    if (n_modules >= PROF_MAX_MODULES)
        return -1;
    modules[n_modules].base = info.dli_fbase;
    snprintf(modules[n_modules].path, sizeof(modules[n_modules].path), "%s",
             info.dli_fname ? info.dli_fname : "?");
    modules[n_modules].n = (uint32_t)n_modules;
    return n_modules++;
}

static void on_prof(int sig, siginfo_t *si, void *ctx)
{
    ucontext_t *uc = (ucontext_t *)ctx;

    (void)sig;
    (void)si;
    if (n_samples < (sig_atomic_t)PROF_MAX_SAMPLES)
        samples[n_samples++] = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
}

static void prof_start(void)
{
    struct sigaction sa;
    struct itimerval it;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_prof;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPROF, &sa, NULL) != 0) {
        perror("sigaction");
        exit(1);
    }
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 1000; /* 1 kHz of CPU time */
    it.it_value = it.it_interval;
    if (setitimer(ITIMER_PROF, &it, NULL) != 0) {
        perror("setitimer");
        exit(1);
    }
}

static void prof_stop(void)
{
    struct itimerval it;

    memset(&it, 0, sizeof(it));
    setitimer(ITIMER_PROF, &it, NULL);
}

/* group -> print one line per unique (module, offset) with its count */
struct agg {
    int mod;
    uint64_t off;
    uint32_t count;
};
static struct agg aggs[1u << 16];
static unsigned n_aggs;

static int agg_cmp(const void *a, const void *b)
{
    const struct agg *x = a, *y = b;

    if (x->mod != y->mod)
        return x->mod - y->mod;
    if (x->off != y->off)
        return x->off < y->off ? -1 : 1;
    return 0;
}

static void dump_samples(void)
{
    for (int i = 0; i < (int)n_samples; i++) {
        void *pc = (void *)samples[i];
        int mod = module_slot(pc);
        uintptr_t off;
        unsigned j;

        if (mod < 0)
            continue;
        off = (uintptr_t)pc - (uintptr_t)modules[mod].base;
        for (j = 0; j < n_aggs; j++) {
            if (aggs[j].mod == mod && aggs[j].off == off) {
                aggs[j].count++;
                break;
            }
        }
        if (j == n_aggs && n_aggs < (unsigned)(sizeof(aggs) / sizeof(aggs[0]))) {
            aggs[n_aggs].mod = mod;
            aggs[n_aggs].off = off;
            aggs[n_aggs].count = 1;
            n_aggs++;
        }
    }
    qsort(aggs, n_aggs, sizeof(aggs[0]), agg_cmp);
    printf("# samples: %d\n", (int)n_samples);
    for (int m = 0; m < n_modules; m++)
        printf("# module %d %s\n", m, modules[m].path);
    for (unsigned i = 0; i < n_aggs; i++)
        printf("%d 0x%llx %u\n", aggs[i].mod,
               (unsigned long long)aggs[i].off, aggs[i].count);
}

static double mono_seconds(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* CPU time of the process: excludes hypervisor steal and scheduling gaps, so
 * it is far less noisy than wall clock on a shared host. */
static double cpu_seconds(void)
{
    struct rusage ru;

    getrusage(RUSAGE_SELF, &ru);
    return (double)ru.ru_utime.tv_sec + (double)ru.ru_utime.tv_usec / 1e6 +
           (double)ru.ru_stime.tv_sec + (double)ru.ru_stime.tv_usec / 1e6;
}

static inline uint64_t tsc_read(void)
{
    uint32_t lo, hi;

    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static void tx_count(void *arg, int worker, int if_slot, struct rte_mbuf *m)
{
    (void)worker;
    (void)if_slot;
    (*(uint64_t *)arg)++;
    rte_pktmbuf_free(m);
}

static int apply(struct tr_config *cfg, const struct tr_config_env *env,
                 const char *line)
{
    char buf[256];
    char *argv[32];
    char err[256];
    int argc;

    snprintf(buf, sizeof(buf), "%s", line);
    argc = tr_split(buf, argv, 32);
    if (tr_config_apply(cfg, env, argc, argv, err, sizeof(err))) {
        fprintf(stderr, "%s: %s\n", line, err);
        return -1;
    }
    return 0;
}

static void fill_frame(uint8_t *p)
{
    static const uint8_t dmac[6] = {0x02, 0, 0, 0, 0, 1};
    static const uint8_t smac[6] = {0x02, 0, 0, 0, 0, 2};
    uint16_t sum;

    memset(p, 0, PROF_FRAME_LEN);
    memcpy(p, dmac, 6);
    memcpy(p + 6, smac, 6);
    p[12] = 0x08;
    p[13] = 0;
    p[14] = 0x45;
    p[16] = 0;
    p[17] = 44;
    p[22] = 64;
    p[23] = 17;
    p[26] = 192;
    p[27] = 0;
    p[28] = 2;
    p[29] = 2;
    p[30] = 198;
    p[31] = 51;
    p[32] = 100;
    p[33] = 2;
    sum = tr_checksum16(p + 14, 20, 0);
    p[24] = (uint8_t)(sum >> 8);
    p[25] = (uint8_t)sum;
}

static inline struct rte_mbuf *make_packet(struct rte_mempool *mp)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(mp);

    if (!m)
        return NULL;
    if (!rte_pktmbuf_append(m, PROF_FRAME_LEN)) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    memcpy(rte_pktmbuf_mtod(m, uint8_t *), frame_template, PROF_FRAME_LEN);
    return m;
}

int main(void)
{
    char *eal_argv[] = {"engine_prof", "--no-huge", "--no-pci", "--lcores",
                        "0",            "-m",        "512",        NULL};
    char err[256];
    struct rte_mempool *mp;
    struct tr_config cfg;
    struct tr_config env_cfg;
    struct tr_config_env env;
    uint64_t tx_pkts = 0;
    int rounds = 20;
    int total = PROF_TOTAL;
    bool sample = false;
    const char *env_rounds = getenv("TR_PROF_ROUNDS");
    const char *env_total = getenv("TR_PROF_TOTAL");
    const char *env_sample = getenv("TR_PROF_SAMPLE");
    double best_cpu = 0, best_tsc = 0, best_wall = 0;

    if (env_rounds && atoi(env_rounds) > 0)
        rounds = atoi(env_rounds);
    if (env_total && atoi(env_total) >= PROF_BATCH)
        total = atoi(env_total) / PROF_BATCH * PROF_BATCH;
    if (env_sample && atoi(env_sample) != 0)
        sample = true;
    if (rte_eal_init(7, eal_argv) < 0) {
        fprintf(stderr, "EAL init failed\n");
        return 1;
    }
    if (tr_tunnel_drivers_init())
        return 1;
    mp = rte_pktmbuf_pool_create("prof_pool", 16384, 256, 0, 2048,
                                 rte_socket_id());
    if (!mp) {
        fprintf(stderr, "mempool: %s\n", rte_strerror(rte_errno));
        return 1;
    }
    fill_frame(frame_template);
    tr_config_init(&cfg);
    env.n_ports = 2;
    env.port_valid = NULL;
    env.port_names = NULL;
    const char *cmds[] = {
        "set interfaces ethernet eth0 port 0",
        "set interfaces ethernet eth0 address 192.0.2.1/24",
        "set interfaces ethernet eth1 port 1",
        "set interfaces ethernet eth1 address 198.51.100.1/24",
        NULL,
    };
    for (int i = 0; cmds[i]; i++)
        if (apply(&cfg, &env, cmds[i]))
            return 1;
    const uint8_t eth0_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t eth1_mac[6] = {0x02, 0, 0, 0, 0, 2};
    const uint8_t peer_mac[6] = {0x02, 0, 0, 0, 0, 0xbb};
    memcpy(tr_config_find(&cfg, "eth0")->mac, eth0_mac, 6);
    memcpy(tr_config_find(&cfg, "eth1")->mac, eth1_mac, 6);

    struct tr_engine *engine =
        tr_engine_create(&(struct tr_engine_params){.n_ports = 2,
                                                    .workers = 1,
                                                    .mp = mp},
                         err, sizeof(err));
    if (!engine) {
        fprintf(stderr, "engine: %s\n", err);
        return 1;
    }
    tr_engine_set_tx(engine, tx_count, &tx_pkts);
    if (tr_engine_apply(engine, &cfg, err, sizeof(err))) {
        fprintf(stderr, "apply: %s\n", err);
        return 1;
    }
    tr_engine_config_copy(engine, &env_cfg);
    int eth0 = tr_config_find_const(&env_cfg, "eth0")->slot;
    int eth1 = tr_config_find_const(&env_cfg, "eth1")->slot;

    struct rte_mbuf *arp = rte_pktmbuf_alloc(mp);
    if (!arp || !rte_pktmbuf_append(arp, 42))
        return 1;
    uint8_t *ap = rte_pktmbuf_mtod(arp, uint8_t *);
    memset(ap, 0, 42);
    memcpy(ap, eth1_mac, 6);
    memcpy(ap + 6, peer_mac, 6);
    ap[12] = 0x08;
    ap[13] = 0x06;
    ap[15] = 1;
    ap[16] = 0x08;
    ap[18] = 6;
    ap[19] = 4;
    ap[21] = 2;
    memcpy(ap + 22, peer_mac, 6);
    inet_pton(AF_INET, "198.51.100.2", ap + 28);
    memcpy(ap + 32, eth1_mac, 6);
    inet_pton(AF_INET, "198.51.100.1", ap + 38);
    tr_engine_input(engine, 0, eth1, arp);

    for (int i = 0; i < 100000; i++) {
        struct rte_mbuf *m = make_packet(mp);
        if (!m)
            return 1;
        tr_engine_input(engine, 0, eth0, m);
    }

    fprintf(stderr, "profiling %d rounds x %d pkts (burst, sample=%d)...\n",
            rounds, total, (int)sample);
    if (sample)
        prof_start();
    for (int round = 0; round < rounds; round++) {
        double w0 = mono_seconds();
        uint64_t t0 = tsc_read();
        double c0 = cpu_seconds();
        for (int i = 0; i < total; i += PROF_BATCH) {
            struct rte_mbuf *bufs[PROF_BATCH];
            for (int j = 0; j < PROF_BATCH; j++) {
                bufs[j] = make_packet(mp);
                if (!bufs[j])
                    return 1;
            }
            tr_engine_input_burst(engine, 0, eth0, bufs, PROF_BATCH);
        }
        double c1 = cpu_seconds();
        double w1 = mono_seconds();
        double cpu_ns = (c1 - c0) * 1e9 / total;
        double tsc_cyc = (double)(tsc_read() - t0) / total;
        double wall_ns = (w1 - w0) * 1e9 / total;
        if (best_cpu == 0 || cpu_ns < best_cpu)
            best_cpu = cpu_ns;
        if (best_tsc == 0 || tsc_cyc < best_tsc)
            best_tsc = tsc_cyc;
        if (best_wall == 0 || wall_ns < best_wall)
            best_wall = wall_ns;
        fprintf(stderr, "round %2d: %6.1f cpu-ns/pkt  %6.1f tsc-cyc/pkt  "
                        "%6.1f wall-ns/pkt\n",
                round + 1, cpu_ns, tsc_cyc, wall_ns);
    }
    if (sample)
        prof_stop();
    fprintf(stderr, "== best of %d rounds: %.1f cpu-ns/pkt  %.1f tsc-cyc/pkt"
                    "  %.1f wall-ns/pkt (%d pkts, tx %llu)\n",
            rounds, best_cpu, best_tsc, best_wall, rounds * total,
            (unsigned long long)tx_pkts);
    if (sample)
        dump_samples();

    tr_engine_destroy(engine);
    rte_mempool_free(mp);
    tr_tunnel_drivers_fini();
    rte_eal_cleanup();
    return 0;
}
