#include "capture.h"

#include "addr.h"
#include "util.h"

#include <rte_ring.h>
#include <rte_errno.h>

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define TR_CAP_SLOTS 512
#define TR_CAP_RING_SIZE 1024
#define TR_CAP_DATA_SIZE TR_CAP_SNAPLEN_MAX

struct tr_cap_slot {
    struct timespec ts;
    uint32_t orig_len;
    uint32_t incl_len;
    uint8_t data[TR_CAP_DATA_SIZE];
};

struct tr_cap_filter {
    uint16_t eth_type; /* 0 = any, 0x0800, 0x86dd, 0x0806 */
    uint8_t ip_proto;  /* 0 = any */
    bool host_set;
    struct tr_ip host;
    uint8_t host_dir; /* 0 any, 1 src, 2 dst */
    bool port_set;
    uint16_t port;
    uint8_t port_dir;
    bool vlan_set;
    uint16_t vlan;
    bool ether_set;
    uint8_t ether[6];
};

static _Atomic unsigned g_cap_ring_seq;

struct tr_capture {
    _Atomic bool active;
    _Atomic uint32_t inflight;
    _Atomic uint64_t drops;
    _Atomic uint64_t generation;

    struct rte_ring *free_ring;
    struct rte_ring *full_ring;
    struct tr_cap_slot *slots;

    int if_slot;
    char ifname[TR_CAP_IFNAME_LEN];
    char file[TR_CAP_FILE_LEN];
    unsigned direction;
    uint32_t snaplen;
    uint64_t count;
    char filter_expr[TR_CAP_FILTER_LEN];
    struct tr_cap_filter filter;

    FILE *fp;
    bool ever_started;
    uint64_t packets;
    uint64_t bytes;
    time_t started;
    time_t stopped;
    char stop_reason[128];
    char error[128];
};

static void put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static int write_pcap_header(FILE *f, uint32_t snaplen)
{
    uint8_t h[24];

    put_le32(h, 0xa1b2c3d4u); /* little-endian, microsecond timestamps */
    put_le16(h + 4, 2);
    put_le16(h + 6, 4);
    put_le32(h + 8, 0);  /* thiszone */
    put_le32(h + 12, 0); /* sigfigs */
    put_le32(h + 16, snaplen);
    put_le32(h + 20, 1); /* DLT_EN10MB */
    return fwrite(h, 1, sizeof(h), f) == sizeof(h) ? 0 : -1;
}

static int write_record(FILE *f, const struct tr_cap_slot *slot)
{
    uint8_t h[16];
    uint32_t sec = (uint32_t)slot->ts.tv_sec;
    uint32_t usec = (uint32_t)(slot->ts.tv_nsec / 1000);

    put_le32(h, sec);
    put_le32(h + 4, usec);
    put_le32(h + 8, slot->incl_len);
    put_le32(h + 12, slot->orig_len);
    if (fwrite(h, 1, sizeof(h), f) != sizeof(h))
        return -1;
    if (slot->incl_len &&
        fwrite(slot->data, 1, slot->incl_len, f) != slot->incl_len)
        return -1;
    return 0;
}

static int ring_reset(struct tr_capture *cap)
{
    void *p;

    while (rte_ring_dequeue(cap->free_ring, &p) == 0)
        ;
    while (rte_ring_dequeue(cap->full_ring, &p) == 0)
        ;
    for (int i = 0; i < TR_CAP_SLOTS; i++) {
        if (rte_ring_enqueue(cap->free_ring, &cap->slots[i]) != 0)
            return -1;
    }
    return 0;
}

int tr_capture_create(struct tr_capture **out, char *err, size_t errlen)
{
    struct tr_capture *cap;
    char name[64];

    cap = calloc(1, sizeof(*cap));
    if (!cap) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    cap->slots = calloc(TR_CAP_SLOTS, sizeof(*cap->slots));
    if (!cap->slots) {
        snprintf(err, errlen, "out of memory");
        free(cap);
        return -1;
    }
    unsigned seq = atomic_fetch_add(&g_cap_ring_seq, 1);
    snprintf(name, sizeof(name), "tr_cap_free_%d_%u", getpid(), seq);
    cap->free_ring = rte_ring_create(name, TR_CAP_RING_SIZE,
                                     rte_socket_id(), 0);
    snprintf(name, sizeof(name), "tr_cap_full_%d_%u", getpid(), seq);
    cap->full_ring = rte_ring_create(name, TR_CAP_RING_SIZE,
                                     rte_socket_id(), 0);
    if (!cap->free_ring || !cap->full_ring) {
        snprintf(err, errlen, "cannot create capture rings: %s",
                 rte_strerror(rte_errno));
        if (cap->free_ring)
            rte_ring_free(cap->free_ring);
        if (cap->full_ring)
            rte_ring_free(cap->full_ring);
        free(cap->slots);
        free(cap);
        return -1;
    }
    cap->if_slot = -1;
    atomic_store(&cap->active, false);
    atomic_store(&cap->inflight, 0);
    atomic_store(&cap->drops, 0);
    if (ring_reset(cap)) {
        snprintf(err, errlen, "cannot initialize capture rings");
        rte_ring_free(cap->free_ring);
        rte_ring_free(cap->full_ring);
        free(cap->slots);
        free(cap);
        return -1;
    }
    *out = cap;
    return 0;
}

static int filter_parse(const char *expr, struct tr_cap_filter *f, char *err,
                        size_t errlen)
{
    char buf[TR_CAP_FILTER_LEN];
    char *argv[64];
    int argc;

    memset(f, 0, sizeof(*f));
    if (!expr || !*expr)
        return 0;
    snprintf(buf, sizeof(buf), "%s", expr);
    argc = tr_split(buf, argv, (int)TR_ARRAY_SIZE(argv));
    for (int i = 0; i < argc; i++) {
        const char *t = argv[i];
        if (strcmp(t, "and") == 0)
            continue;
        if (strcmp(t, "or") == 0) {
            snprintf(err, errlen, "filter: 'or' is not supported");
            return -1;
        }
        if (strcmp(t, "ip") == 0) {
            if (f->eth_type && f->eth_type != 0x0800) {
                snprintf(err, errlen, "filter: conflicting IP versions");
                return -1;
            }
            f->eth_type = 0x0800;
        } else if (strcmp(t, "ip6") == 0 || strcmp(t, "ipv6") == 0) {
            if (f->eth_type && f->eth_type != 0x86dd) {
                snprintf(err, errlen, "filter: conflicting IP versions");
                return -1;
            }
            f->eth_type = 0x86dd;
        } else if (strcmp(t, "arp") == 0) {
            if (f->eth_type && f->eth_type != 0x0806) {
                snprintf(err, errlen, "filter: conflicting ether types");
                return -1;
            }
            f->eth_type = 0x0806;
        } else if (strcmp(t, "tcp") == 0 || strcmp(t, "udp") == 0 ||
                   strcmp(t, "icmp") == 0 || strcmp(t, "icmp6") == 0) {
            uint8_t proto = strcmp(t, "tcp") == 0   ? 6
                            : strcmp(t, "udp") == 0 ? 17
                            : strcmp(t, "icmp") == 0 ? 1
                                                     : 58;
            if (f->ip_proto && f->ip_proto != proto) {
                snprintf(err, errlen, "filter: conflicting protocols");
                return -1;
            }
            if (proto == 1) {
                if (f->eth_type == 0x86dd) {
                    snprintf(err, errlen,
                             "filter: icmp is IPv4; use icmp6");
                    return -1;
                }
                f->eth_type = 0x0800;
            } else if (proto == 58) {
                if (f->eth_type == 0x0800) {
                    snprintf(err, errlen,
                             "filter: icmp6 is IPv6; use icmp");
                    return -1;
                }
                f->eth_type = 0x86dd;
            }
            f->ip_proto = proto;
        } else if (strcmp(t, "host") == 0 || strcmp(t, "src") == 0 ||
                   strcmp(t, "dst") == 0) {
            uint8_t dir = 0;
            if (strcmp(t, "src") == 0)
                dir = 1;
            else if (strcmp(t, "dst") == 0)
                dir = 2;
            if (dir != 0) {
                if (++i >= argc) {
                    snprintf(err, errlen, "filter: %s requires a term", t);
                    return -1;
                }
                t = argv[i];
            }
            if (strcmp(t, "host") == 0) {
                if (++i >= argc) {
                    snprintf(err, errlen, "filter: host requires an address");
                    return -1;
                }
                if (f->host_set) {
                    snprintf(err, errlen, "filter: duplicate host");
                    return -1;
                }
                if (tr_ip_parse(argv[i], &f->host)) {
                    snprintf(err, errlen, "filter: invalid host '%s'",
                             argv[i]);
                    return -1;
                }
                f->host_set = true;
                f->host_dir = dir;
            } else if (strcmp(t, "port") == 0) {
                uint32_t port;
                if (++i >= argc) {
                    snprintf(err, errlen, "filter: port requires a value");
                    return -1;
                }
                if (f->port_set) {
                    snprintf(err, errlen, "filter: duplicate port");
                    return -1;
                }
                if (tr_parse_u32(argv[i], 1, 65535, &port)) {
                    snprintf(err, errlen, "filter: invalid port '%s'",
                             argv[i]);
                    return -1;
                }
                f->port_set = true;
                f->port = (uint16_t)port;
                f->port_dir = dir;
            } else {
                snprintf(err, errlen, "filter: expected host/port after %s",
                         dir ? (dir == 1 ? "src" : "dst") : "term");
                return -1;
            }
        } else if (strcmp(t, "port") == 0) {
            uint32_t port;
            if (++i >= argc) {
                snprintf(err, errlen, "filter: port requires a value");
                return -1;
            }
            if (f->port_set) {
                snprintf(err, errlen, "filter: duplicate port");
                return -1;
            }
            if (tr_parse_u32(argv[i], 1, 65535, &port)) {
                snprintf(err, errlen, "filter: invalid port '%s'", argv[i]);
                return -1;
            }
            f->port_set = true;
            f->port = (uint16_t)port;
            f->port_dir = 0;
        } else if (strcmp(t, "vlan") == 0) {
            uint32_t vid;
            if (++i >= argc) {
                snprintf(err, errlen, "filter: vlan requires a value");
                return -1;
            }
            if (f->vlan_set) {
                snprintf(err, errlen, "filter: duplicate vlan");
                return -1;
            }
            if (tr_parse_u32(argv[i], 1, 4094, &vid)) {
                snprintf(err, errlen, "filter: invalid VLAN '%s'", argv[i]);
                return -1;
            }
            f->vlan_set = true;
            f->vlan = (uint16_t)vid;
        } else if (strcmp(t, "ether") == 0) {
            if (++i >= argc || strcmp(argv[i], "host") != 0) {
                snprintf(err, errlen, "filter: expected 'ether host'");
                return -1;
            }
            if (++i >= argc) {
                snprintf(err, errlen, "filter: ether host requires a MAC");
                return -1;
            }
            if (f->ether_set) {
                snprintf(err, errlen, "filter: duplicate ether host");
                return -1;
            }
            if (tr_parse_mac(argv[i], f->ether)) {
                snprintf(err, errlen, "filter: invalid MAC '%s'", argv[i]);
                return -1;
            }
            f->ether_set = true;
        } else {
            snprintf(err, errlen, "filter: unknown term '%s'", t);
            return -1;
        }
    }
    return 0;
}

static bool host_match(const struct tr_cap_filter *f, const struct tr_ip *src,
                       const struct tr_ip *dst)
{
    if (!f->host_set)
        return true;
    if (f->host_dir != 2 && tr_ip_equal(src, &f->host))
        return true;
    if (f->host_dir != 1 && tr_ip_equal(dst, &f->host))
        return true;
    return false;
}

static bool port_match(const struct tr_cap_filter *f, uint16_t sp,
                       uint16_t dp)
{
    if (!f->port_set)
        return true;
    if (f->port_dir != 2 && sp == f->port)
        return true;
    if (f->port_dir != 1 && dp == f->port)
        return true;
    return false;
}

static bool filter_match(const struct tr_cap_filter *f, const uint8_t *p,
                         uint32_t len)
{
    uint32_t off = 12;
    uint16_t type;
    uint16_t vlan = 0;
    bool tagged = false;
    const uint8_t *l3;
    uint32_t l3len;

    if (!f->ether_set && !f->eth_type && !f->ip_proto && !f->host_set &&
        !f->port_set && !f->vlan_set)
        return true;
    if (len < 14)
        return false;
    if (f->ether_set &&
        memcmp(p, f->ether, 6) != 0 && memcmp(p + 6, f->ether, 6) != 0)
        return false;
    for (int depth = 0; depth < 2; depth++) {
        if (off + 2 > len)
            return false;
        type = (uint16_t)(p[off] << 8 | p[off + 1]);
        if (type != 0x8100 || off + 6 > len)
            break;
        if (!tagged) {
            tagged = true;
            vlan = (uint16_t)((p[off + 2] << 8 | p[off + 3]) & 0x0fff);
        }
        off += 4;
    }
    if (off + 2 > len)
        return false;
    type = (uint16_t)(p[off] << 8 | p[off + 1]);
    l3 = p + off + 2;
    l3len = len - off - 2;
    if (f->vlan_set && (!tagged || vlan != f->vlan))
        return false;
    if (f->eth_type && type != f->eth_type)
        return false;

    if (type == 0x0806) {
        if (f->ip_proto || f->port_set)
            return false;
        if (!f->host_set)
            return true;
        if (l3len < 28)
            return false;
        struct tr_ip spa = {.family = TR_AF_INET};
        struct tr_ip tpa = {.family = TR_AF_INET};
        memcpy(&spa.u.v4, l3 + 14, 4);
        memcpy(&tpa.u.v4, l3 + 24, 4);
        return host_match(f, &spa, &tpa);
    }
    if (type != 0x0800 && type != 0x86dd)
        return f->eth_type == 0 && !f->host_set && !f->port_set &&
               !f->ip_proto;
    if (type == 0x0800) {
        if (l3len < 20 || (l3[0] >> 4) != 4)
            return false;
        uint32_t ihl = (uint32_t)(l3[0] & 0x0f) * 4;
        if (ihl < 20 || l3len < ihl)
            return false;
        struct tr_ip src = {.family = TR_AF_INET};
        struct tr_ip dst = {.family = TR_AF_INET};
        memcpy(&src.u.v4, l3 + 12, 4);
        memcpy(&dst.u.v4, l3 + 16, 4);
        if (!host_match(f, &src, &dst))
            return false;
        if (f->ip_proto && l3[9] != f->ip_proto)
            return false;
        if (f->port_set) {
            if ((l3[9] != 6 && l3[9] != 17) ||
                (l3[6] & 0x20) || (l3[6] & 0x1f) || l3[7])
                return false;
            if (l3len < ihl + 4)
                return false;
            uint16_t sp = (uint16_t)(l3[ihl] << 8 | l3[ihl + 1]);
            uint16_t dp = (uint16_t)(l3[ihl + 2] << 8 | l3[ihl + 3]);
            return port_match(f, sp, dp);
        }
        return true;
    }
    if (l3len < 40 || (l3[0] >> 4) != 6)
        return false;
    struct tr_ip src = {.family = TR_AF_INET6};
    struct tr_ip dst = {.family = TR_AF_INET6};
    memcpy(&src.u.v6, l3 + 8, 16);
    memcpy(&dst.u.v6, l3 + 24, 16);
    if (!host_match(f, &src, &dst))
        return false;
    if (f->ip_proto && l3[6] != f->ip_proto)
        return false;
    if (f->port_set) {
        if ((l3[6] != 6 && l3[6] != 17) || l3len < 44)
            return false;
        uint16_t sp = (uint16_t)(l3[40] << 8 | l3[41]);
        uint16_t dp = (uint16_t)(l3[42] << 8 | l3[43]);
        return port_match(f, sp, dp);
    }
    return true;
}

static void capture_close(struct tr_capture *cap, bool drain)
{
    void *p;

    atomic_store_explicit(&cap->active, false, memory_order_release);
    atomic_fetch_add_explicit(&cap->generation, 1, memory_order_relaxed);
    while (atomic_load_explicit(&cap->inflight, memory_order_acquire) != 0)
        sched_yield();
    while (rte_ring_dequeue(cap->full_ring, &p) == 0) {
        struct tr_cap_slot *slot = p;
        if (drain && cap->fp && write_record(cap->fp, slot) == 0) {
            cap->packets++;
            cap->bytes += slot->orig_len;
        }
        rte_ring_enqueue(cap->free_ring, slot);
    }
    if (cap->fp) {
        fflush(cap->fp);
        fclose(cap->fp);
        cap->fp = NULL;
    }
    cap->stopped = time(NULL);
}

int tr_capture_start(struct tr_capture *cap, int if_slot, const char *ifname,
                     const char *file, unsigned direction, uint32_t snaplen,
                     uint64_t count, const char *filter, char *err,
                     size_t errlen)
{
    struct tr_cap_filter parsed;

    if (!cap || !file || !*file) {
        snprintf(err, errlen, "capture file is required");
        return -1;
    }
    if (atomic_load_explicit(&cap->active, memory_order_acquire)) {
        snprintf(err, errlen, "a capture is already running");
        return -1;
    }
    if (direction == 0 || (direction & ~TR_CAP_BOTH)) {
        snprintf(err, errlen, "invalid capture direction");
        return -1;
    }
    if (snaplen < 64 || snaplen > TR_CAP_SNAPLEN_MAX) {
        snprintf(err, errlen, "snaplen must be 64..%d",
                 TR_CAP_SNAPLEN_MAX);
        return -1;
    }
    if (strlen(file) >= sizeof(cap->file) ||
        strlen(ifname ? ifname : "any") >= sizeof(cap->ifname)) {
        snprintf(err, errlen, "capture path or interface name is too long");
        return -1;
    }
    if (filter && strlen(filter) >= sizeof(cap->filter_expr)) {
        snprintf(err, errlen, "capture filter is too long");
        return -1;
    }
    if (filter_parse(filter, &parsed, err, errlen))
        return -1;
    FILE *fp = fopen(file, "wb");
    if (!fp) {
        snprintf(err, errlen, "cannot open %s: %s", file, strerror(errno));
        return -1;
    }
    setvbuf(fp, NULL, _IOFBF, 1 << 20);
    (void)fchmod(fileno(fp), 0640);
    if (write_pcap_header(fp, snaplen)) {
        snprintf(err, errlen, "cannot write pcap header to %s", file);
        fclose(fp);
        return -1;
    }
    if (ring_reset(cap)) {
        snprintf(err, errlen, "cannot initialize capture rings");
        fclose(fp);
        return -1;
    }
    cap->if_slot = if_slot;
    snprintf(cap->ifname, sizeof(cap->ifname), "%s",
             ifname && *ifname ? ifname : "any");
    snprintf(cap->file, sizeof(cap->file), "%s", file);
    cap->direction = direction;
    cap->snaplen = snaplen;
    cap->count = count;
    snprintf(cap->filter_expr, sizeof(cap->filter_expr), "%s",
             filter ? filter : "");
    cap->filter = parsed;
    cap->fp = fp;
    cap->packets = 0;
    cap->bytes = 0;
    atomic_store(&cap->drops, 0);
    cap->started = time(NULL);
    cap->stopped = 0;
    cap->stop_reason[0] = '\0';
    cap->error[0] = '\0';
    cap->ever_started = true;
    atomic_fetch_add_explicit(&cap->generation, 1, memory_order_relaxed);
    atomic_store_explicit(&cap->active, true, memory_order_release);
    return 0;
}

int tr_capture_stop(struct tr_capture *cap, char *err, size_t errlen)
{
    (void)err;
    (void)errlen;
    if (!cap)
        return -1;
    if (atomic_load_explicit(&cap->active, memory_order_acquire)) {
        snprintf(cap->stop_reason, sizeof(cap->stop_reason), "stopped");
        capture_close(cap, true);
    }
    return 0;
}

void tr_capture_poll(struct tr_capture *cap)
{
    if (!cap || !atomic_load_explicit(&cap->active, memory_order_acquire))
        return;
    int budget = TR_CAP_SLOTS;
    while (budget-- > 0) {
        void *p;
        if (rte_ring_dequeue(cap->full_ring, &p) != 0)
            break;
        struct tr_cap_slot *slot = p;
        if (!cap->fp || write_record(cap->fp, slot) != 0) {
            snprintf(cap->error, sizeof(cap->error), "pcap write failed");
            snprintf(cap->stop_reason, sizeof(cap->stop_reason),
                     "write error");
            rte_ring_enqueue(cap->free_ring, slot);
            capture_close(cap, false);
            return;
        }
        cap->packets++;
        cap->bytes += slot->orig_len;
        rte_ring_enqueue(cap->free_ring, slot);
        if (cap->count && cap->packets >= cap->count) {
            snprintf(cap->stop_reason, sizeof(cap->stop_reason),
                     "count reached");
            capture_close(cap, false);
            return;
        }
    }
    if (cap->fp)
        fflush(cap->fp);
}

static void capture_tap_impl(struct tr_capture *cap, int if_slot,
                             unsigned direction, const struct rte_mbuf *m,
                             bool exact)
{
    if (!cap || !m)
        return;
    uint64_t gen = atomic_load_explicit(&cap->generation, memory_order_relaxed);
    if (!atomic_load_explicit(&cap->active, memory_order_acquire))
        return;
    atomic_fetch_add_explicit(&cap->inflight, 1, memory_order_acquire);
    if (!atomic_load_explicit(&cap->active, memory_order_acquire) ||
        atomic_load_explicit(&cap->generation, memory_order_relaxed) != gen) {
        atomic_fetch_sub_explicit(&cap->inflight, 1, memory_order_release);
        return;
    }
    if (!(cap->direction & direction) ||
        (exact ? cap->if_slot != if_slot
               : (cap->if_slot >= 0 && cap->if_slot != if_slot))) {
        atomic_fetch_sub_explicit(&cap->inflight, 1, memory_order_release);
        return;
    }
    uint32_t len = rte_pktmbuf_pkt_len(m);
    if (!len || m->nb_segs != 1 || m->data_len != len) {
        atomic_fetch_add_explicit(&cap->drops, 1, memory_order_relaxed);
        atomic_fetch_sub_explicit(&cap->inflight, 1, memory_order_release);
        return;
    }
    const uint8_t *data = rte_pktmbuf_mtod(m, const uint8_t *);
    if (!filter_match(&cap->filter, data, len)) {
        atomic_fetch_sub_explicit(&cap->inflight, 1, memory_order_release);
        return;
    }
    void *p;
    if (rte_ring_dequeue(cap->free_ring, &p) != 0) {
        atomic_fetch_add_explicit(&cap->drops, 1, memory_order_relaxed);
        atomic_fetch_sub_explicit(&cap->inflight, 1, memory_order_release);
        return;
    }
    struct tr_cap_slot *slot = p;
    uint32_t incl = len;
    if (incl > cap->snaplen)
        incl = cap->snaplen;
    if (incl > TR_CAP_DATA_SIZE)
        incl = TR_CAP_DATA_SIZE;
    const void *src = rte_pktmbuf_read(m, 0, incl, slot->data);
    if (!src) {
        atomic_fetch_add_explicit(&cap->drops, 1, memory_order_relaxed);
        rte_ring_enqueue(cap->free_ring, slot);
        atomic_fetch_sub_explicit(&cap->inflight, 1, memory_order_release);
        return;
    }
    if (src != slot->data)
        memcpy(slot->data, src, incl);
    clock_gettime(CLOCK_REALTIME, &slot->ts);
    slot->orig_len = len;
    slot->incl_len = incl;
    if (rte_ring_enqueue(cap->full_ring, slot) != 0) {
        atomic_fetch_add_explicit(&cap->drops, 1, memory_order_relaxed);
        rte_ring_enqueue(cap->free_ring, slot);
    }
    atomic_fetch_sub_explicit(&cap->inflight, 1, memory_order_release);
}

void tr_capture_tap(struct tr_capture *cap, int if_slot, unsigned direction,
                    const struct rte_mbuf *m)
{
    capture_tap_impl(cap, if_slot, direction, m, false);
}

void tr_capture_tap_exact(struct tr_capture *cap, int if_slot,
                          unsigned direction, const struct rte_mbuf *m)
{
    capture_tap_impl(cap, if_slot, direction, m, true);
}

void tr_capture_destroy(struct tr_capture *cap)
{
    if (!cap)
        return;
    if (atomic_load_explicit(&cap->active, memory_order_acquire))
        capture_close(cap, true);
    if (cap->free_ring)
        rte_ring_free(cap->free_ring);
    if (cap->full_ring)
        rte_ring_free(cap->full_ring);
    free(cap->slots);
    free(cap);
}

int tr_capture_status_text(struct tr_capture *cap, char **out)
{
    if (!cap)
        return -1;
    tr_capture_poll(cap);
    char *buf = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&buf, &n);
    if (!f)
        return -1;
    bool active = atomic_load_explicit(&cap->active, memory_order_acquire);
    if (!cap->ever_started) {
        fprintf(f, "capture: not started\n");
        fclose(f);
        *out = buf;
        return 0;
    }
    if (active)
        fprintf(f, "capture: active\n");
    else if (cap->stop_reason[0])
        fprintf(f, "capture: stopped (%s)\n", cap->stop_reason);
    else
        fprintf(f, "capture: stopped\n");
    fprintf(f, "  file: %s\n", cap->file);
    fprintf(f, "  interface: %s\n", cap->ifname);
    fprintf(f, "  direction: %s%s%s\n", cap->direction & TR_CAP_RX ? "rx" : "",
            cap->direction == TR_CAP_BOTH ? "+" : "",
            cap->direction & TR_CAP_TX ? "tx" : "");
    fprintf(f, "  filter: %s\n", cap->filter_expr[0] ? cap->filter_expr : "all");
    fprintf(f, "  snaplen: %u\n", cap->snaplen);
    fprintf(f, "  count: %llu%s\n", (unsigned long long)cap->count,
            cap->count ? "" : " (unlimited)");
    fprintf(f, "  packets: %llu bytes: %llu drops: %llu\n",
            (unsigned long long)cap->packets, (unsigned long long)cap->bytes,
            (unsigned long long)atomic_load(&cap->drops));
    if (cap->started) {
        char tbuf[64];
        struct tm tm;
        localtime_r(&cap->started, &tm);
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);
        fprintf(f, "  started: %s\n", tbuf);
    }
    if (cap->error[0])
        fprintf(f, "  error: %s\n", cap->error);
    fclose(f);
    *out = buf;
    return 0;
}
