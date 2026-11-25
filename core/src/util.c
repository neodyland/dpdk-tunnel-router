#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

uint64_t tr_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

uint64_t tr_now_sec(void)
{
    return (uint64_t)time(NULL);
}

uint64_t tr_monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

uint32_t tr_checksum_add(uint32_t sum, const void *data, size_t len)
{
    const uint8_t *p = data;

    while (len >= 2) {
        sum += (uint32_t)p[0] << 8 | p[1];
        p += 2;
        len -= 2;
    }
    if (len)
        sum += (uint32_t)p[0] << 8;
    return sum;
}

uint16_t tr_checksum16_finish(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

uint16_t tr_checksum16(const void *data, size_t len, uint32_t seed)
{
    return tr_checksum16_finish(tr_checksum_add(seed, data, len));
}

uint64_t tr_random_u64(void)
{
    static _Atomic uint64_t state = 0;
    uint64_t x = atomic_load_explicit(&state, memory_order_relaxed);
    uint64_t seed = 0;

    if (x == 0) {
        if (getrandom(&seed, sizeof(seed), GRND_NONBLOCK) != sizeof(seed))
            seed = tr_now_ms() ^ (uint64_t)getpid() << 32;
        if (seed == 0)
            seed = 0x9e3779b97f4a7c15ULL;
        atomic_store(&state, seed);
        x = seed;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    atomic_store_explicit(&state, x, memory_order_relaxed);
    return x;
}

uint32_t tr_random_u32(void)
{
    return (uint32_t)(tr_random_u64() >> 16);
}

int tr_parse_u32(const char *s, uint32_t min, uint32_t max, uint32_t *out)
{
    char *end = NULL;
    unsigned long v;

    if (!s || !*s)
        return -1;
    errno = 0;
    v = strtoul(s, &end, 0);
    if (errno || !end || *end || v < min || v > max)
        return -1;
    *out = (uint32_t)v;
    return 0;
}

int tr_parse_u16(const char *s, uint16_t min, uint16_t max, uint16_t *out)
{
    uint32_t v;

    if (tr_parse_u32(s, min, max, &v))
        return -1;
    *out = (uint16_t)v;
    return 0;
}

bool tr_is_hex(const char *s)
{
    if (!s || !*s)
        return false;
    for (; *s; s++) {
        if (!isxdigit((unsigned char)*s))
            return false;
    }
    return true;
}

void tr_format_mac(const uint8_t mac[6], char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int tr_parse_mac(const char *s, uint8_t mac[6])
{
    unsigned int b[6];
    char tail;

    if (sscanf(s, "%x:%x:%x:%x:%x:%x%c", &b[0], &b[1], &b[2], &b[3],
               &b[4], &b[5], &tail) != 6)
        return -1;
    for (int i = 0; i < 6; i++) {
        if (b[i] > 255)
            return -1;
        mac[i] = (uint8_t)b[i];
    }
    return 0;
}

void tr_mac_from_name(const char *name, uint8_t mac[6])
{
    /* Stable, locally administered unicast MAC derived from the interface
     * name.  FNV-1a keeps names like tun0 and tun1 far apart. */
    uint32_t h = 2166136261u;

    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }
    mac[0] = 0x02;
    mac[1] = (uint8_t)(h >> 24);
    mac[2] = (uint8_t)(h >> 16);
    mac[3] = (uint8_t)(h >> 8);
    mac[4] = (uint8_t)h;
    uint32_t h2 = h * 2654435761u;
    mac[5] = (uint8_t)(h2 >> 24);
}

bool tr_mac_is_multicast(const uint8_t mac[6])
{
    return (mac[0] & 0x01) != 0;
}

bool tr_mac_is_broadcast(const uint8_t mac[6])
{
    static const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    return memcmp(mac, bcast, 6) == 0;
}

bool tr_mac_is_zero(const uint8_t mac[6])
{
    static const uint8_t zero[6] = {0};
    return memcmp(mac, zero, 6) == 0;
}

char *tr_trim(char *s)
{
    char *end;

    while (*s && isspace((unsigned char)*s))
        s++;
    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return s;
}

int tr_split(char *line, char **argv, int max)
{
    int argc = 0;
    char *p = line;

    while (*p && argc < max) {
        while (*p && isspace((unsigned char)*p))
            p++;
        if (!*p)
            break;
        argv[argc++] = p;
        while (*p && !isspace((unsigned char)*p))
            p++;
        if (*p)
            *p++ = '\0';
    }
    return argc;
}

int tr_read_file(const char *path, char **out, size_t *out_len)
{
    int fd;
    struct stat st;
    char *buf;
    size_t off = 0;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) < 0 || st.st_size < 0 || st.st_size > (16 << 20)) {
        close(fd);
        return -1;
    }
    buf = malloc((size_t)st.st_size + 1);
    if (!buf) {
        close(fd);
        return -1;
    }
    while (off < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + off, (size_t)st.st_size - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            free(buf);
            close(fd);
            return -1;
        }
        if (n == 0)
            break;
        off += (size_t)n;
    }
    close(fd);
    buf[off] = '\0';
    *out = buf;
    if (out_len)
        *out_len = off;
    return 0;
}

int tr_write_file_atomic(const char *path, const char *data, size_t len,
                         mode_t mode)
{
    char tmp[512];
    int fd;
    size_t off = 0;
    int rc = -1;
    int n;

    n = snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp))
        return -1;
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0)
        return -1;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            goto out;
        }
        off += (size_t)w;
    }
    if (fsync(fd) < 0)
        goto out;
    if (close(fd) < 0) {
        fd = -1;
        goto out;
    }
    fd = -1;
    if (rename(tmp, path) < 0)
        goto out;
    rc = 0;
out:
    if (fd >= 0)
        close(fd);
    if (rc)
        unlink(tmp);
    return rc;
}
