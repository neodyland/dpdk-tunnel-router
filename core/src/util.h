#ifndef TR_UTIL_H
#define TR_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#define TR_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define TR_MIN(a, b) ((a) < (b) ? (a) : (b))
#define TR_MAX(a, b) ((a) > (b) ? (a) : (b))
#define TR_ALIGN_UP(v, a) (((v) + ((a) - 1)) & ~((a) - 1))

uint64_t tr_now_ms(void);
uint64_t tr_now_sec(void);
uint64_t tr_monotonic_ms(void);
uint64_t tr_monotonic_ns(void);

/* The per-packet checksum primitives live in the header so that the compiler
 * sees the constant header size at every call site and inlines the loop; this
 * is measurable on the forwarding path. */
static inline uint32_t tr_checksum_add(uint32_t sum, const void *data,
                                       size_t len)
{
    const uint8_t *p = data;

#if defined(__GNUC__) && defined(__BYTE_ORDER__) && \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    /* Fold four bytes at a time by byte-swapping the 32-bit load so that the
     * halfwords are accumulated in network order, exactly like the byte-wise
     * loop below.  ~30% cheaper for a 20-byte IPv4 header and several times
     * cheaper for full-size segments (TCP MSS clamping, ICMP, payloads). */
    while (len >= 4) {
        uint32_t w;

        memcpy(&w, p, 4);
        w = __builtin_bswap32(w);
        sum += w >> 16;
        sum += w & 0xffffu;
        p += 4;
        len -= 4;
    }
#endif
    while (len >= 2) {
        sum += (uint32_t)p[0] << 8 | p[1];
        p += 2;
        len -= 2;
    }
    if (len)
        sum += (uint32_t)p[0] << 8;
    return sum;
}

static inline uint16_t tr_checksum16_finish(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

static inline uint16_t tr_checksum16(const void *data, size_t len,
                                     uint32_t seed)
{
    return tr_checksum16_finish(tr_checksum_add(seed, data, len));
}

/* Verify the IPv4 header checksum (RFC 1071): a valid header, checksum field
 * included, sums to 0xFFFF.  The header is 20 bytes in virtually all traffic,
 * so that case is unrolled; other lengths fall back to the generic loop. */
static inline bool tr_ip4_cksum_ok(const void *data, size_t len)
{
    uint32_t sum;

#if defined(__GNUC__) && defined(__BYTE_ORDER__) && \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    if (len == 20) {
        const uint8_t *p = data;
        uint32_t w0, w1, w2, w3, w4;

        memcpy(&w0, p, 4);
        memcpy(&w1, p + 4, 4);
        memcpy(&w2, p + 8, 4);
        memcpy(&w3, p + 12, 4);
        memcpy(&w4, p + 16, 4);
        w0 = __builtin_bswap32(w0);
        w1 = __builtin_bswap32(w1);
        w2 = __builtin_bswap32(w2);
        w3 = __builtin_bswap32(w3);
        w4 = __builtin_bswap32(w4);
        sum = (w0 & 0xffffu) + (w0 >> 16) + (w1 & 0xffffu) + (w1 >> 16) +
              (w2 & 0xffffu) + (w2 >> 16) + (w3 & 0xffffu) + (w3 >> 16) +
              (w4 & 0xffffu) + (w4 >> 16);
        sum = (sum & 0xffffu) + (sum >> 16);
        sum = (sum & 0xffffu) + (sum >> 16);
        return sum == 0xffffu;
    }
#endif
    sum = tr_checksum_add(0, data, len);
    sum = (sum & 0xffffu) + (sum >> 16);
    sum = (sum & 0xffffu) + (sum >> 16);
    return sum == 0xffffu;
}

/* Update a valid one's complement checksum after a single 16-bit word changed
 * from `old_word` to `new_word` (RFC 1624 equation 3).  Cost is constant, so
 * a header whose only modification is the TTL does not need to be re-summed. */
static inline uint16_t tr_checksum16_update(uint16_t csum, uint16_t old_word,
                                           uint16_t new_word)
{
    uint32_t sum = (uint16_t)~csum + (uint16_t)~old_word + new_word;

    sum = (sum & 0xffffu) + (sum >> 16);
    sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

uint64_t tr_random_u64(void);
uint32_t tr_random_u32(void);

int tr_parse_u32(const char *s, uint32_t min, uint32_t max, uint32_t *out);
int tr_parse_u16(const char *s, uint16_t min, uint16_t max, uint16_t *out);
bool tr_is_hex(const char *s);

void tr_format_mac(const uint8_t mac[6], char out[18]);
int tr_parse_mac(const char *s, uint8_t mac[6]);
void tr_mac_from_name(const char *name, uint8_t mac[6]);
static inline bool tr_mac_is_multicast(const uint8_t mac[6])
{
    return (mac[0] & 0x01) != 0;
}

bool tr_mac_is_broadcast(const uint8_t mac[6]);
bool tr_mac_is_zero(const uint8_t mac[6]);

/* Split a mutable line on whitespace. Returns token count, stores up to max
 * pointers (the line is NUL-separated in place). */
int tr_split(char *line, char **argv, int max);

/* Trim leading/trailing whitespace in place. */
char *tr_trim(char *s);

int tr_read_file(const char *path, char **out, size_t *out_len);
int tr_write_file_atomic(const char *path, const char *data, size_t len,
                         mode_t mode);

#endif
