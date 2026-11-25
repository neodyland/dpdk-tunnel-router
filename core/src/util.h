#ifndef TR_UTIL_H
#define TR_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define TR_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define TR_MIN(a, b) ((a) < (b) ? (a) : (b))
#define TR_MAX(a, b) ((a) > (b) ? (a) : (b))
#define TR_ALIGN_UP(v, a) (((v) + ((a) - 1)) & ~((a) - 1))

uint64_t tr_now_ms(void);
uint64_t tr_now_sec(void);
uint64_t tr_monotonic_ms(void);

uint16_t tr_checksum16(const void *data, size_t len, uint32_t seed);
uint16_t tr_checksum16_finish(uint32_t sum);
uint32_t tr_checksum_add(uint32_t sum, const void *data, size_t len);

uint64_t tr_random_u64(void);
uint32_t tr_random_u32(void);

int tr_parse_u32(const char *s, uint32_t min, uint32_t max, uint32_t *out);
int tr_parse_u16(const char *s, uint16_t min, uint16_t max, uint16_t *out);
bool tr_is_hex(const char *s);

void tr_format_mac(const uint8_t mac[6], char out[18]);
int tr_parse_mac(const char *s, uint8_t mac[6]);
void tr_mac_from_name(const char *name, uint8_t mac[6]);
bool tr_mac_is_multicast(const uint8_t mac[6]);
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
