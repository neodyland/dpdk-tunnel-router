#ifndef TR_REASM_H
#define TR_REASM_H

#include "addr.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TR_REASM_MAX_ENTRIES 64
#define TR_REASM_TIMEOUT_MS 10000
#define TR_REASM_MAX_FRAGS 128
#define TR_FRAG_MAX_OUT 128

struct tr_reasm_frag {
    uint32_t off;
    uint32_t len;
};

struct tr_reasm_entry {
    bool used;
    int if_slot;
    uint8_t family;
    struct tr_ip src;
    struct tr_ip dst;
    uint32_t id;
    uint8_t proto;
    uint32_t total_len;
    bool have_total;
    uint8_t header[256];
    uint32_t header_len;
    uint8_t *payload;
    uint8_t *bitmap;
    uint32_t bitmap_len;
    uint32_t received;
    struct tr_reasm_frag frags[TR_REASM_MAX_FRAGS];
    int nfrags;
    uint64_t last_seen;
};

struct tr_reasm {
    struct tr_reasm_entry entries[TR_REASM_MAX_ENTRIES];
};

struct tr_reasm_out {
    uint8_t *data;
    uint32_t len;
    uint8_t family;
};

void tr_reasm_init(struct tr_reasm *r);
void tr_reasm_fini(struct tr_reasm *r);
void tr_reasm_expire(struct tr_reasm *r, uint64_t now_ms);

/*
 * Feed one outer fragment.  `header` is the IPv4 header (ihl bytes) or the
 * IPv6 unfragmentable part including the base header (without the fragment
 * header).  `payload` points after the IP header / fragment header.  Returns
 * 1 when a complete packet is produced in *out (caller frees out->data),
 * 0 when more fragments are needed, -1 on malformed input.
 */
int tr_reasm4_input(struct tr_reasm *r, int if_slot, const struct tr_ip *src,
                    const struct tr_ip *dst, uint16_t id, uint8_t proto,
                    const uint8_t *header, uint32_t header_len,
                    uint32_t frag_off, bool more, const uint8_t *payload,
                    uint32_t payload_len, uint64_t now_ms,
                    struct tr_reasm_out *out);
int tr_reasm6_input(struct tr_reasm *r, int if_slot, const struct tr_ip *src,
                    const struct tr_ip *dst, uint32_t id, uint8_t next_header,
                    const uint8_t *unfrag, uint32_t unfrag_len,
                    uint32_t frag_off, bool more, const uint8_t *payload,
                    uint32_t payload_len, uint64_t now_ms,
                    struct tr_reasm_out *out);

struct tr_frag_packet {
    uint8_t *data;
    uint32_t len;
};

/* Fragment a complete IPv4/IPv6 packet to `mtu` (IP MTU, no Ethernet header).
 * Returns number of fragments (>=1) or -1.  Caller frees each data pointer. */
int tr_frag4(const uint8_t *pkt, uint32_t len, uint32_t mtu,
             struct tr_frag_packet *out, int max_out);
int tr_frag6(const uint8_t *pkt, uint32_t len, uint32_t mtu, uint32_t id,
             struct tr_frag_packet *out, int max_out);

#endif
