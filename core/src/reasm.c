#include "reasm.h"

#include "util.h"

#include <stdlib.h>
#include <string.h>

#define REASM_MAX_PACKET 16384

static void entry_free(struct tr_reasm_entry *e)
{
    free(e->payload);
    free(e->bitmap);
    memset(e, 0, sizeof(*e));
}

void tr_reasm_init(struct tr_reasm *r)
{
    memset(r, 0, sizeof(*r));
}

void tr_reasm_fini(struct tr_reasm *r)
{
    for (int i = 0; i < TR_REASM_MAX_ENTRIES; i++)
        entry_free(&r->entries[i]);
}

void tr_reasm_expire(struct tr_reasm *r, uint64_t now_ms)
{
    for (int i = 0; i < TR_REASM_MAX_ENTRIES; i++) {
        struct tr_reasm_entry *e = &r->entries[i];
        if (e->used && now_ms > e->last_seen &&
            now_ms - e->last_seen > TR_REASM_TIMEOUT_MS)
            entry_free(e);
    }
}

static struct tr_reasm_entry *entry_get(struct tr_reasm *r, int if_slot,
                                        uint8_t family,
                                        const struct tr_ip *src,
                                        const struct tr_ip *dst, uint32_t id,
                                        uint8_t proto, uint64_t now)
{
    struct tr_reasm_entry *oldest = NULL;

    for (int i = 0; i < TR_REASM_MAX_ENTRIES; i++) {
        struct tr_reasm_entry *e = &r->entries[i];
        if (!e->used)
            continue;
        if (e->if_slot == if_slot && e->family == family && e->id == id &&
            e->proto == proto && tr_ip_equal(&e->src, src) &&
            tr_ip_equal(&e->dst, dst)) {
            e->last_seen = now;
            return e;
        }
        if (!oldest || e->last_seen < oldest->last_seen)
            oldest = e;
    }
    for (int i = 0; i < TR_REASM_MAX_ENTRIES; i++) {
        struct tr_reasm_entry *e = &r->entries[i];
        if (!e->used) {
            memset(e, 0, sizeof(*e));
            e->used = true;
            e->if_slot = if_slot;
            e->family = family;
            e->src = *src;
            e->dst = *dst;
            e->id = id;
            e->proto = proto;
            e->last_seen = now;
            return e;
        }
    }
    if (oldest) {
        entry_free(oldest);
        return entry_get(r, if_slot, family, src, dst, id, proto, now);
    }
    return NULL;
}

static int entry_prepare(struct tr_reasm_entry *e, uint32_t total)
{
    if (total > REASM_MAX_PACKET)
        return -1;
    if (!e->payload) {
        e->payload = calloc(1, REASM_MAX_PACKET);
        e->bitmap = calloc(1, REASM_MAX_PACKET);
        if (!e->payload || !e->bitmap)
            return -1;
    }
    return 0;
}

static int entry_add_fragment(struct tr_reasm_entry *e, uint32_t off,
                              uint32_t len, const uint8_t *payload, bool more,
                              uint64_t now)
{
    if (off % 8 || (more && (len % 8)))
        return -1;
    if (off > REASM_MAX_PACKET || len > REASM_MAX_PACKET - off)
        return -1;
    if (e->nfrags >= TR_REASM_MAX_FRAGS)
        return -1;
    if (e->have_total && off + len > e->total_len)
        return -1;

    for (int i = 0; i < e->nfrags; i++) {
        uint32_t a0 = e->frags[i].off;
        uint32_t a1 = a0 + e->frags[i].len;
        uint32_t b0 = off;
        uint32_t b1 = off + len;
        if (b0 < a1 && a0 < b1) {
            if (a0 == b0 && a1 == b1)
                return 0; /* duplicate retransmission */
            return -1; /* overlap is rejected (RFC 5722 for IPv6) */
        }
    }

    if (!more) {
        if (e->have_total && e->total_len != off + len)
            return -1;
        e->total_len = off + len;
        e->have_total = true;
    }
    if (e->total_len > 0 || e->have_total) {
        uint32_t need = e->have_total ? e->total_len : off + len;
        if (entry_prepare(e, need))
            return -1;
    }
    if (!e->payload) {
        if (entry_prepare(e, REASM_MAX_PACKET))
            return -1;
    }
    if (e->have_total && off + len > e->total_len)
        return -1;
    memcpy(e->payload + off, payload, len);
    for (uint32_t i = 0; i < len; i++) {
        if (!e->bitmap[off + i]) {
            e->bitmap[off + i] = 1;
            e->received++;
        }
    }
    e->frags[e->nfrags].off = off;
    e->frags[e->nfrags].len = len;
    e->nfrags++;
    e->last_seen = now;
    return 0;
}

static int entry_complete(const struct tr_reasm_entry *e)
{
    return e->have_total && e->received == e->total_len;
}

static int emit4(struct tr_reasm_entry *e, struct tr_reasm_out *out)
{
    uint32_t hlen = e->header_len;
    uint32_t total = hlen + e->total_len;
    uint8_t *p;

    if (hlen < 20 || total > 65535)
        return -1;
    p = malloc(total);
    if (!p)
        return -1;
    memcpy(p, e->header, hlen);
    p[2] = (uint8_t)(total >> 8);
    p[3] = (uint8_t)total;
    p[6] = 0;
    p[7] = 0;
    p[10] = 0;
    p[11] = 0;
    uint16_t csum = tr_checksum16(p, hlen, 0);
    p[10] = (uint8_t)(csum >> 8);
    p[11] = (uint8_t)csum;
    memcpy(p + hlen, e->payload, e->total_len);
    out->data = p;
    out->len = total;
    out->family = 4;
    return 1;
}

static int emit6(struct tr_reasm_entry *e, struct tr_reasm_out *out)
{
    uint32_t hlen = e->header_len;
    uint32_t total = hlen + e->total_len;
    uint8_t *p;

    if (hlen < 40)
        return -1;
    p = malloc(total);
    if (!p)
        return -1;
    memcpy(p, e->header, hlen);
    uint32_t plen = hlen - 40 + e->total_len;
    if (plen > 65535)
        return -1;
    p[4] = (uint8_t)(plen >> 8);
    p[5] = (uint8_t)plen;
    if (hlen == 40)
        p[6] = e->proto;
    memcpy(p + hlen, e->payload, e->total_len);
    out->data = p;
    out->len = total;
    out->family = 6;
    return 1;
}

int tr_reasm4_input(struct tr_reasm *r, int if_slot, const struct tr_ip *src,
                    const struct tr_ip *dst, uint16_t id, uint8_t proto,
                    const uint8_t *header, uint32_t header_len,
                    uint32_t frag_off, bool more, const uint8_t *payload,
                    uint32_t payload_len, uint64_t now_ms,
                    struct tr_reasm_out *out)
{
    struct tr_reasm_entry *e;

    if (!header || header_len < 20 || header_len > 60 ||
        frag_off % 8)
        return -1;
    if (frag_off + payload_len > REASM_MAX_PACKET)
        return -1;
    e = entry_get(r, if_slot, 4, src, dst, id, proto, now_ms);
    if (!e)
        return -1;
    if (frag_off == 0) {
        if (header_len > sizeof(e->header))
            return -1;
        memcpy(e->header, header, header_len);
        e->header_len = header_len;
    }
    if (entry_add_fragment(e, frag_off, payload_len, payload, more, now_ms))
        return -1;
    if (entry_complete(e)) {
        int rc = emit4(e, out);
        entry_free(e);
        return rc;
    }
    return 0;
}

int tr_reasm6_input(struct tr_reasm *r, int if_slot, const struct tr_ip *src,
                    const struct tr_ip *dst, uint32_t id, uint8_t next_header,
                    const uint8_t *unfrag, uint32_t unfrag_len,
                    uint32_t frag_off, bool more, const uint8_t *payload,
                    uint32_t payload_len, uint64_t now_ms,
                    struct tr_reasm_out *out)
{
    struct tr_reasm_entry *e;

    if (!unfrag || unfrag_len < 40 || unfrag_len > 256 || frag_off % 8)
        return -1;
    if (frag_off + payload_len > REASM_MAX_PACKET)
        return -1;
    e = entry_get(r, if_slot, 6, src, dst, id, next_header, now_ms);
    if (!e)
        return -1;
    if (frag_off == 0) {
        memcpy(e->header, unfrag, unfrag_len);
        e->header_len = unfrag_len;
    }
    if (entry_add_fragment(e, frag_off, payload_len, payload, more, now_ms))
        return -1;
    if (entry_complete(e)) {
        int rc = emit6(e, out);
        entry_free(e);
        return rc;
    }
    return 0;
}

int tr_frag4(const uint8_t *pkt, uint32_t len, uint32_t mtu,
             struct tr_frag_packet *out, int max_out)
{
    uint32_t ihl, total, payload_len, chunk, off;
    int n = 0;

    if (!pkt || len < 20 || (pkt[0] >> 4) != 4)
        return -1;
    ihl = (uint32_t)(pkt[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > len)
        return -1;
    total = (uint32_t)(pkt[2] << 8 | pkt[3]);
    if (total < ihl || total > len)
        return -1;
    if (total <= mtu)
        return 0;
    if (mtu <= ihl)
        return -1;
    chunk = (mtu - ihl) & ~7u;
    if (chunk < 8)
        return -1;
    payload_len = total - ihl;
    off = 0;
    while (off < payload_len) {
        uint32_t nlen = payload_len - off;
        bool more;
        uint8_t *p;

        if (nlen > chunk)
            nlen = chunk;
        more = off + nlen < payload_len;
        if (n >= max_out)
            goto fail;
        p = malloc(ihl + nlen);
        if (!p)
            goto fail;
        memcpy(p, pkt, ihl);
        uint32_t frag_total = ihl + nlen;
        p[2] = (uint8_t)(frag_total >> 8);
        p[3] = (uint8_t)frag_total;
        uint16_t flags = (uint16_t)((more ? 0x2000 : 0) | (off / 8));
        p[6] = (uint8_t)(flags >> 8);
        p[7] = (uint8_t)flags;
        p[10] = 0;
        p[11] = 0;
        uint16_t csum = tr_checksum16(p, ihl, 0);
        p[10] = (uint8_t)(csum >> 8);
        p[11] = (uint8_t)csum;
        memcpy(p + ihl, pkt + ihl + off, nlen);
        out[n].data = p;
        out[n].len = frag_total;
        n++;
        off += nlen;
    }
    return n;
fail:
    for (int i = 0; i < n; i++)
        free(out[i].data);
    return -1;
}

int tr_frag6(const uint8_t *pkt, uint32_t len, uint32_t mtu, uint32_t id,
             struct tr_frag_packet *out, int max_out)
{
    uint32_t total, payload_len, chunk, off;
    uint8_t next_header;
    int n = 0;

    if (!pkt || len < 40 || (pkt[0] >> 4) != 6)
        return -1;
    total = 40u + (uint32_t)(pkt[4] << 8 | pkt[5]);
    if (total > len)
        return -1;
    if (total <= mtu)
        return 0;
    if (mtu <= 48)
        return -1;
    chunk = (mtu - 48) & ~7u;
    if (chunk < 8)
        return -1;
    next_header = pkt[6];
    payload_len = total - 40;
    off = 0;
    if (!id)
        id = tr_random_u32();
    while (off < payload_len) {
        uint32_t nlen = payload_len - off;
        bool more;
        uint8_t *p;
        uint32_t plen;

        if (nlen > chunk)
            nlen = chunk;
        more = off + nlen < payload_len;
        if (n >= max_out)
            goto fail;
        p = malloc(48 + nlen);
        if (!p)
            goto fail;
        memcpy(p, pkt, 40);
        plen = 8 + nlen;
        p[4] = (uint8_t)(plen >> 8);
        p[5] = (uint8_t)plen;
        p[6] = 44; /* Fragment header */
        p[40] = next_header;
        p[41] = 0;
        uint16_t fo = (uint16_t)((more ? 1u : 0u) | ((off / 8) << 3));
        p[42] = (uint8_t)(fo >> 8);
        p[43] = (uint8_t)fo;
        p[44] = (uint8_t)(id >> 24);
        p[45] = (uint8_t)(id >> 16);
        p[46] = (uint8_t)(id >> 8);
        p[47] = (uint8_t)id;
        memcpy(p + 48, pkt + 40 + off, nlen);
        out[n].data = p;
        out[n].len = 48 + nlen;
        n++;
        off += nlen;
    }
    return n;
fail:
    for (int i = 0; i < n; i++)
        free(out[i].data);
    return -1;
}
