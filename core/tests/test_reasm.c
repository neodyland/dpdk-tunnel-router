#include "test_common.h"

#include "reasm.h"
#include "addr.h"

#include <stdlib.h>

static uint16_t ip_checksum(const uint8_t *p, size_t n)
{
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < n; i += 2)
        sum += (uint32_t)(p[i] << 8 | p[i + 1]);
    if (n & 1)
        sum += (uint32_t)p[n - 1] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static int test_frag4(void)
{
    const uint32_t payload = 9000;
    uint32_t total = 20 + payload;
    uint8_t *pkt = calloc(1, total);
    CHECK(pkt != NULL);
    pkt[0] = 0x45;
    pkt[2] = (uint8_t)(total >> 8);
    pkt[3] = (uint8_t)total;
    pkt[4] = 0x12;
    pkt[5] = 0x34;
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12] = 192;
    pkt[13] = 0;
    pkt[14] = 2;
    pkt[15] = 1;
    pkt[16] = 198;
    pkt[17] = 51;
    pkt[18] = 100;
    pkt[19] = 2;
    for (uint32_t i = 20; i < total; i++)
        pkt[i] = (uint8_t)(i * 7);
    uint16_t csum = ip_checksum(pkt, 20);
    pkt[10] = (uint8_t)(csum >> 8);
    pkt[11] = (uint8_t)csum;

    struct tr_frag_packet frags[TR_FRAG_MAX_OUT];
    int n = tr_frag4(pkt, total, 1500, frags, TR_FRAG_MAX_OUT);
    CHECK(n > 1);
    struct tr_reasm r;
    tr_reasm_init(&r);
    struct tr_reasm_out out = {0};
    struct tr_ip src = {.family = TR_AF_INET}, dst = {.family = TR_AF_INET};
    memcpy(&src.u.v4, pkt + 12, 4);
    memcpy(&dst.u.v4, pkt + 16, 4);
    int complete = 0;
    for (int i = n - 1; i >= 0; i--) {
        uint8_t *q = frags[i].data;
        uint16_t fo = (uint16_t)(q[6] << 8 | q[7]);
        uint32_t off = (uint32_t)(fo & 0x1fff) * 8;
        bool more = (fo & 0x2000) != 0;
        uint32_t ihl = (uint32_t)(q[0] & 0x0f) * 4;
        uint32_t flen = (uint32_t)(q[2] << 8 | q[3]);
        int rc = tr_reasm4_input(&r, 0, &src, &dst, (uint16_t)(q[4] << 8 | q[5]),
                                 q[9], q, ihl, off, more, q + ihl,
                                 flen - ihl, 1000, &out);
        CHECK(rc >= 0);
        if (rc == 1) {
            CHECK(!complete);
            complete = 1;
        }
    }
    CHECK(complete);
    CHECK(out.len == total);
    CHECK(memcmp(out.data, pkt, total) == 0);
    free(out.data);
    for (int i = 0; i < n; i++)
        free(frags[i].data);
    tr_reasm_fini(&r);
    free(pkt);
    return 0;
}

static int test_frag6(void)
{
    const uint32_t payload = 9000;
    uint32_t total = 40 + payload;
    uint8_t *pkt = calloc(1, total);
    CHECK(pkt != NULL);
    pkt[0] = 0x60;
    pkt[4] = (uint8_t)(payload >> 8);
    pkt[5] = (uint8_t)payload;
    pkt[6] = 97;
    pkt[7] = 64;
    pkt[8] = 0x20;
    pkt[9] = 0x01;
    pkt[10] = 0x0d;
    pkt[11] = 0xb8;
    pkt[24] = 0x20;
    pkt[25] = 0x01;
    pkt[26] = 0x0d;
    pkt[27] = 0xb8;
    pkt[39] = 2;
    for (uint32_t i = 40; i < total; i++)
        pkt[i] = (uint8_t)(i * 3);

    struct tr_frag_packet frags[TR_FRAG_MAX_OUT];
    int n = tr_frag6(pkt, total, 1500, 0xabcdef01, frags, TR_FRAG_MAX_OUT);
    CHECK(n > 1);
    struct tr_reasm r;
    tr_reasm_init(&r);
    struct tr_reasm_out out = {0};
    struct tr_ip src = {.family = TR_AF_INET6}, dst = {.family = TR_AF_INET6};
    memcpy(&src.u.v6, pkt + 8, 16);
    memcpy(&dst.u.v6, pkt + 24, 16);
    int complete = 0;
    for (int i = n - 1; i >= 0; i--) {
        uint8_t *q = frags[i].data;
        uint16_t fo = (uint16_t)(q[42] << 8 | q[43]);
        uint32_t off = fo & 0xfff8;
        bool more = (fo & 1) != 0;
        uint32_t plen = (uint32_t)(q[4] << 8 | q[5]);
        int rc = tr_reasm6_input(&r, 0, &src, &dst,
                                 (uint32_t)q[44] << 24 |
                                     (uint32_t)q[45] << 16 |
                                     (uint32_t)q[46] << 8 | q[47],
                                 q[40], q, 40, off, more, q + 48, plen - 8,
                                 1000, &out);
        CHECK(rc >= 0);
        if (rc == 1) {
            CHECK(!complete);
            complete = 1;
        }
    }
    CHECK(complete);
    CHECK(out.len == total);
    CHECK(memcmp(out.data, pkt, total) == 0);
    free(out.data);
    for (int i = 0; i < n; i++)
        free(frags[i].data);
    tr_reasm_fini(&r);
    free(pkt);
    return 0;
}

static int test_overlap(void)
{
    struct tr_reasm r;
    struct tr_reasm_out out = {0};
    struct tr_ip src = {.family = TR_AF_INET}, dst = {.family = TR_AF_INET};
    uint8_t hdr[20] = {0x45};
    uint8_t payload[32] = {0};
    tr_reasm_init(&r);
    CHECK(tr_reasm4_input(&r, 0, &src, &dst, 1, 17, hdr, 20, 0, true, payload,
                          8, 1000, &out) == 0);
    CHECK(tr_reasm4_input(&r, 0, &src, &dst, 1, 17, hdr, 20, 0, true, payload,
                          16, 1000, &out) == -1);
    tr_reasm_fini(&r);
    return 0;
}

int main(void)
{
    int rc = 0;
    rc |= test_frag4();
    rc |= test_frag6();
    rc |= test_overlap();
    if (rc == 0)
        printf("test_reasm: ok\n");
    return rc;
}
