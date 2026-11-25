#ifndef TR_CAPTURE_H
#define TR_CAPTURE_H

#include <rte_mbuf.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TR_CAP_RX 0x1u
#define TR_CAP_TX 0x2u
#define TR_CAP_BOTH (TR_CAP_RX | TR_CAP_TX)
#define TR_CAP_IFNAME_LEN 48
#define TR_CAP_FILE_LEN 256
#define TR_CAP_FILTER_LEN 256
#define TR_CAP_SNAPLEN_MAX 16384

struct tr_capture;

int tr_capture_create(struct tr_capture **out, char *err, size_t errlen);
void tr_capture_destroy(struct tr_capture *cap);

/* if_slot < 0 means "any".  direction is TR_CAP_RX/TX/BOTH.
 * count == 0 means unlimited.  filter is a tiny tcpdump-like expression. */
int tr_capture_start(struct tr_capture *cap, int if_slot, const char *ifname,
                     const char *file, unsigned direction, uint32_t snaplen,
                     uint64_t count, const char *filter, char *err,
                     size_t errlen);
int tr_capture_stop(struct tr_capture *cap, char *err, size_t errlen);
void tr_capture_poll(struct tr_capture *cap);
void tr_capture_tap(struct tr_capture *cap, int if_slot, unsigned direction,
                    const struct rte_mbuf *m);
/* Capture only when the selected interface is exactly if_slot.  Used for
 * logical VLAN taps so interface "any" does not see tagged and untagged
 * copies of the same frame. */
void tr_capture_tap_exact(struct tr_capture *cap, int if_slot,
                          unsigned direction, const struct rte_mbuf *m);
int tr_capture_status_text(struct tr_capture *cap, char **out);

#endif
