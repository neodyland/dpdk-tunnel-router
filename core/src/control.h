#ifndef TR_CONTROL_H
#define TR_CONTROL_H

#include <stddef.h>

struct tr_control;

struct tr_control_ops {
    /* Per-client session.  The core uses this to keep a candidate
     * configuration for configuration mode. */
    void *(*session_open)(void *arg);
    void (*session_close)(void *arg, void *session);
    /* Execute one command line.  On success return 0 and allocate *body
     * (possibly NULL).  On failure return -1 and allocate *error_text. */
    int (*execute)(void *arg, void *session, const char *line, char **body,
                   char **error_text);
};

struct tr_control *tr_control_create(const char *path,
                                     const struct tr_control_ops *ops,
                                     void *arg, char *err, size_t errlen);
void tr_control_poll(struct tr_control *c, int timeout_ms);
void tr_control_destroy(struct tr_control *c);

#endif
