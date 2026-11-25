#ifndef TR_TEST_COMMON_H
#define TR_TEST_COMMON_H

#include "config.h"
#include "tunnel.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
            return 1;                                                         \
        }                                                                     \
    } while (0)

static inline int test_apply(struct tr_config *cfg,
                             const struct tr_config_env *env, const char *line,
                             char *err, size_t errlen)
{
    char buf[1024];
    char *argv[64];
    int argc;

    snprintf(buf, sizeof(buf), "%s", line);
    argc = tr_split(buf, argv, (int)(sizeof(argv) / sizeof(argv[0])));
    return tr_config_apply(cfg, env, argc, argv, err, errlen);
}

static inline int test_apply_ok(struct tr_config *cfg,
                                const struct tr_config_env *env,
                                const char *line)
{
    char err[256];
    int rc = test_apply(cfg, env, line, err, sizeof(err));
    if (rc)
        fprintf(stderr, "command failed: %s: %s\n", line, err);
    return rc;
}

#endif
