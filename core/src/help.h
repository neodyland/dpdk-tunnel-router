#ifndef TR_HELP_H
#define TR_HELP_H

#include "config.h"

#include <stdbool.h>
#include <stddef.h>

int tr_help_command(const struct tr_config *cfg, int nports, bool config_mode,
                    int argc, char **argv, char **out);

#endif
