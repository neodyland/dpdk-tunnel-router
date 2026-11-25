#ifndef TR_CONFIG_INTERNAL_H
#define TR_CONFIG_INTERNAL_H

#include "config.h"

int tr_config_validate(const struct tr_config *cfg,
                       const struct tr_config_env *env, char *err,
                       size_t errlen);
bool tr_config_name_valid(const char *name);
void tr_config_iface_clear(struct tr_iface *iface);
int tr_config_add_addr(struct tr_iface *iface, const struct tr_prefix *addr,
                       char *err, size_t errlen);
int tr_config_del_addr(struct tr_iface *iface, const struct tr_prefix *addr,
                       bool autoconf, char *err, size_t errlen);
struct tr_iface *tr_config_ensure_ethernet(struct tr_config *cfg,
                                           const char *name,
                                           const struct tr_config_env *env,
                                           char *err, size_t errlen);
void tr_config_detach_bridge(struct tr_config *cfg, struct tr_iface *iface);
int tr_config_add_child(struct tr_config *cfg, struct tr_iface *bridge,
                        struct tr_iface *child, char *err, size_t errlen);

#endif
