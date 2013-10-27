#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdlib.h>
#include <stdint.h>

// Maximum length of interface name
// FIXME: The value should probably be used from IFNAMSIZ
#define INTERFACE_NAME_MAX_LEN 24

extern int conf_init (config_t *conf, const char *file);
extern void conf_destroy (config_t *conf);

extern int conf_count_interfaces (config_t *conf);
extern int conf_count_filters (config_t *conf);

extern int conf_load_session_timeout (config_t *conf, long int *session_timeout);
extern int conf_load_interfaces (config_t *conf, char *interfaces[], size_t length);
//extern int conf_load_filters (config_t *conf, use_custom_type);

#endif
