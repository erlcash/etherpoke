#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdlib.h>
#include <stdint.h>

// Maximum length of interface name
// FIXME: The value should probably be used from IFNAMSIZ
#define INTERFACE_NAME_MAX_LEN 24

#define FILTER_EVENT_BEGIN 0
#define FILTER_EVENT_END 1

typedef struct
{
	char *name;
	char *eth_addr;
	uint16_t eth_addr_bin;
	char *cmd_session_begin;
	char *cmd_session_end;
} filter_t;

typedef struct
{
	long int session_timeout;
	char **interfaces;
	unsigned int interfaces_count;
	filter_t *filters;
	unsigned int filters_count;
} conf_t;

extern conf_t* conf_init (const char *file);
extern void conf_destroy (conf_t *conf);

#endif
