#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdlib.h>
#include <stdint.h>

// Maximum length of interface name
// FIXME: The value should probably be used from IFNAMSIZ
#define INTERFACE_NAME_MAX_LEN 24

#define CONF_ERRBUF_SIZE 1024

#define FILTER_EVENT_BEGIN 1
#define FILTER_EVENT_END 2

struct config_filter
{
	char *name;
	char *match;
	char *session_begin;
	char *session_end;
	char *interface;
	uint32_t session_timeout;
};

struct config
{
	struct config_filter *filter;
	uint32_t filter_cnt;
};

extern struct config* config_open (const char *filename, char *errbuf);

extern void config_close (struct config *conf);

#endif

