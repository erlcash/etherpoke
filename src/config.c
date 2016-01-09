/*
 * Copyright (c) 2013 - 2015, CodeWard.org
 */
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <libconfig.h>

#include "session_event.h"
#include "config.h"

static int
filter_set_name (struct config_filter *filter, const char *name)
{
	if ( filter->name != NULL )
		free (filter->name);

	if ( name == NULL ){
		filter->name = NULL;
		return 0;
	}

	filter->name = strdup (name);
	
	if ( filter->name == NULL )
		return 1;
	
	return 0;
}

static int
filter_set_matchrule (struct config_filter *filter, const char *rule)
{
	if ( filter->match != NULL )
		free (filter->match);

	if ( rule == NULL ){
		filter->match = NULL;
		return 0;
	}

	filter->match = strdup (rule);

	if ( filter->match == NULL )
		return 1;
	
	return 0;
}

static int
filter_set_interface (struct config_filter *filter, const char *interface)
{
	if ( filter->interface != NULL )
		free (filter->interface);

	if ( interface == NULL ){
		filter->interface = NULL;
		return 0;
	}

	filter->interface = strdup (interface);

	if ( filter->interface == NULL )
		return 1;
	
	return 0;
}

static int
filter_set_event (struct config_filter *filter, const char *cmd, int type)
{
	char **filter_event;
	
	switch ( type ){
		case SE_BEG:
			filter_event = &(filter->session_begin);
			break;
		case SE_END:
			filter_event = &(filter->session_end);
			break;
		case SE_ERR:
			filter_event = &(filter->session_error);
			break;
		default:
			return 1;
	}
	
	if ( *filter_event != NULL )
		free (*filter_event);

	if ( cmd == NULL ){
		*filter_event = NULL;
		return 0;
	}
	
	*filter_event = strdup (cmd);
	
	if ( *filter_event == NULL )
		return 1;
	
	return 0;
}

static void
filter_set_session_timeout (struct config_filter *filter, uint32_t session_timeout)
{
	filter->session_timeout = session_timeout;
}

static void
filter_set_monitor_mode (struct config_filter *filter, uint8_t monitor_mode)
{
	filter->rfmon = monitor_mode;
}

static int
filter_set_link_type (struct config_filter *filter, const char *link_type)
{
	if ( filter->link_type != NULL )
		free (filter->link_type);

	if ( link_type == NULL ){
		filter->link_type = NULL;
		return 1;
	}

	filter->link_type = strdup (link_type);

	if ( filter->link_type == NULL )
		return 1;

	return 0;
}

static void
filter_set_notify (struct config_filter *filter, uint8_t notify_type)
{
	filter->notify |= notify_type;
}

static void
filter_destroy (struct config_filter *filter)
{
	if ( filter->name != NULL )
		free (filter->name);
	if ( filter->match != NULL )
		free (filter->match);
	if ( filter->session_begin != NULL )
		free (filter->session_begin);
	if ( filter->session_end != NULL )
		free (filter->session_end);
	if ( filter->session_error != NULL )
		free (filter->session_error);
	if ( filter->interface != NULL )
		free (filter->interface);
	if ( filter->link_type != NULL )
		free (filter->link_type);
}

int
config_load (struct config *conf, const char *filename, char *errbuf)
{
	config_t libconfig;
	config_setting_t *root_setting;
	config_setting_t *filter_setting;
	struct config_filter *filter;
	const char *str_val;
	int i, filter_cnt, num;

	config_init (&libconfig);

	if ( config_read_file (&libconfig, filename) == CONFIG_FALSE ){
		snprintf (errbuf, CONF_ERRBUF_SIZE, "%s on line %d", config_error_text (&libconfig), config_error_line (&libconfig));
		config_destroy (&libconfig);
		return -1;
	}

	root_setting = config_root_setting (&libconfig);
	filter_cnt = config_setting_length (root_setting);

	memset (errbuf, 0, sizeof (CONF_ERRBUF_SIZE));

	for ( i = 0; i < filter_cnt; i++ ){
		filter = (struct config_filter*) calloc (1, sizeof (struct config_filter));

		if ( filter == NULL ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "cannot allocate memory for filter");
			config_destroy (&libconfig);
			return -1;
		}

		filter_setting = config_setting_get_elem (root_setting, i);

		// Just in case... we do not want to touch the NULL pointer
		if ( filter_setting == NULL ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "no filters defined");
			free (filter);
			config_destroy (&libconfig);
			return -1;
		}

		str_val = config_setting_name (filter_setting);

		if ( str_val == NULL ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "in %d. filter, missing filter name", i + 1);
			free (filter);
			config_unload (conf);
			config_destroy (&libconfig);
			return -1;
		}

		if ( strlen (str_val) > CONF_FILTER_NAME_MAXLEN ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "filter name too long");
			free (filter);
			config_destroy (&libconfig);
			return -1;
		}

		filter_set_name (filter, str_val);

		if ( config_setting_lookup_string (filter_setting, "match", &str_val) == CONFIG_FALSE ){
			str_val = NULL;
		}

		filter_set_matchrule (filter, str_val);

		if ( config_setting_lookup_string (filter_setting, "session_begin", &str_val) == CONFIG_FALSE ){
			str_val = NULL;
		}

		filter_set_event (filter, str_val, SE_BEG);
	
		if ( config_setting_lookup_string (filter_setting, "session_end", &str_val) == CONFIG_FALSE ){
			str_val = NULL;
		}

		filter_set_event (filter, str_val, SE_END);

		if ( config_setting_lookup_string (filter_setting, "session_error", &str_val) == CONFIG_FALSE ){
			str_val = NULL;
		}

		filter_set_event (filter, str_val, SE_ERR);
	
		if ( config_setting_lookup_int (filter_setting, "session_timeout", &num) == CONFIG_FALSE ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "in filter '%s', missing option 'session_timeout'", filter->name);
			free (filter);
			config_unload (conf);
			config_destroy (&libconfig);
			return -1;
		}

		if ( num == 0 ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "in filter '%s', 'session_timeout' must be greater than 0", filter->name);
			free (filter);
			config_unload (conf);
			config_destroy (&libconfig);
			return -1;
		}
	
		filter_set_session_timeout (filter, ((num < 0)? (num * -1):num));

		if ( config_setting_lookup_bool (filter_setting, "monitor_mode", &num) == CONFIG_FALSE ){
			num = 0;
		}

		filter_set_monitor_mode (filter, num);

		if ( config_setting_lookup_string (filter_setting, "interface", &str_val) == CONFIG_FALSE ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "in filter '%s', missing option 'interface'", filter->name);
			free (filter);
			config_unload (conf);
			config_destroy (&libconfig);
			return -1;
		}

		if ( strlen (str_val) == 0 ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "in filter '%s', empty option 'interface'", filter->name);
			free (filter);
			config_unload (conf);
			config_destroy (&libconfig);
			return -1;
		}

		filter_set_interface (filter, str_val);

		if ( config_setting_lookup_string (filter_setting, "link_type", &str_val) == CONFIG_FALSE ){
			str_val = NULL;
		}

		filter_set_link_type (filter, str_val);

		if ( config_setting_lookup_bool (filter_setting, "notify_exec", &num) == CONFIG_FALSE ){
			// If options not specified, enable it by default
			num = NOTIFY_EXEC;
		} else {
			num = (num)? NOTIFY_EXEC:0;
		}

		filter_set_notify (filter, num);

		if ( config_setting_lookup_bool (filter_setting, "notify_sock", &num) == CONFIG_FALSE ){
			num = 0;
		} else {
			num = (num)? NOTIFY_SOCK:0;
		}

		filter_set_notify (filter, num);

		if ( conf->head == NULL ){
			conf->head = filter;
			conf->tail = conf->head;
		} else {
			conf->tail->next = filter;
			conf->tail = filter;
		}
	}

	config_destroy (&libconfig); // destroy libconfig object

	return filter_cnt;
}

void
config_unload (struct config *conf)
{
	struct config_filter *filter, *filter_next;

	filter = conf->head;

	while ( filter != NULL ){
		filter_next = filter->next;
		filter_destroy (filter);
		free (filter);
		filter = filter_next;
	}
}

