/*
 * Copyright (c) 2013 - 2015, CodeWard.org
 */
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <libconfig.h>

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
	char **event_type;
	
	switch ( type ){
		case FILTER_EVENT_BEGIN:
			event_type = &(filter->session_begin);
			break;
		case FILTER_EVENT_END:
			event_type = &(filter->session_end);
			break;
		case FILTER_EVENT_ERROR:
			event_type = &(filter->session_error);
			break;
		default:
			return 1;
	}
	
	if ( *event_type != NULL )
		free (*event_type);
	
	*event_type = strdup (cmd);
	
	if ( *event_type == NULL )
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

struct config*
config_open (const char *filename, char *errbuf)
{
	// libconfig structure
	config_t libconfig;
	config_setting_t *root_setting, *filter_setting, *interface_setting;
	struct config *conf;
	const char *str_val;
	int i, j, filter_cnt, interface_cnt, num;

	config_init (&libconfig);
	
	if ( config_read_file (&libconfig, filename) == CONFIG_FALSE ){
		snprintf (errbuf, CONF_ERRBUF_SIZE, "%s on line %d", config_error_text (&libconfig), config_error_line (&libconfig));
		config_destroy (&libconfig);
		return NULL;
	}

	root_setting = config_root_setting (&libconfig);
	filter_cnt = config_setting_length (root_setting);

	if ( filter_cnt == 0 ){
		snprintf (errbuf, CONF_ERRBUF_SIZE, "no packet capture filters specified");
		config_destroy (&libconfig);
		return NULL;
	}
	
	conf = (struct config*) malloc (sizeof (struct config));
	
	if ( conf == NULL ){
		config_destroy (&libconfig);
		return NULL;
	}
	
	memset (conf, 0, sizeof (struct config));
	memset (errbuf, 0, sizeof (CONF_ERRBUF_SIZE));

	conf->filter_cnt = filter_cnt;
	conf->filter = (struct config_filter*) malloc (sizeof (struct config_filter) * filter_cnt);
	
	if ( conf->filter == NULL ){
		config_close (conf);
		config_destroy (&libconfig);
		return NULL;
	}

	memset (conf->filter, 0, sizeof (struct config_filter) * filter_cnt);

	for ( i = 0; i < conf->filter_cnt; i++ ){
		filter_setting = config_setting_get_elem (root_setting, i);

		// Just in case... we do not want to touch the NULL pointer
		if ( filter_setting == NULL )
			break;

		str_val = config_setting_name (filter_setting);

		if ( str_val == NULL ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "in %d. filter, missing filter name", i + 1);
			config_close (conf);
			config_destroy (&libconfig);
			return NULL;
		}

		filter_set_name (&(conf->filter[i]), str_val);

		if ( config_setting_lookup_string (filter_setting, "match", &str_val) == CONFIG_FALSE ){
			str_val = NULL;
		}

		filter_set_matchrule (&(conf->filter[i]), str_val);

		if ( config_setting_lookup_string (filter_setting, "session_begin", &str_val) == CONFIG_FALSE ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "in filter '%s', missing option 'session_begin'", conf->filter[i].name);
			config_close (conf);
			config_destroy (&libconfig);
			return NULL;
		}
	
		filter_set_event (&(conf->filter[i]), str_val, FILTER_EVENT_BEGIN);
	
		if ( config_setting_lookup_string (filter_setting, "session_end", &str_val) == CONFIG_FALSE ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "in filter '%s', missing option 'session_end'", conf->filter[i].name);
			config_close (conf);
			config_destroy (&libconfig);
			return NULL;
		}
	
		filter_set_event (&(conf->filter[i]), str_val, FILTER_EVENT_END);

		if ( config_setting_lookup_string (filter_setting, "session_error", &str_val) == CONFIG_FALSE ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "in filter '%s', missing option 'session_error'", conf->filter[i].name);
			config_close (conf);
			config_destroy (&libconfig);
			return NULL;
		}

		filter_set_event (&(conf->filter[i]), str_val, FILTER_EVENT_ERROR);
	
		if ( config_setting_lookup_int (filter_setting, "session_timeout", &num) == CONFIG_FALSE ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "in filter '%s', missing option 'session_timeout'", conf->filter[i].name);
			config_close (conf);
			config_destroy (&libconfig);
			return NULL;
		}

		if ( num == 0 ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "in filter '%s', zero 'session_timeout' is not allowed", conf->filter[i].name);
			config_close (conf);
			config_destroy (&libconfig);
			return NULL;
		}
	
		filter_set_session_timeout (&(conf->filter[i]), ((num < 0)? (num * -1):num));

		if ( config_setting_lookup_bool (filter_setting, "monitor_mode", &num) == CONFIG_FALSE ){
			num = 0;
		}

		filter_set_monitor_mode (&(conf->filter[i]), num);

		if ( config_setting_lookup_string (filter_setting, "interface", &str_val) == CONFIG_FALSE ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "in filter '%s', missing option 'interface'", conf->filter[i].name);
			config_close (conf);
			config_destroy (&libconfig);
			return NULL;
		}

		if ( strlen (str_val) == 0 ){
			snprintf (errbuf, CONF_ERRBUF_SIZE, "in filter '%s', empty option 'interface'", conf->filter[i].name);
			config_close (conf);
			config_destroy (&libconfig);
			return NULL;
		}

		filter_set_interface (&(conf->filter[i]), str_val);

		if ( config_setting_lookup_string (filter_setting, "link_type", &str_val) == CONFIG_FALSE ){
			str_val = NULL;
		}

		filter_set_link_type (&(conf->filter[i]), str_val);
	}
	
	config_destroy (&libconfig); // destroy libconfig object
	
	return conf;
}

void
config_close (struct config *conf)
{
	int i;
	
	for ( i = 0; i < conf->filter_cnt; i++ )
		filter_destroy (&(conf->filter[i]));
	
	free (conf->filter);

	free (conf);
}

