#include <stdlib.h>
#include <string.h>
#include <libconfig.h>

#include "config.h"

static int
filter_set_name (filter_t *filter, const char *name)
{
	if ( filter->name != NULL )
		free (filter->name);
	
	filter->name = (char*) malloc (sizeof (char) * strlen (name) + 1);
		
	if ( filter->name == NULL )
		return 1;
	
	strncpy (filter->name, name, strlen (name));
	filter->name[strlen (name)] = '\0';
	
	return 0;
}

static int
filter_set_ethaddr (filter_t *filter, const char *eth_addr)
{
	if ( filter->eth_addr != NULL )
		free (filter->eth_addr);
	
	filter->eth_addr = (char*) malloc (sizeof (char) * strlen (eth_addr) + 1);
	
	if ( filter->eth_addr == NULL )
		return 1;
	
	strncpy (filter->eth_addr, eth_addr, strlen (eth_addr));
	filter->eth_addr[strlen (eth_addr)] = '\0';
	
	// Convert string representation to the 6 byte representation
	sscanf (filter->eth_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &(filter->eth_addr_bin[0]), &(filter->eth_addr_bin[1]),
													&(filter->eth_addr_bin[2]), &(filter->eth_addr_bin[3]),
													&(filter->eth_addr_bin[4]), &(filter->eth_addr_bin[5]));
	return 0;
}

static int
filter_set_event (filter_t *filter, const char *cmd, int type)
{
	char **event_type;
	
	switch ( type ){
		case FILTER_EVENT_BEGIN:
			event_type = &(filter->cmd_session_begin);
			break;
		case FILTER_EVENT_END:
			event_type = &(filter->cmd_session_end);
			break;
		default:
			return 1;
	}
	
	if ( *event_type != NULL )
		free (*event_type);
	
	*event_type = (char*) malloc (sizeof (char) * strlen (cmd) + 1);
	
	if ( *event_type == NULL )
		return 1;
	
	strncpy (*event_type, cmd, strlen (cmd));
	*((*event_type) + strlen (cmd)) = '\0';
	
	return 0;
}

static int
filter_set_session_timeout (filter_t *filter, uint32_t session_timeout)
{
	filter->session_timeout = session_timeout;
	
	return 0;
}

static void
filter_destroy (filter_t *filter)
{	
	if ( filter->name != NULL )
		free (filter->name);
	if ( filter->eth_addr != NULL )
		free (filter->eth_addr);
	if ( filter->cmd_session_begin != NULL )
		free (filter->cmd_session_begin);
	if ( filter->cmd_session_end != NULL )
		free (filter->cmd_session_end);
	
	free (filter);
	filter = NULL;
}

//
// conf_t functions
//

static int
conf_count_interfaces (config_t *conf)
{
	config_setting_t *interfaces;
	
	interfaces = config_lookup (conf, "common.interfaces");
	
	if ( interfaces == NULL )
		return -1;
	
	return config_setting_length (interfaces);
}

static int
conf_count_filters (config_t *conf)
{
	config_setting_t *filters;
	
	filters = config_lookup (conf, "filters");
	
	if ( filters == NULL )
		return -1;
	
	return config_setting_length (filters);
}

static int
conf_load_session_timeout (config_t *conf, long int *session_timeout)
{
	if ( config_lookup_int (conf, "common.session_timeout", session_timeout) == CONFIG_FALSE )
		return CONFIG_FALSE;
	
	return CONFIG_TRUE;
}

static int
conf_load_interfaces (config_t *conf, char *interfaces[], size_t length)
{
	config_setting_t *setting_interfaces;
	const char *val;
	int i;
	
	setting_interfaces = config_lookup (conf, "common.interfaces");
	
	if ( setting_interfaces == NULL )
		return CONFIG_FALSE;
	
	for ( i = 0; i < length; i++ ){
		val = config_setting_get_string_elem (setting_interfaces, i);
		
		if ( val == NULL )
			return CONFIG_FALSE;
		
		strncpy (interfaces[i], val, INTERFACE_NAME_MAX_LEN);
		interfaces[i][strlen (val)] = '\0';
	}
	
	return CONFIG_TRUE;
}

static int
conf_load_filters (config_t *conf, filter_t *filters, size_t length)
{
	const config_setting_t *setting_filters, *filter;
	const char *val;
	long num;
	int i;
	
	setting_filters = config_lookup (conf, "filters");
	
	if ( setting_filters == NULL )
		return CONFIG_FALSE;
	
	for ( i = 0; i < length; i++ ){
		filter = config_setting_get_elem (setting_filters, i);
		
		if ( filter == NULL )
			return CONFIG_FALSE;
		
		val = config_setting_name (filter);
		
		if ( val == NULL )
			return CONFIG_FALSE;
		
		filter_set_name (&(filters[i]), val);
		
		if ( config_setting_lookup_string (filter, "mac_addr", &val) == CONFIG_FALSE )
			return CONFIG_FALSE;
		
		filter_set_ethaddr (&(filters[i]), val);
		
		if ( config_setting_lookup_string (filter, "session_begin", &val) == CONFIG_FALSE )
			return CONFIG_FALSE;
		
		filter_set_event (&(filters[i]), val, FILTER_EVENT_BEGIN);
		
		if ( config_setting_lookup_string (filter, "session_end", &val) == CONFIG_FALSE )
			return CONFIG_FALSE;
		
		filter_set_event (&(filters[i]), val, FILTER_EVENT_END);
		
		if ( config_setting_lookup_int (filter, "session_timeout", &num) == CONFIG_FALSE )
			return CONFIG_FALSE;
		
		filter_set_session_timeout (&(filters[i]), num);
	}
	
	return CONFIG_TRUE;
}

extern conf_t*
conf_init (const char *file)
{
	conf_t *conf;
	config_t config; // libconfig structure
	int i;
	
	conf = (conf_t*) malloc (sizeof (conf_t));
	
	if ( conf == NULL )
		return NULL;
	
	memset (conf, 0, sizeof (conf_t));
	
	config_init (&config);
	
	if ( config_read_file (&config, file) == CONFIG_FALSE ){
		config_destroy (&config);
		conf_destroy (conf);
		return NULL;
	}
	
	// Load session timeout
	if ( conf_load_session_timeout (&config, &(conf->session_timeout)) == CONFIG_FALSE ){
		config_destroy (&config);
		conf_destroy (conf);
		return NULL;
	}
	
	// Load interfaces
	conf->interfaces_count = conf_count_interfaces (&config);
	
	if ( conf->interfaces_count == -1 ){
		config_destroy (&config);
		conf_destroy (conf);
		return NULL;
	}
	
	conf->interfaces = (char**) malloc (sizeof (char*) * conf->interfaces_count);
	
	if ( conf->interfaces == NULL ){
		config_destroy (&config);
		conf_destroy (conf);
		return NULL;
	}
	
	for ( i = 0; i < conf->interfaces_count; i++ ){
		conf->interfaces[i] = (char*) malloc (sizeof (char) * INTERFACE_NAME_MAX_LEN);
		
		if ( conf->interfaces[i] == NULL ){
			config_destroy (&config);
			conf_destroy (conf);
			return NULL;
		}
	}
	
	if ( conf_load_interfaces (&config, conf->interfaces, conf->interfaces_count) == CONFIG_FALSE ){
		config_destroy (&config);
		conf_destroy (conf);
		return NULL;
	}
	
	// Load filters
	conf->filters_count = conf_count_filters (&config);
	
	if ( conf->filters_count == -1 ){
		config_destroy (&config);
		conf_destroy (conf);
		return NULL;
	}
	
	conf->filters = (filter_t*) malloc (sizeof (filter_t) * conf->filters_count);
	
	if ( conf->filters == NULL ){
		config_destroy (&config);
		conf_destroy (conf);
		return NULL;
	}
	
	memset (conf->filters, 0, sizeof (filter_t) * conf->filters_count);
	
	if ( conf_load_filters (&config, conf->filters, conf->filters_count) == CONFIG_FALSE ){
		config_destroy (&config);
		conf_destroy (conf);
		return NULL;
	}
	
	config_destroy (&config);
	
	return conf;
}

void
conf_destroy (conf_t *conf)
{
	int i;
	
	for ( i = 0; i < conf->interfaces_count; i++ )
		free (conf->interfaces[i]);
	free (conf->interfaces);
	
	for ( i = 0; i < conf->filters_count; i++ )
		filter_destroy (&(conf->filters[i]));
	
	free (conf);
	conf = NULL;
}

