#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <libconfig.h>

#include "config.h"

#include "listener.h"
#include "worker.h"
#include "executioner.h"

#define CONF_FILE "conf/etherpoke.conf"

int
main (int argc, char *argv[])
{
	config_t etherpoke_config;
	int64_t session_timeout;
	
	if ( conf_init (&etherpoke_config, CONF_FILE) == CONFIG_FALSE ){
		fprintf (stderr, "%s: cannot read configuration file '%s'\n", argv[0], CONF_FILE);
		exit (EXIT_FAILURE);
	}
	
	conf_load_session_timeout (&etherpoke_config, (long int*) &session_timeout);
	
	fprintf (stderr, "interfaces: %d\nsession_timeout: %ld\n", conf_count_interfaces (&etherpoke_config), session_timeout);

	conf_destroy (&etherpoke_config);

	return EXIT_SUCCESS;
}
