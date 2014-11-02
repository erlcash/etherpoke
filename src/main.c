#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <pcap.h>
#include <libconfig.h>
#include <sys/stat.h>
#include <getopt.h>
#include <time.h>
#include <unistd.h>

#include "config.h"

#include "etherpoke.h"
#include "queue.h"
#include "log.h"

struct session_data
{
	int fd;
	int evt_flag;
	time_t ts;
};

int main_loop;

static void
etherpoke_help (const char *p)
{
	fprintf (stdout, "%s v%s\n\nUsage:\n"
					 "  %s [-dhv] -f <FILE>\n\n"
					 "Options:\n"
					 "  -f <FILE>\tconfiguration file\n"
					 "  -d\t\trun as a daemon\n"
					 "  -h\t\tshow this help text\n"
					 "  -v\t\tshow version information\n"
					 , p, ETHERPOKE_VER, p);
}

static void
etherpoke_version (const char *p)
{
	fprintf (stdout, "%s v%s\n", p, ETHERPOKE_VER);
}

int
main (int argc, char *argv[])
{
	pcap_t **pcap_handle;
	struct config *etherpoke_conf;
	char *config_file, conf_errbuff[CONF_ERRBUF_SIZE], pcap_errbuff[PCAP_ERRBUF_SIZE];
	struct session_data *pcap_session;
	int i, c, rval, daemonize;
	
	daemonize = 0;
	config_file = NULL;
	
	while ( (c = getopt (argc, argv, "f:dhv")) != -1 ){
		switch (c){
			case 'f':
				config_file = strdup (optarg);
				
				if ( config_file == NULL ){
					fprintf (stderr, "%s: cannot allocate memory for configuration file\n", argv[0]);
					return EXIT_FAILURE;
				}
				break;
			
			case 'd':
				daemonize = 1;
				break;
			
			case 'h':
				etherpoke_help (argv[0]);
				return EXIT_SUCCESS;
			
			case 'v':
				etherpoke_version (argv[0]);
				return EXIT_SUCCESS;
			
			default:
				etherpoke_help (argv[0]);
				return EXIT_FAILURE;
		}
	}

	if ( config_file == NULL ){
		fprintf (stderr, "%s: configuration file not specified. Use '-h' to see usage.\n", argv[0]);
		return EXIT_FAILURE;
	}
	
	etherpoke_conf = config_open (config_file, conf_errbuff);
	
	if ( etherpoke_conf == NULL ){
		fprintf (stderr, "%s: cannot load configuration file '%s': %s\n", argv[0], config_file, conf_errbuff);
		free (config_file);
		return EXIT_FAILURE;
	}

	if ( etherpoke_conf->filter_cnt == 0 ){
		fprintf (stderr, "%s: nothing to do, packet capture filters not specified.\n", argv[0]);
		return EXIT_FAILURE;
	}

	pcap_handle = (pcap_t**) malloc (sizeof (pcap_t*) * etherpoke_conf->filter_cnt);

	if ( pcap_handle == NULL ){
		fprintf (stderr, "%s: cannot allocate memory for packet capture.\n", argv[0]);
		return EXIT_FAILURE;
	}

	pcap_session = (struct session_data*) malloc (sizeof (struct session_data) * etherpoke_conf->filter_cnt);

	if ( pcap_session == NULL ){
		fprintf (stderr, "%s: cannot allocate memory for packet capture.\n", argv[0]);
		return EXIT_FAILURE;
	}

	memset (pcap_session, 0, sizeof (struct session_data) * etherpoke_conf->filter_cnt);

	//
	// Prepare packet capture
	//
	for ( i = 0; i < etherpoke_conf->filter_cnt; i++ ){
		struct bpf_program bpf_prog;

		pcap_handle[i] = pcap_create (etherpoke_conf->filter[i].interface, pcap_errbuff);

		if ( pcap_handle[i] == NULL ){
			fprintf (stderr, "%s: cannot start packet capture: %s\n", argv[0], pcap_errbuff);
			return EXIT_FAILURE;
		}

		rval = pcap_set_promisc (pcap_handle[i], 1);

		if ( rval != 0 ){
			fprintf (stderr, "%s: cannot set promiscuous mode on interface '%s'\n", argv[0], etherpoke_conf->filter[i].interface);
			return EXIT_FAILURE;
		}

		rval = pcap_setnonblock (pcap_handle[i], 1, pcap_errbuff);

		if ( rval == -1 ){
			fprintf (stderr, "%s: cannot set nonblock mode on packet capture resource: %s\n", argv[0], pcap_errbuff);
			return EXIT_FAILURE;
		}

		rval = pcap_activate (pcap_handle[i]);

		if ( rval != 0 ){
			fprintf (stderr, "%s: cannot activate packet capture on interface '%s': %s\n", argv[0], etherpoke_conf->filter[i].interface, pcap_geterr (pcap_handle[i]));
			return EXIT_FAILURE;
		}

		rval = pcap_compile (pcap_handle[i], &bpf_prog, etherpoke_conf->filter[i].match, 0, PCAP_NETMASK_UNKNOWN);

		if ( rval == -1 ){
			fprintf (stderr, "%s: cannot compile the filter's match rule '%s': %s\n", argv[0], etherpoke_conf->filter[i].name, pcap_geterr (pcap_handle[i]));
			return EXIT_FAILURE;
		}

		rval = pcap_setfilter (pcap_handle[i], &bpf_prog);

		if ( rval == -1 ){
			fprintf (stderr, "%s: cannot apply the filter '%s' on interface '%s': %s\n", argv[0], etherpoke_conf->filter[i].name, pcap_geterr (pcap_handle[i]));
			return EXIT_FAILURE;
		}

		pcap_freecode (&bpf_prog);

		pcap_session[i].fd = pcap_get_selectable_fd (pcap_handle[i]);

		if ( pcap_session[i].fd == -1 ){
			fprintf (stderr, "%s: cannot obtain file descriptor for packet capture interface '%s'\n", argv[0], etherpoke_conf->filter[i].interface);
			return EXIT_FAILURE;
		}
	}
	
	// Daemonize the process if the flag was set
	if ( daemonize == 1 ){
		pid_t pid;

		pid = fork ();
		
		if ( pid > 0 ){
			return EXIT_SUCCESS;
		} else if ( pid == -1 ){
			fprintf (stderr, "%s: cannot daemonize the process (fork failed).\n", argv[0]);
			return EXIT_FAILURE;
		}
		
		if ( setsid () == -1 ){
			fprintf (stderr, "%s: cannot daemonize the process (setsid failed).\n", argv[0]);
			return EXIT_FAILURE;
		}
		
		umask (0);
		chdir ("/");
		fclose (stdin);
		fclose (stdout);
		fclose (stderr);
	}

	main_loop = 1;

	while ( main_loop ){
		struct pcap_pkthdr *pkt_header;
		const u_char *pkt_data;
		struct timeval timeout;
		fd_set fdset_read;
		int last_fd;

		FD_ZERO (&fdset_read);
		timeout.tv_sec = 0;
		timeout.tv_usec = 400;

		for ( i = 0; i < etherpoke_conf->filter_cnt; i++ ){
			FD_SET (pcap_session[i].fd, &fdset_read);
			last_fd = pcap_session[i].fd;
		}

		rval = select (last_fd + 1, &fdset_read, NULL, NULL, &timeout);

		if ( rval == -1 ){
			log_error ("select failed: %s", strerror (errno));
			break;
		}

		for ( i = 0; i < etherpoke_conf->filter_cnt; i++ ){
			time_t current_time;

			time (&current_time);

			if ( FD_ISSET (pcap_session[i].fd, &fdset_read) ){
				rval = pcap_next_ex (pcap_handle[i], &pkt_header, &pkt_data);

				if ( rval != 1 )
					continue;

				if ( pcap_session[i].ts == 0 ){
					pcap_session[i].evt_flag = FILTER_EVENT_BEGIN;
					pcap_session[i].ts = pkt_header->ts.tv_sec;
				}
			}

			if ( (pcap_session[i].ts > 0)
					&& (difftime (current_time, pcap_session[i].ts) >= etherpoke_conf->filter[i].session_timeout) ){
				pcap_session[i].evt_flag = FILTER_EVENT_END;
			}

			switch ( pcap_session[i].evt_flag ){
				case FILTER_EVENT_BEGIN:
					fprintf (stderr, "session begin...\n");
					pcap_session[i].evt_flag = 0;
					break;

				case FILTER_EVENT_END:
					fprintf (stderr, "session end...\n");
					pcap_session[i].evt_flag = 0;
					pcap_session[i].ts = 0;
					break;
			}
		}
	}

	for ( i = 0; i < etherpoke_conf->filter_cnt; i++ )
		pcap_close (pcap_handle[i]);
	
	config_close (etherpoke_conf);
	free (config_file);
	
	return EXIT_SUCCESS;
}

