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
#include <syslog.h>
#include <wordexp.h>
#include <unistd.h>

#include "config.h"
#include "etherpoke.h"

struct session_data
{
	int fd;
	int evt_flag;
	time_t ts;
};

static int main_loop;

static void
etherpoke_help (const char *p)
{
	fprintf (stdout, "%s %d.%d.%d\n\nUsage:\n"
					 "  %s [-dhv] -f <FILE>\n\n"
					 "Options:\n"
					 "  -f <FILE>\tconfiguration file\n"
					 "  -d\t\trun as a daemon\n"
					 "  -h\t\tshow this help text\n"
					 "  -v\t\tshow version information\n"
					 , p, ETHERPOKE_VER_MAJOR, ETHERPOKE_VER_MINOR, ETHERPOKE_VER_PATCH, p);
}

static void
etherpoke_version (const char *p)
{
	fprintf (stdout, "%s %d.%d.%d\n", p, ETHERPOKE_VER_MAJOR,
										ETHERPOKE_VER_MINOR, ETHERPOKE_VER_PATCH);
}

static void
etherpoke_sigdie (int signo)
{
	main_loop = 0;
}

int
main (int argc, char *argv[])
{
	pcap_t **pcap_handle;
	struct config *etherpoke_conf;
	char conf_errbuff[CONF_ERRBUF_SIZE],
			pcap_errbuff[PCAP_ERRBUF_SIZE],
			*config_file;
	struct session_data *pcap_session;
	struct sigaction sa;
	int i, c, rval, daemonize, syslog_flags, exitno;
	pid_t pid;
	
	config_file = NULL;
	pcap_session = NULL;
	etherpoke_conf = NULL;

	daemonize = 0;
	main_loop = 1;
	exitno = EXIT_SUCCESS;
	syslog_flags = LOG_PID | LOG_PERROR;

	sa.sa_handler = etherpoke_sigdie;
	sigemptyset (&(sa.sa_mask));
	sa.sa_flags = 0;
	
	while ( (c = getopt (argc, argv, "f:dhv")) != -1 ){
		switch (c){
			case 'f':
				config_file = strdup (optarg);
				break;
			
			case 'd':
				daemonize = 1;
				break;
			
			case 'h':
				etherpoke_help (argv[0]);
				exitno = EXIT_SUCCESS;
				goto cleanup;
			
			case 'v':
				etherpoke_version (argv[0]);
				exitno = EXIT_SUCCESS;
				goto cleanup;
			
			default:
				etherpoke_help (argv[0]);
				exitno = EXIT_FAILURE;
				goto cleanup;
		}
	}

	if ( config_file == NULL ){
		fprintf (stderr, "%s: configuration file not specified. Use '-h' to see usage.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}
	
	etherpoke_conf = config_open (config_file, conf_errbuff);
	
	if ( etherpoke_conf == NULL ){
		fprintf (stderr, "%s: cannot load configuration file '%s': %s\n", argv[0], config_file, conf_errbuff);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	if ( etherpoke_conf->filter_cnt == 0 ){
		fprintf (stderr, "%s: nothing to do, packet capture filters not specified.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	pcap_handle = (pcap_t**) malloc (sizeof (pcap_t*) * etherpoke_conf->filter_cnt);

	if ( pcap_handle == NULL ){
		fprintf (stderr, "%s: cannot allocate memory for packet capture.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	pcap_session = (struct session_data*) malloc (sizeof (struct session_data) * etherpoke_conf->filter_cnt);

	if ( pcap_session == NULL ){
		fprintf (stderr, "%s: cannot allocate memory for packet capture.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
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
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_set_promisc (pcap_handle[i], 1);

		if ( rval != 0 ){
			fprintf (stderr, "%s: cannot set promiscuous mode on interface '%s'\n", argv[0], etherpoke_conf->filter[i].interface);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_setnonblock (pcap_handle[i], 1, pcap_errbuff);

		if ( rval == -1 ){
			fprintf (stderr, "%s: cannot set nonblock mode on packet capture resource: %s\n", argv[0], pcap_errbuff);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_activate (pcap_handle[i]);

		if ( rval != 0 ){
			fprintf (stderr, "%s: cannot activate packet capture on interface '%s': %s\n", argv[0], etherpoke_conf->filter[i].interface, pcap_geterr (pcap_handle[i]));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_compile (pcap_handle[i], &bpf_prog, etherpoke_conf->filter[i].match, 0, PCAP_NETMASK_UNKNOWN);

		if ( rval == -1 ){
			fprintf (stderr, "%s: cannot compile the filter's match rule '%s': %s\n", argv[0], etherpoke_conf->filter[i].name, pcap_geterr (pcap_handle[i]));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_setfilter (pcap_handle[i], &bpf_prog);

		if ( rval == -1 ){
			fprintf (stderr, "%s: cannot apply the filter '%s' on interface '%s': %s\n", argv[0], etherpoke_conf->filter[i].name, pcap_geterr (pcap_handle[i]));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		pcap_freecode (&bpf_prog);

		pcap_session[i].fd = pcap_get_selectable_fd (pcap_handle[i]);

		if ( pcap_session[i].fd == -1 ){
			fprintf (stderr, "%s: cannot obtain file descriptor for packet capture interface '%s'\n", argv[0], etherpoke_conf->filter[i].interface);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}
	}

	//
	// Setup signal handler
	//
	rval = 0;
	rval &= sigaction (SIGINT, &sa, NULL);
	rval &= sigaction (SIGQUIT, &sa, NULL);
	rval &= sigaction (SIGTERM, &sa, NULL);

	if ( rval != 0 ){
		fprintf (stderr, "%s: cannot setup signal handler: %s\n", strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}
	
	//
	// Daemonize the process if the flag was set
	//
	if ( daemonize == 1 ){
		pid = fork ();
		
		if ( pid > 0 ){
			exitno = EXIT_SUCCESS;
			goto cleanup;
		} else if ( pid == -1 ){
			fprintf (stderr, "%s: cannot daemonize the process (fork failed).\n", argv[0]);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}
		
		if ( setsid () == -1 ){
			fprintf (stderr, "%s: cannot daemonize the process (setsid failed).\n", argv[0]);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}
		
		umask (0);
		chdir ("/");
		fclose (stdin);
		fclose (stdout);
		fclose (stderr);
		syslog_flags = LOG_PID;
	}

	openlog ("etherpoke", syslog_flags, LOG_DAEMON);

	//
	// Main loop
	//
	while ( main_loop ){
		struct pcap_pkthdr *pkt_header;
		const u_char *pkt_data;
		struct timeval timeout;
		fd_set fdset_read;
		int last_fd;

		FD_ZERO (&fdset_read);
		timeout.tv_sec = 0;
		timeout.tv_usec = 700;

		for ( i = 0; i < etherpoke_conf->filter_cnt; i++ ){
			if ( pcap_session[i].fd == -1 )
				continue;

			FD_SET (pcap_session[i].fd, &fdset_read);
			last_fd = pcap_session[i].fd;
		}

		rval = select (last_fd + 1, &fdset_read, NULL, NULL, &timeout);

		if ( rval == -1 ){
			if ( errno != EINTR )
				syslog (LOG_ERR, "select system call failed: %s", strerror (errno));
			break;
		}

		for ( i = 0; i < etherpoke_conf->filter_cnt; i++ ){
			time_t current_time;

			time (&current_time);

			if ( FD_ISSET (pcap_session[i].fd, &fdset_read) ){
				rval = pcap_next_ex (pcap_handle[i], &pkt_header, &pkt_data);

				if ( rval != 1 )
					continue;

				if ( pcap_session[i].ts == 0 )
					pcap_session[i].evt_flag = FILTER_EVENT_BEGIN;

				pcap_session[i].ts = pkt_header->ts.tv_sec;
			}

			if ( (pcap_session[i].ts > 0)
					&& (difftime (current_time, pcap_session[i].ts) >= etherpoke_conf->filter[i].session_timeout) ){
				pcap_session[i].evt_flag = FILTER_EVENT_END;
			}


			//
			// Execute event hook
			//
			if ( pcap_session[i].evt_flag ){
				const char *cmd;
				wordexp_t command;

				switch ( pcap_session[i].evt_flag ){
					case FILTER_EVENT_BEGIN:
						syslog (LOG_INFO, "SESSION_BEGIN %s", etherpoke_conf->filter[i].name);
						cmd = etherpoke_conf->filter[i].session_begin;
						pcap_session[i].evt_flag = 0;
						break;

					case FILTER_EVENT_END:
						syslog (LOG_INFO, "SESSION_END %s", etherpoke_conf->filter[i].name);
						cmd = etherpoke_conf->filter[i].session_end;
						pcap_session[i].evt_flag = 0;
						pcap_session[i].ts = 0;
						break;
				}

				rval = wordexp (cmd, &command, WRDE_UNDEF);

				// TODO: if program ends up in any of the code branches producing a warning message,
				// pcap handle should be closed and file descriptor set to -1.
				// By doing so we will save valuable resources, to fix any of the errors will most likely require
				// a program's restart in order to reload a configuration file.
				if ( rval == WRDE_SYNTAX ){
					syslog (LOG_WARNING, "invalid event hook in '%s': syntax error", etherpoke_conf->filter[i].name);
					wordfree (&command);
					continue;
				} else if ( rval == WRDE_NOSPACE ){
					syslog (LOG_ERR, "cannot expand event hook string in '%s': out of memory", etherpoke_conf->filter[i].name);
					wordfree (&command);
					main_loop = 0;
					break;
				} else if ( rval == WRDE_BADVAL ){
					syslog (LOG_WARNING, "invalid event hook in '%s': referencing undefined variable", etherpoke_conf->filter[i].name);
					wordfree (&command);
					continue;
				}

				pid = fork ();

				if ( pid == -1 ){
					syslog (LOG_ERR, "cannot fork the process: %s", strerror (errno));
					wordfree (&command);
					main_loop = 0;
					break;
				}

				// Parent process, carry on...
				if ( pid > 0 ){
					wordfree (&command);
					continue;
				}

				errno = 0;
				rval = execv (command.we_wordv[0], command.we_wordv);
				wordfree (&command);

				if ( rval == -1 )
					syslog (LOG_WARNING, "cannot execute event hook in '%s': %s", etherpoke_conf->filter[i].name, strerror (errno));

				main_loop = 0;
				break;
			}
		}
	}

cleanup:
	if ( pcap_handle != NULL ){
		for ( i = 0; i < etherpoke_conf->filter_cnt; i++ )
			pcap_close (pcap_handle[i]);
	
		free (pcap_handle);
	}
	
	if ( etherpoke_conf != NULL )
		config_close (etherpoke_conf);

	if ( pcap_session != NULL )
		free (pcap_session);

	if ( config_file != NULL )
		free (config_file);
	
	return exitno;
}

