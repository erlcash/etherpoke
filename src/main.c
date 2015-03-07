/*
 * Copyright (c) 2013 - 2015, CodeWard.org
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <pcap.h>
#include <libconfig.h>
#include <sys/stat.h>
#include <poll.h>
#include <getopt.h>
#include <time.h>
#include <syslog.h>
#include <wordexp.h>
#include <unistd.h>

#include "config.h"
#include "etherpoke.h"
#include "session_data.h"

#define SELECT_TIMEOUT_MS 700

static int main_loop;
static int exitno;

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
	fprintf (stdout, "%s %d.%d.%d\n", p, ETHERPOKE_VER_MAJOR, ETHERPOKE_VER_MINOR, ETHERPOKE_VER_PATCH);
}

static void
etherpoke_sigdie (int signo)
{
	main_loop = 0;
	exitno = signo;
}

int
main (int argc, char *argv[])
{
	struct config *etherpoke_conf;
	char conf_errbuff[CONF_ERRBUF_SIZE],
			pcap_errbuff[PCAP_ERRBUF_SIZE],
			*config_file;
	struct session_data *pcap_session;
	struct pollfd *poll_fd;
	struct sigaction sa;
	int i, c, rval, daemonize, syslog_flags;
	pid_t pid;

	config_file = NULL;
	pcap_session = NULL;
	poll_fd = NULL;
	etherpoke_conf = NULL;

	daemonize = 0;
	main_loop = 1;
	exitno = EXIT_SUCCESS;
	syslog_flags = LOG_PID | LOG_PERROR;

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

	pcap_session = (struct session_data*) calloc (etherpoke_conf->filter_cnt, sizeof (struct session_data));

	if ( pcap_session == NULL ){
		fprintf (stderr, "%s: cannot allocate memory for packet capture.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	poll_fd = (struct pollfd*) malloc (sizeof (struct pollfd) * etherpoke_conf->filter_cnt);

	if ( poll_fd == NULL ){
		fprintf (stderr, "%s: cannot allocate memory for file descriptor array.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	//
	// Prepare packet capture
	//
	for ( i = 0; i < etherpoke_conf->filter_cnt; i++ ){
		struct bpf_program bpf_prog;
		int link_type;

		session_data_init (&(pcap_session[i]));

		pcap_session[i].handle = pcap_create (etherpoke_conf->filter[i].interface, pcap_errbuff);

		if ( pcap_session[i].handle == NULL ){
			fprintf (stderr, "%s: cannot start packet capture: %s\n", argv[0], pcap_errbuff);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_set_rfmon (pcap_session[i].handle, etherpoke_conf->filter[i].rfmon);

		if ( rval != 0 ){
			fprintf (stderr, "%s: cannot enable monitor mode on interface '%s': %s\n", argv[0], etherpoke_conf->filter[i].interface, pcap_geterr (pcap_session[i].handle));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_set_promisc (pcap_session[i].handle, !etherpoke_conf->filter[i].rfmon);

		if ( rval != 0 ){
			fprintf (stderr, "%s: cannot enable promiscuous mode on interface '%s'\n", argv[0], etherpoke_conf->filter[i].interface);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_set_timeout (pcap_session[i].handle, SELECT_TIMEOUT_MS);

		if ( rval != 0 ){
			fprintf (stderr, "%s: cannot set read timeout on interface '%s': %s\n", argv[0], etherpoke_conf->filter[i].interface, pcap_geterr (pcap_session[i].handle));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_setnonblock (pcap_session[i].handle, 1, pcap_errbuff);

		if ( rval == -1 ){
			fprintf (stderr, "%s: cannot set nonblock mode on packet capture resource: %s\n", argv[0], pcap_errbuff);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_activate (pcap_session[i].handle);

		if ( rval != 0 ){
			fprintf (stderr, "%s: cannot activate packet capture on interface '%s': %s\n", argv[0], etherpoke_conf->filter[i].interface, pcap_geterr (pcap_session[i].handle));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		// Set link-layer type from configuration file.
		if ( etherpoke_conf->filter[i].link_type != NULL ){
			link_type = pcap_datalink_name_to_val (etherpoke_conf->filter[i].link_type);

			if ( link_type == -1 ){
				fprintf (stderr, "%s: cannot convert link-layer type '%s': unknown link-layer type name\n", argv[0], etherpoke_conf->filter[i].link_type);
				exitno = EXIT_FAILURE;
				goto cleanup;
			}
		} else {
			// If no link-layer type is specified in the configuration file,
			// use default value. At this point I am sticking with DLTs used by
			// wireshark on hardware I have available. Different values may
			// apply to different hardware/driver, therefore more research time
			// should be put into finding 'best' values.
			// More information: http://www.tcpdump.org/linktypes.html
			if ( etherpoke_conf->filter[i].rfmon ){
				link_type = DLT_IEEE802_11_RADIO;
			} else {
				link_type = DLT_EN10MB;
			}
		}

		rval = pcap_set_datalink (pcap_session[i].handle, link_type);

		if ( rval == -1 ){
			fprintf (stderr, "%s: cannot set data-link type: %s\n", argv[0], pcap_geterr (pcap_session[i].handle));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		if ( etherpoke_conf->filter[i].match != NULL ){
			rval = pcap_compile (pcap_session[i].handle, &bpf_prog, etherpoke_conf->filter[i].match, 0, PCAP_NETMASK_UNKNOWN);

			if ( rval == -1 ){
				fprintf (stderr, "%s: cannot compile the filter '%s' match rule: %s\n", argv[0], etherpoke_conf->filter[i].name, pcap_geterr (pcap_session[i].handle));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			rval = pcap_setfilter (pcap_session[i].handle, &bpf_prog);

			if ( rval == -1 ){
				fprintf (stderr, "%s: cannot apply the filter '%s' on interface '%s': %s\n", argv[0], etherpoke_conf->filter[i].name, etherpoke_conf->filter[i].interface, pcap_geterr (pcap_session[i].handle));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			pcap_freecode (&bpf_prog);
		}

		pcap_session[i].fd = pcap_get_selectable_fd (pcap_session[i].handle);

		if ( pcap_session[i].fd == -1 ){
			fprintf (stderr, "%s: cannot obtain file descriptor for packet capture interface '%s'\n", argv[0], etherpoke_conf->filter[i].interface);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}
	}

	//
	// Setup signal handler
	//
	sa.sa_handler = etherpoke_sigdie;
	sigemptyset (&(sa.sa_mask));
	sa.sa_flags = 0;

	rval = 0;
	rval &= sigaction (SIGINT, &sa, NULL);
	rval &= sigaction (SIGQUIT, &sa, NULL);
	rval &= sigaction (SIGTERM, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigemptyset (&(sa.sa_mask));
	sa.sa_flags = 0;

	rval &= sigaction (SIGCHLD, &sa, NULL);

	if ( rval != 0 ){
		fprintf (stderr, "%s: cannot setup signal handler: %s\n", argv[0], strerror (errno));
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

		rval = chdir ("/");

		if ( rval == -1 ){
			fprintf (stderr, "%s: cannot change working directory: %s\n", argv[0], strerror (errno));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

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
		time_t current_time;
		struct pcap_pkthdr *pkt_header;
		const u_char *pkt_data;
		int filter_ok_cnt;

		filter_ok_cnt = 0;

		for ( i = 0; i < etherpoke_conf->filter_cnt; i++ ){
			poll_fd[i].fd = pcap_session[i].fd;
			poll_fd[i].events = POLLIN | POLLERR;

			if ( pcap_session[i].fd != -1 )
				filter_ok_cnt++;
		}

		if ( filter_ok_cnt == 0 ){
			syslog (LOG_ERR, "no more applicable filters left to use. Dying!");
			break;
		}

		errno = 0;
		rval = poll (poll_fd, etherpoke_conf->filter_cnt, SELECT_TIMEOUT_MS);

		if ( rval == -1 ){
			if ( errno == EINTR )
				continue;

			syslog (LOG_ERR, "poll system call failed: %s", strerror (errno));
			break;
		}

		time (&current_time);

		for ( i = 0; i < etherpoke_conf->filter_cnt; i++ ){
			// Handle incoming packet
			if ( (poll_fd[i].revents & POLLIN) || (poll_fd[i].revents & POLLERR) ){
				rval = pcap_next_ex (pcap_session[i].handle, &pkt_header, &pkt_data);

				if ( rval == 1 ){
					if ( pcap_session[i].ts == 0 )
						pcap_session[i].evt_flag = FILTER_EVENT_BEGIN;

					pcap_session[i].ts = pkt_header->ts.tv_sec;
				} else if ( rval < 0 ){
					pcap_session[i].evt_flag = FILTER_EVENT_ERROR;
				}
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

					case FILTER_EVENT_ERROR:
						syslog (LOG_INFO, "SESSION_ERROR %s", etherpoke_conf->filter[i].name);
						cmd = etherpoke_conf->filter[i].session_error;
						pcap_session[i].evt_flag = 0;
						pcap_session[i].ts = 0;
						break;
				}

				rval = wordexp (cmd, &command, WRDE_UNDEF);

				if ( rval == 0 ){
					// OK, do nothing
				} else if ( rval == WRDE_SYNTAX ){
					syslog (LOG_WARNING, "invalid event hook in '%s': syntax error", etherpoke_conf->filter[i].name);
					session_data_free (&(pcap_session[i]));
					continue;
				} else if ( rval == WRDE_BADCHAR ){
					syslog (LOG_WARNING, "invalid event hook in '%s': bad character", etherpoke_conf->filter[i].name);
					session_data_free (&(pcap_session[i]));
					continue;
				} else if ( rval == WRDE_BADVAL ){
					syslog (LOG_WARNING, "invalid event hook in '%s': referencing undefined variable", etherpoke_conf->filter[i].name);
					session_data_free (&(pcap_session[i]));
					continue;
				} else if ( rval == WRDE_NOSPACE ){
					syslog (LOG_ERR, "cannot expand event hook string in '%s': out of memory", etherpoke_conf->filter[i].name);
					main_loop = 0;
					break;
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
	if ( pcap_session != NULL ){
		for ( i = 0; i < etherpoke_conf->filter_cnt; i++ )
			session_data_free (&(pcap_session[i]));
		free (pcap_session);
	}

	if ( poll_fd != NULL )
		free (poll_fd);

	if ( etherpoke_conf != NULL )
		config_close (etherpoke_conf);

	if ( config_file != NULL )
		free (config_file);
	
	return exitno;
}

