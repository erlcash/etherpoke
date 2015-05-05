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

#define WORDEXP_FLAGS WRDE_UNDEF

struct option_data
{
	int daemon;
	int port;
};

static int main_loop;
static int exitno;

static void
etherpoke_help (const char *p)
{
	fprintf (stdout, "Usage: %s [OPTIONS] <FILE>...\n\n"
					 "Options:\n"
					 "  -d, --daemon       run as a daemon\n"
					 "  -l, --listen=NUM   TCP port used for inbound client connections\n"
					 "  -h, --help         show this usage information\n"
					 "  -v, --version      show version information\n"
					 , p);
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
	struct pollfd *poll_fd;
	struct config etherpoke_conf;
	struct config_filter *filter_iter;
	struct session_data *pcap_session;
	struct option_data opt;
	char conf_errbuff[CONF_ERRBUF_SIZE];
	char pcap_errbuff[PCAP_ERRBUF_SIZE];
	int i, c, rval, syslog_flags, opt_index, filter_cnt;
	struct sigaction sa;
	pid_t pid;
	struct option opt_long[] = {
		{ "daemon", no_argument, 0, 'd' },
		{ "listen", required_argument, 0, 'l' },
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'v' },
		{ NULL, 0, 0, 0 }
	};

	memset (&opt, 0, sizeof (struct option_data));
	memset (&etherpoke_conf, 0, sizeof (struct config));

	poll_fd = NULL;
	pcap_session = NULL;

	exitno = EXIT_SUCCESS;
	syslog_flags = LOG_PID | LOG_PERROR;

	while ( (c = getopt_long (argc, argv, "dl:hv", opt_long, &opt_index)) != -1 ){
		switch ( c ){
			case 'd':
				opt.daemon = 1;
				break;

			case 'l':
				// TODO: convert string to int!
				opt.port = 0;
				fprintf (stderr, "listen %u\n", 0);
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

	// Check if there are some non-option arguments, these are treated as paths
	// to configuration files.
	if ( (argc - optind) == 0 ){
		fprintf (stderr, "%s: configuration file not specified. Use '--help' to see usage information.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	filter_cnt = 0;

	for ( opt_index = optind; opt_index < argc; opt_index++ ){
		rval = config_load (&etherpoke_conf, argv[opt_index], conf_errbuff);

		if ( rval == -1 ){
			fprintf (stderr, "%s: cannot load configuration file '%s': %s\n", argv[0], argv[opt_index], conf_errbuff);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		filter_cnt += rval;
	}

	if ( filter_cnt == 0 ){
		fprintf (stderr, "%s: nothing to do, no filters defined.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	pcap_session = (struct session_data*) calloc (filter_cnt, sizeof (struct session_data));

	if ( pcap_session == NULL ){
		fprintf (stderr, "%s: cannot allocate memory for packet capture.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	poll_fd = (struct pollfd*) malloc (sizeof (struct pollfd) * filter_cnt);

	if ( poll_fd == NULL ){
		fprintf (stderr, "%s: cannot allocate memory for file descriptor array.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	for ( i = 0, filter_iter = etherpoke_conf.head; filter_iter != NULL; i++, filter_iter = filter_iter->next ){
		struct bpf_program bpf_prog;
		int link_type;

		session_data_init (&(pcap_session[i]));

		rval = wordexp (filter_iter->session_begin, &(pcap_session[i].evt_cmd_beg), WORDEXP_FLAGS);

		if ( rval == 0 )
			rval = wordexp (filter_iter->session_error, &(pcap_session[i].evt_cmd_err), WORDEXP_FLAGS);

		if ( rval == 0 )
			rval = wordexp (filter_iter->session_end, &(pcap_session[i].evt_cmd_end), WORDEXP_FLAGS);

		switch ( rval ){
			case WRDE_SYNTAX:
				fprintf (stderr, "%s: invalid event hook in '%s': syntax error\n", argv[0], filter_iter->name);
				exitno = EXIT_FAILURE;
				goto cleanup;

			case WRDE_BADCHAR:
				fprintf (stderr, "%s: invalid event hook in '%s': bad character\n", argv[0], filter_iter->name);
				exitno = EXIT_FAILURE;
				goto cleanup;

			case WRDE_BADVAL:
				fprintf (stderr, "%s: invalid event hook in '%s': referencing undefined variable\n", argv[0], filter_iter->name);
				exitno = EXIT_FAILURE;
				goto cleanup;

			case WRDE_NOSPACE:
				fprintf (stderr, "%s: cannot expand event hook string in '%s': out of memory\n", argv[0], filter_iter->name);
				exitno = EXIT_FAILURE;
				goto cleanup;
		}

		pcap_session[i].handle = pcap_create (filter_iter->interface, pcap_errbuff);

		if ( pcap_session[i].handle == NULL ){
			fprintf (stderr, "%s: cannot start packet capture: %s\n", argv[0], pcap_errbuff);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_set_rfmon (pcap_session[i].handle, filter_iter->rfmon);

		if ( rval != 0 ){
			fprintf (stderr, "%s: cannot enable monitor mode on interface '%s': %s\n", argv[0], filter_iter->interface, pcap_geterr (pcap_session[i].handle));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_set_promisc (pcap_session[i].handle, !(filter_iter->rfmon));

		if ( rval != 0 ){
			fprintf (stderr, "%s: cannot enable promiscuous mode on interface '%s'\n", argv[0], filter_iter->interface);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_set_timeout (pcap_session[i].handle, SELECT_TIMEOUT_MS);

		if ( rval != 0 ){
			fprintf (stderr, "%s: cannot set read timeout on interface '%s': %s\n", argv[0], filter_iter->interface, pcap_geterr (pcap_session[i].handle));
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
			fprintf (stderr, "%s: cannot activate packet capture on interface '%s': %s\n", argv[0], filter_iter->interface, pcap_geterr (pcap_session[i].handle));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		// Set link-layer type from configuration file.
		if ( filter_iter->link_type != NULL ){
			link_type = pcap_datalink_name_to_val (filter_iter->link_type);

			if ( link_type == -1 ){
				fprintf (stderr, "%s: cannot convert link-layer type '%s': unknown link-layer type name\n", argv[0], filter_iter->link_type);
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
			if ( filter_iter->rfmon ){
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

		if ( filter_iter->match != NULL ){
			rval = pcap_compile (pcap_session[i].handle, &bpf_prog, filter_iter->match, 0, PCAP_NETMASK_UNKNOWN);

			if ( rval == -1 ){
				fprintf (stderr, "%s: cannot compile the filter '%s' match rule: %s\n", argv[0], filter_iter->name, pcap_geterr (pcap_session[i].handle));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			rval = pcap_setfilter (pcap_session[i].handle, &bpf_prog);

			if ( rval == -1 ){
				fprintf (stderr, "%s: cannot apply the filter '%s' on interface '%s': %s\n", argv[0], filter_iter->name, filter_iter->interface, pcap_geterr (pcap_session[i].handle));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			pcap_freecode (&bpf_prog);
		}

		pcap_session[i].fd = pcap_get_selectable_fd (pcap_session[i].handle);

		if ( pcap_session[i].fd == -1 ){
			fprintf (stderr, "%s: cannot obtain file descriptor for packet capture interface '%s'\n", argv[0], filter_iter->interface);
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
	if ( opt.daemon == 1 ){
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

	// Populate poll structure
	for ( i = 0; i < filter_cnt; i++ ){
		poll_fd[i].fd = pcap_session[i].fd;
		poll_fd[i].events = POLLIN | POLLERR;
	}

	openlog ("etherpoke", syslog_flags, LOG_DAEMON);

	//
	// Main loop
	//
	main_loop = 1;

	while ( main_loop ){
		const u_char *pkt_data;
		struct pcap_pkthdr *pkt_header;
		time_t current_time;
		wordexp_t *cmd_exp;

		errno = 0;
		rval = poll (poll_fd, filter_cnt, SELECT_TIMEOUT_MS);

		if ( rval == -1 ){
			if ( errno == EINTR )
				continue;

			syslog (LOG_ERR, "poll system call failed: %s", strerror (errno));
			break;
		}

		time (&current_time);

		for ( i = 0, filter_iter = etherpoke_conf.head; filter_iter != NULL; i++, filter_iter = filter_iter->next ){
			// Handle incoming packet
			if ( (poll_fd[i].revents & POLLIN) || (poll_fd[i].revents & POLLERR) ){
				rval = pcap_next_ex (pcap_session[i].handle, &pkt_header, &pkt_data);

				if ( rval == 1 ){
					if ( pcap_session[i].evt.ts == 0 )
						pcap_session[i].evt.type = SE_BEG;

					pcap_session[i].evt.ts = pkt_header->ts.tv_sec;
				} else if ( rval < 0 ){
					pcap_session[i].evt.type = SE_ERR;
				}
			}

			if ( (pcap_session[i].evt.ts > 0)
					&& (difftime (current_time, pcap_session[i].evt.ts) >= filter_iter->session_timeout) ){
				pcap_session[i].evt.type = SE_END;
			}

			cmd_exp = NULL;

			switch ( pcap_session[i].evt.type ){
				case SE_BEG:
					syslog (LOG_INFO, "SESSION_BEGIN %s", filter_iter->name);
					cmd_exp = &(pcap_session[i].evt_cmd_beg);
					pcap_session[i].evt.type = SE_NUL;
					break;

				case SE_END:
					syslog (LOG_INFO, "SESSION_END %s", filter_iter->name);
					cmd_exp = &(pcap_session[i].evt_cmd_end);
					pcap_session[i].evt.type = SE_NUL;
					pcap_session[i].evt.ts = 0;
					break;

				case SE_ERR:
					syslog (LOG_INFO, "SESSION_ERROR %s", filter_iter->name);
					cmd_exp = &(pcap_session[i].evt_cmd_err);
					pcap_session[i].evt.type = SE_NUL;
					pcap_session[i].evt.ts = 0;
					break;
			}

			if ( cmd_exp == NULL )
				continue;

			pid = fork ();

			if ( pid == -1 ){
				syslog (LOG_ERR, "cannot fork the process: %s", strerror (errno));
				main_loop = 0;
				break;
			}

			// Parent process, carry on...
			if ( pid > 0 )
				continue;

			errno = 0;
			rval = execv (cmd_exp->we_wordv[0], cmd_exp->we_wordv);

			if ( rval == -1 )
				syslog (LOG_WARNING, "cannot execute event hook in '%s': %s", filter_iter->name, strerror (errno));

			main_loop = 0;
			break;
		}
	}

cleanup:
	if ( pcap_session != NULL ){
		for ( i = 0; i < filter_cnt; i++ )
			session_data_free (&(pcap_session[i]));
		free (pcap_session);
	}

	if ( poll_fd != NULL )
		free (poll_fd);

	config_unload (&etherpoke_conf);

	return exitno;
}

