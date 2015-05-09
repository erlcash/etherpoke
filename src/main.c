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
#include <sys/socket.h>
#include <poll.h>
#include <getopt.h>
#include <time.h>
#include <syslog.h>
#include <wordexp.h>
#include <libgen.h>
#include <unistd.h>

#include "config.h"
#include "etherpoke.h"
#include "session_data.h"
#include "sock.h"

#define SELECT_TIMEOUT_MS 700

#define ACCEPT_MAX 32

#define WORDEXP_FLAGS WRDE_UNDEF

struct option_data
{
	uint8_t daemon;
	uint16_t port;
	uint32_t accept_max;
};

static int main_loop;
static int exitno;

static void
etherpoke_help (const char *p)
{
	fprintf (stdout, "Usage: %s [OPTIONS] <FILE>\n\n"
					 "Options:\n"
					 "  -d, --daemon          run as a daemon\n"
					 "  -l, --listen=NUM      TCP port to use for inbound client connections\n"
					 "  -m, --accept-max=NUM  accept maximum NUM of concurrent client connections\n"
					 "  -h, --help            show this usage information\n"
					 "  -v, --version         show version information\n"
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
	char *dirname_config, *path_config;
	struct sigaction sa;
	pid_t pid;
	int i, c, j, rval, syslog_flags, opt_index, filter_cnt, sock, poll_len;
	struct option opt_long[] = {
		{ "daemon", no_argument, 0, 'd' },
		{ "listen", required_argument, 0, 'l' },
		{ "accept-max", required_argument, 0, 'm' },
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'v' },
		{ NULL, 0, 0, 0 }
	};

	sock = -1;
	poll_fd = NULL;
	pcap_session = NULL;
	exitno = EXIT_SUCCESS;
	syslog_flags = LOG_PID | LOG_PERROR;

	memset (&opt, 0, sizeof (struct option_data));
	memset (&etherpoke_conf, 0, sizeof (struct config));

	while ( (c = getopt_long (argc, argv, "dl:m:hv", opt_long, &opt_index)) != -1 ){
		switch ( c ){
			case 'd':
				opt.daemon = 1;
				break;

			case 'l':
				sscanf (optarg, "%hu", &(opt.port));

				if ( opt.port == 0 ){
					fprintf (stderr, "%s: invalid port number\n", argv[0]);
					exitno = EXIT_FAILURE;
					goto cleanup;
				}
				break;

			case 'm':
				sscanf (optarg, "%u", &(opt.accept_max));

				if ( opt.accept_max == 0 ){
					fprintf (stderr, "%s: invalid number for maximum connections\n", argv[0]);
					exitno = EXIT_FAILURE;
					goto cleanup;
				}
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

	if ( opt.accept_max == 0 )
		opt.accept_max = ACCEPT_MAX;

	// Check if there are some non-option arguments, these are treated as paths
	// to configuration files.
	if ( (argc - optind) == 0 ){
		fprintf (stderr, "%s: configuration file not specified. Use '--help' to see usage information.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	// Change working directory to match the dirname of the config file.  In
	// some implementations dirname may change input string hence the copy in
	// path_config.
	path_config = strdup (argv[optind]);

	dirname_config = dirname (path_config);

	rval = chdir (dirname_config);

	if ( rval == -1 ){
		fprintf (stderr, "%s: cannot change working directory to '%s': %s\n", argv[0], dirname_config, strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	free (path_config);

	//
	// Load configuration file
	//
	filter_cnt = config_load (&etherpoke_conf, argv[optind], conf_errbuff);

	if ( filter_cnt == -1 ){
		fprintf (stderr, "%s: cannot load configuration file '%s': %s\n", argv[0], argv[optind], conf_errbuff);
		exitno = EXIT_FAILURE;
		goto cleanup;
	} else	if ( filter_cnt == 0 ){
		fprintf (stderr, "%s: nothing to do, no filters defined.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	poll_len = filter_cnt + 1;

	if ( opt.port ){
		// Increase poll size to accommodate socket descriptors for clients.
		poll_len += opt.accept_max;

		sock = sock_open (AF_INET);

		if ( sock == -1 ){
			fprintf (stderr, "%s: cannot create socket: %s\n", argv[0], strerror (errno));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = sock_listen (sock, "0.0.0.0", opt.port);

		if ( rval == -1 ){
			fprintf (stderr, "%s: cannot open port %u for listening: %s\n", argv[0], opt.port, strerror (errno));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}
	}

	pcap_session = (struct session_data*) calloc (filter_cnt, sizeof (struct session_data));

	if ( pcap_session == NULL ){
		fprintf (stderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	for ( i = 0, filter_iter = etherpoke_conf.head; filter_iter != NULL; i++, filter_iter = filter_iter->next ){
		struct bpf_program bpf_prog;
		int link_type;

		session_data_init (&(pcap_session[i]));

		if ( filter_iter->notify & NOTIFY_EXEC ){
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

	// Allocate enough resources to hold file descriptors for each pcap handle,
	// plus one listening socket, plus --accept-max socket descriptors.
	poll_fd = (struct pollfd*) malloc (sizeof (struct pollfd) * poll_len);

	if ( poll_fd == NULL ){
		fprintf (stderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	// Populate poll structure...
	for ( i = 0; i < poll_len; i++ ){
		// ... with pcap file descriptors...
		if ( i < filter_cnt )
			poll_fd[i].fd = pcap_session[i].fd;
		// ... listening socket...
		else if ( i == filter_cnt )
			poll_fd[i].fd = sock;
		// ... invalid file descriptors (to be ignored by poll)...
		else
			poll_fd[i].fd = -1;

		poll_fd[i].events = POLLIN | POLLERR;
		poll_fd[i].revents = 0;
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

		freopen ("/dev/null", "r", stdin);
		freopen ("/dev/null", "w", stdout);
		freopen ("/dev/null", "w", stderr);
		syslog_flags = LOG_PID;
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

		errno = 0;
		rval = poll (poll_fd, poll_len, SELECT_TIMEOUT_MS);

		if ( rval == -1 ){
			if ( errno == EINTR )
				continue;

			syslog (LOG_ERR, "poll system call failed: %s", strerror (errno));
			break;
		}

		// Accept incoming connection
		if ( poll_fd[filter_cnt].revents & POLLIN ){
			int sock_new;

			syslog (LOG_INFO, "incoming connection");

			sock_new = accept (sock, NULL, NULL);

			if ( sock_new == -1 ){
				syslog (LOG_ERR, "cannot accept new connection: %s", strerror (errno));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			// Find unused place in the poll array
			for ( j = (filter_cnt + 1); j < poll_len; j++ ){
				if ( poll_fd[j].fd != -1 )
					continue;

				poll_fd[j].fd = sock_new;
				sock_new = -1;
			}

			if ( sock_new != -1 ){
				syslog (LOG_INFO, "too many concurrent connections");
				close (sock_new);
			}
		}

		// Take care of incoming client data.  At this point only shutdown and
		// close is handled, no input is expected from the clients.
		for ( i = (filter_cnt + 1); i < poll_len; i++ ){
			if ( (poll_fd[i].revents & POLLIN) || (poll_fd[i].revents & POLLERR) ){
				char nok[128];

				rval = recv (poll_fd[i].fd, &nok, sizeof (nok), 0);

				if ( rval <= 0 ){
					syslog (LOG_INFO, "connection closed");
					poll_fd[i].fd = -1;
				}
			}
		}

		time (&current_time);

		for ( i = 0, filter_iter = etherpoke_conf.head; filter_iter != NULL; i++, filter_iter = filter_iter->next ){
			wordexp_t *cmd_exp;
			int evt;

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

			// Store a copy of the event before it is discarded
			evt = pcap_session[i].evt.type;

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

				default:
					cmd_exp = NULL;
					break;
			}

			// Send socket notification
			if ( filter_iter->notify & NOTIFY_SOCK ){
				const char *evt_str;
				char msg[128];

				switch ( evt ){
					case SE_BEG:
						evt_str = "BEG";
						break;

					case SE_END:
						evt_str = "END";
						break;

					case SE_ERR:
						evt_str = "ERR";
						break;

					default:
						evt_str = NULL;
						break;
				}

				if ( evt_str == NULL )
					continue;

				snprintf (msg, sizeof (msg), "%s:%s", filter_iter->name, evt_str);

				for ( j = (filter_cnt + 1); j < poll_len; j++ ){
					if ( poll_fd[j].fd == -1 )
						continue;

					rval = send (poll_fd[j].fd, msg, strlen (msg) + 1, MSG_NOSIGNAL);

					if ( rval == -1 ){
						syslog (LOG_WARNING, "failed to send notification: %s", strerror (errno));
						poll_fd[j].fd = -1;
					}
				}
			}

			// Execute event hook
			if ( filter_iter->notify & NOTIFY_EXEC ){

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

				goto cleanup;
			}
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

	if ( sock != -1 )
		close (sock);

	config_unload (&etherpoke_conf);

	return exitno;
}

