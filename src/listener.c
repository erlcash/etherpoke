/*
 * listener.c
 * 
 * Copyright 2013 Earl Cash <erl@codeward.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */

#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <pthread.h>

#include "queue.h"
#include "metapkt.h"
#include "listener.h"

extern conf_t *etherpoke_conf;

extern queue_t packet_queue;
extern pthread_mutex_t packet_queue_mut;
extern pthread_cond_t packet_queue_cond;

/*
 * Allocate and populate a buffer with bpf program.
 */
static char*
listener_bpf_prog_init (filter_t *filters, uint16_t filter_count)
{
	char *bpf_prog, *bpf_template;
	uint16_t bpf_prog_len;
	uint8_t insert_or;
	int i;
	
	bpf_prog_len = ((LISTENER_BPF_TEMPL_LEN * filter_count) + (LISTENER_BPF_LOGOPER_LEN * (filter_count - 1)) + 1);
	bpf_prog = (char*) calloc (bpf_prog_len, sizeof (char));
	
	if ( bpf_prog == NULL )
		return NULL;
	
	insert_or = 0;
	for ( i = 0; i < filter_count; i++ ){
		bpf_template = (char*) calloc (LISTENER_BPF_TEMPL_LEN + 1, sizeof (char));
		
		if ( bpf_template == NULL )
			return NULL;
		
		sprintf (bpf_template, LISTENER_BPF_TEMPL, filters[i].eth_addr);
		
		if ( insert_or )
			strncat (bpf_prog, LISTENER_BPG_LOGOPER, LISTENER_BPF_LOGOPER_LEN);
		
		strncat (bpf_prog, bpf_template, LISTENER_BPF_TEMPL_LEN);
		free (bpf_template);
		insert_or = 1;
	}
	
	return bpf_prog;
}

/*
 * Free allocated buffer with bpf program.
 */
void
listener_bpf_prog_destroy (char *bpf_prog)
{
	free (bpf_prog);
}

void*
listener_main (void *th_data)
{
	listener_data_t *listener_data;
	pcap_t *pcap_handle;
	struct pcap_pkthdr pkt_header;
	struct bpf_program bpf_prog; // berkeley packet filter program
	char *bpf_program_str;
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char *pkt = NULL;
	struct ethhdr *eth_header;
	metapkt_t *meta_pkt;
	
	listener_data = (listener_data_t*) th_data;
	
	pcap_handle = pcap_open_live (listener_data->interface, SNAPSHOT_LENGTH, 1, 0, errbuf);
	
	if ( pcap_handle == NULL ){
		fprintf (stderr, "th_%d: cannot open device %s\n", listener_data->id, errbuf);
		pthread_exit ((void*) EXIT_FAILURE);
	}
	
	bpf_program_str = listener_bpf_prog_init (etherpoke_conf->filters, etherpoke_conf->filters_count);
	
	if ( bpf_program_str == NULL ){
		fprintf (stderr, "th_%d: cannot initialize bpf program\n", listener_data->id);
		abort (); // die! we are probably without memory.
	}
	
	fprintf (stderr, "th_%d: bpf_prog %s\n", listener_data->id, bpf_program_str);
	
	if ( pcap_compile (pcap_handle, &bpf_prog, bpf_program_str, 0, PCAP_NETMASK_UNKNOWN) == -1 ){
		fprintf (stderr, "th_%d: cannot compile a bpf program\n", listener_data->id);
		abort ();
	}
	
	listener_bpf_prog_destroy (bpf_program_str);
	
	if ( pcap_setfilter (pcap_handle, &bpf_prog) == -1 ){
		fprintf (stderr, "th_%d: cannot apply bpf program\n", listener_data->id);
		abort ();
	}
	
	fprintf (stderr, "th_%d: listener spawned (%s)\n", listener_data->id, listener_data->interface);
	
	for ( ;; ){
		pkt = pcap_next (pcap_handle, &pkt_header);
		
		if ( pkt == NULL )
			continue;
		
		eth_header = (struct ethhdr*) pkt;
		
		// NOTICE: memory is freed by executioner
		meta_pkt = metapkt_init (eth_header->h_source, pkt_header.ts.tv_sec);
	
		if ( meta_pkt == NULL ){
			fprintf (stderr, "th_%d: cannot allocate memory for meta packet\n", listener_data->id);
			abort ();
		}
		
		pthread_mutex_lock (&packet_queue_mut);
		if ( queue_enqueue (&packet_queue, (void*) meta_pkt) == NULL ){
			fprintf (stderr, "th_%d: cannot enqueue packet\n", listener_data->id);
			pthread_exit ((void*) EXIT_FAILURE);
		}
		pthread_cond_signal (&packet_queue_cond); // signal executioner
		pthread_mutex_unlock (&packet_queue_mut);
	}
	
	pcap_close (pcap_handle);
	
	pthread_exit ((void*) EXIT_SUCCESS);
}
