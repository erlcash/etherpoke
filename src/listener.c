#include <stdlib.h>
#include <pcap.h>
#include <netinet/ether.h>

#include "listener.h"

void*
listener_main (void *th_data)
{
	listener_data_t *listener_data;
	pcap_t *pcap_handle;
	struct pcap_pkthdr pkt_header;
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char *pkt = NULL;
	struct ethhdr *eth_header;
	
	listener_data = (listener_data_t*) th_data;
	
	pcap_handle = pcap_open_live (listener_data->interface, SNAPSHOT_LENGTH, 1, 0, errbuf);
	
	if ( pcap_handle == NULL ) {
		fprintf (stderr, "th_%d: cannot open device '%s': %s\n", listener_data->id, listener_data->interface, errbuf);
		pthread_exit (NULL);
	}
	
	for ( ;; ){
		pkt = pcap_next (pcap_handle, &pkt_header);
		
		if ( pkt == NULL )
			continue;
		
		eth_header = (struct ethhdr*) pkt;
	}
	
	pcap_close (pcap_handle);
	
	pthread_exit (NULL);
}
