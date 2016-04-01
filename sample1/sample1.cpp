#include <string.h>
#include "pcap.h"

#define IP_HEADER 0x0800
#define ARP_HEADER 0x0806
#define REVERSE_ARP_HEADER 0x0835
#define SYN 0x02
#define PUSH 0x08
#define ACK 0x10
#define SYN_ACK 0x12
#define PUSH_ACK 0x18
#define FIN_ACK 0x11
#define TCP 0x06
#define UDP 0x11

typedef struct ether_header{
	u_char dstMac[6];
	u_char srcMac[6];
	u_short type;
}ether_header;

/* prototype of the packet handler */
typedef struct ip_header{
	u_char ip_leng : 4;
	u_char ip_version : 4;
	u_char ip_tos;
	u_short ip_total_length;
	u_short ip_id;
	u_short ip_flags_fo;
	u_char ip_ttl;
	u_char ip_protocol;
	u_short ip_checksum;
	in_addr src_addr;
	in_addr dst_addr;
}ip_header;

typedef struct tcp_header{
	u_short src_port;
	u_short dst_port;
	u_int sequence;
	u_int acknowledge;
	u_char ns : 1;
	u_char reserved_part1 : 3;
	u_char length : 4;
	u_char flag;
	u_short window;
	u_short checksum;
	u_short urgent_pointer;
}tcp_header;

typedef struct udp_header{
	u_short src_port;
	u_short dst_port;
	u_short length;
	u_short checksum;
};

typedef struct udpHeader{

}udpHeader;
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void print_ether_header(ether_header *eh);
void print_ip_header(ip_header *ih);
void print_tcp_header(tcp_header *th);
void print_udp_header(udp_header *uh);
void print_data(const u_char *pkt_data, int length);

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		//printf("%d. %s", ++i, d->name);
		if (d->description)
			printf("%d. (%s)\n",++i, d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the device */
	if ((adhandle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture
		// 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
		1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm ltime;
	char timestr[16];
	int i, j, k;
	ether_header *eh;
	ip_header *ih;
	tcp_header *th;
	udp_header *uh;

	eh = (ether_header*)pkt_data;
	pkt_data += sizeof(*eh);
	print_ether_header(eh);
	ih = (ip_header*)(pkt_data);
	pkt_data += sizeof(*ih);
	print_ip_header(ih);
	if (ih->ip_protocol == TCP){
		th = (tcp_header*)(pkt_data);
		pkt_data += sizeof(*th);
		print_tcp_header(th);
		print_data(pkt_data, htons(ih->ip_total_length) - ih->ip_leng*4 - th->length*4);
	}
	else if (ih->ip_protocol == UDP){
		uh = (udp_header*)(pkt_data);
		pkt_data += sizeof(*uh);
		print_udp_header(uh);
		print_data(pkt_data, htons((uh->length))-8);
	}
}

void print_ether_header(ether_header *eh){
	printf("Destination MAC : ");
	for (int i = 0; i < 6; i++)
		printf("%02x ", eh->dstMac[i]);
	printf("\nSource MAC : ");
	for (int i = 0; i < 6; i++)
		printf("%02x ", eh->srcMac[i]);
	
	printf("\n");
}
void print_ip_header(ip_header *ih){
	printf("Source IP : %s\n", inet_ntoa(ih->src_addr));
	printf("Destination IP : %s\n", inet_ntoa(ih->dst_addr));
}
void print_tcp_header(tcp_header *th){
	printf("Source Port : %d\n", htons(th->src_port));
	printf("Destination Port : %d\n", htons(th->dst_port));
}
void print_udp_header(udp_header *uh){
	printf("Source Port : %d\n", htons(uh->src_port));
	printf("Destination Port : %d\n", htons(uh->dst_port));
}
void print_data(const u_char *pkt_data, int length){
	int k=0;
	int l = 0;
	for (int i = 0; k < length; i += 16){
		printf("%05d   ", i);
		for (l = 0; l < 16 && (k + l) < length; l++)
			printf("%02x ", pkt_data[k + l]);

		printf("   ");

		for (int j = 0; j < 16 - l; j++){
			printf("   ");
		}

		for (int j = 0; j < 16 && k < length; j++, k++){
			if (pkt_data[k] > '!' && pkt_data[k] < '}' + 1)
				putchar(pkt_data[k]);
			else
				putchar('.');
		}
		putchar('\n');
	}
	putchar('\n');
}