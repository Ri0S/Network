#include <string.h>
#include "pcap.h"

/* prototype of the packet handler */
typedef struct pkt{
	u_char dstMac[6];
	u_char srcMac[6];
	u_char Type[2];
	u_char Protocal;
	const u_char *data;
	int dataLen;
	struct in_addr dstIPaddr;
	struct in_addr srcIPaddr;
	char dstAddr[16];
	char srcAddr[16];
	int dstPort;
	int srcPort;
}pkt;
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
pkt packet_anal(const u_char *pkt_data);

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
	pkt pk;
	time_t local_tv_sec;

	/*
	* unused variables
	*/
	(VOID)(param);
	(VOID)(pkt_data);

	pk = packet_anal(pkt_data);

	printf("Destination MAC: ");
	for (i = 0; i < 6; i++)
		printf("%02x ", pk.dstMac[i]);
	printf("\nSource MAC: ");
	for (i = 0; i < 6; i++)
		printf("%02x ", pk.srcMac[i]);

	printf("\nSource IP Address : %s\n", pk.srcAddr);
	printf("Destination IP : %s\n", pk.dstAddr);
	
	if (pk.Protocal == 0x06 || pk.Protocal == 0x11){

		printf("Source Port: %d\n", pk.srcPort);
		printf("Destination Port: %d\n", pk.dstPort);

		for (i = 0; i < pk.dataLen; i += 16){
			printf("%05d   ", i);
			for (j = 0; j < 16; j++){
				printf("%02x ", pk.data[i + j]);
				if (j == 7)
					printf(" ");
			}
			printf("    ");
			for (k = 0; k < 16; k++){
				if (pk.data[i + k] > 32 && pk.data[i + k] < 126)
					printf("%c", pk.data[i + k]);
				else
					printf(".");
			}
			printf("\n");
		}
	}
	printf("\n");

}
pkt packet_anal(const u_char *pkt_data){
	pkt pk = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	long temp = 0, temp2 = 0;
	int it;
	char st[5];

	for (int i = 0; i < 6; i++){
		pk.dstMac[i] = pkt_data[i];
		pk.srcMac[i] = pkt_data[i + 6];
	}
	pk.Type[0] = pkt_data[12];
	pk.Type[1] = pkt_data[13];

	pk.Protocal = pkt_data[23];

	for (int i = 4; i > 0; i--){
		temp += (pkt_data[0x1A + 4 - i] << 8 * (i - 1));
		it = pkt_data[0x1A + 4 - i];
		sprintf(st, "%d", it);
		strcat(pk.srcAddr, st);
		temp2 += (pkt_data[0x1E + 4 - i] << 8 * (i - 1));
		it = pkt_data[0x1E + 4 - i];
		sprintf(st, "%d", it);
		strcat(pk.dstAddr, st);
		if (i != 1){
			strcat(pk.srcAddr, ".");
			strcat(pk.dstAddr, ".");
		}
	}
	pk.srcIPaddr.S_un.S_addr = temp;
	pk.dstIPaddr.S_un.S_addr = temp2;



	pk.srcPort = (pkt_data[0x22] << 8) + pkt_data[0x23];
	pk.dstPort = (pkt_data[0x24] << 8) + pkt_data[0x25];

	pk.data = &pkt_data[0x36];
	pk.dataLen = (pkt_data[0x10] << 8) + pkt_data[0x11] - 40;

	return pk;
}