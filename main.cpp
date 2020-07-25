#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

//#define IPPROTO_TCP 0x06

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

void printData(u_char* data){
	printf("data : ");
	for(int i=0;i<16;i++){
		printf("%02X ", (uint8_t)data[i]);
	}
	printf("\n");
}
void printMAC(struct libnet_ethernet_hdr* ehdr){
	printf("Dst Mac : ");
	for(int i=0;i<6;i++){
		printf("%02x", ehdr->ether_dhost[i]);
		if(i < 5) printf(":");
	}
	printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
	struct libnet_ethernet_hdr* ehdr;
	struct libnet_ipv4_hdr* ihdr;
	struct libnet_tcp_hdr* thdr;
	char* data_ptr;
	char data[10];

        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
	
	ehdr = (struct libnet_ethernet_hdr *)packet;
	
	//int res2 = pcap_next_ex(handle, &ihdr, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
	
        //printf("%u bytes captured\n", header->caplen);
	//printf("ethernet : %u\n", ehdr->ether_type);
	//printf("ethernet src : %u.%u\n", ehdr->ether_shost[0], ehdr->ether_shost[1]);
	//printf("sizeof(ehdr) : %u\n", sizeof(*ehdr));
	int dst_size = sizeof(ehdr->ether_dhost);
	int src_size = sizeof(ehdr->ether_shost);
	int src_ip_size = sizeof(ihdr->ip_src);
	int dst_ip_size = sizeof(ihdr->ip_dst);
	
	/**
	printf("dst mac addr : ");
	for (int i=0;i<dst_size;i++){
		printf("%u.", ehdr->ether_dhost[i]);
	}
	printf("\n");
	
	printf("src mac addr : ");
	for (int i=0;i<dst_size;i++){
		printf("%u.", ehdr->ether_shost[i]);
	}
	printf("\n");
	**/
	packet += 14;
	ihdr = (struct libnet_ipv4_hdr *)packet;

	
	//printf("IP protocol : %02X\n", ihdr->ip_p);
        
	struct libnet_ipv4_hdr* tlen = (struct libnet_ipv4_hdr *)packet;

        u_int lengh = htons(tlen->ip_len) - (uint16_t)(tlen->ip_hl)*4;

        packet +=(uint16_t)(tlen->ip_hl)*4;
	thdr = (struct libnet_tcp_hdr *)packet;

	//printf("Src Port : %d\n", ntohs(thdr->th_sport));
    	//printf("Dst Port : %d\n", ntohs(thdr->th_dport));
	//printf("data offset : %d\n", thdr->th_off);
	
	//printf("data offset : %u\n", thdr->th_off);
	packet += (uint16_t)(thdr->th_off)*4;
	int payload_len = ntohs(ihdr->ip_len) - (ihdr->ip_hl + (uint16_t)(thdr->th_off)*4);
	//printf("payload_len : %u\n", payload_len);
	//printf("ntohs(ihdr->ip_len) : %u\n", ntohs(ihdr->ip_len));
	data_ptr = (char *)packet;
	strncpy(data, data_ptr, 16);

	
	
	//printf("IP protocol : %02X\n", ihdr->ip_p);
	
	if (ihdr->ip_p == IPPROTO_TCP)
        {
		printMAC(ehdr);
		printf("Src Mac %02x:%02x:%02x:%02x:%02x:%02x \n",ehdr->ether_shost[0],ehdr->ether_shost[1],ehdr->ether_shost[2],ehdr->ether_shost[3],ehdr->ether_shost[4],ehdr->ether_shost[5]);

		char *net;
		net = inet_ntoa(ihdr->ip_src);
		if(net == NULL)
		{
		    perror("inet_ntoa");
		    exit(1);
		}
		printf("Src ip : %s\n", inet_ntoa(ihdr->ip_src));
		printf("Dst ip : %s\n", inet_ntoa(ihdr->ip_dst));

		printf("Src Port : %d\n", ntohs(thdr->th_sport));
	    	printf("Dst Port : %d\n", ntohs(thdr->th_dport));
		//printf("data offset : %d\n", thdr->th_off);
		printData(const_cast<u_char*>(packet));	
		printf("-------------------------------------------\n");
        }
	
    }

    pcap_close(handle);
}
