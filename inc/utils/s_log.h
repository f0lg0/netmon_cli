/*
+----------------------------------------+
|         stdout logger module           |
|                                        |
|     log incoming packets to            |
|               stdout                   |
|                                        |
|  Author: f0lg0                         |
|  Date: 31-12-2020 (dd-mm-yyyy)         |
+----------------------------------------+
*/

#include "../includes.h"

/**
 * print_pckt_payload: prints the data field of a packet to the screen
 * @param buffer memory containing the packets
 * @param brecv amount of data received
 * @param iphdrlen the length (or size) of the IP header
 * @return void
*/
void print_pckt_payload(unsigned char* buffer, ssize_t brecv, unsigned short iphdrlen) {
    // getting packet payload
    unsigned char* data = (buffer + sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr));
    int remaining_data = brecv - (sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr));
    
    printf("\n\tData\n\t");
    for(int i = 0; i < remaining_data; i++) {
        if(i != 0 && i % 16 == 0) {
            printf("\n\t");
        }
        printf(" %.2X ", data[i]);
    }
    printf("\n");
}

/**
 * print_ethhdr: extracts the ethernet header and prints it
 * @param buffer memory containing the packets
 * @return void
*/
void print_ethhdr(unsigned char* buffer) {
    /*
        Ethernet Packet
        struct ethhdr {
            unsigned char h_dest[ETH_ALEN];
            unsigned char h_source[ETH_ALEN];
            __be16 h_proto; --> packet type ID field
        } __attribute__((packed));
    */
    struct ethhdr* eth = (struct ethhdr *)(buffer);
    printf("\n\t┌─────────────────┐");
    printf("\n\t│ \033[1;31mEthernet Header\033[0m │");
    printf("\n\t└─────────────────┘\n");

    // %.2X --> at least 2 hex digits, if less itis prefixed with 0s 
    printf("\t\t├─ Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
    printf("\t\t├─ Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
    printf("\t\t├─ Protocol : 0x%.2x\n",eth->h_proto);
}

/**
 * print_iphdr: extracts and prints to the screen the IP header (it comes after the Ethernet header)
 * @param buffer memory containing the packets
 * @return void
*/
void print_iphdr(unsigned char* buffer) {
    struct iphdr* iphdr = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    struct sockaddr_in src, dst;
    bzero(&src, sizeof(src));
    bzero(&dst, sizeof(dst));

    src.sin_addr.s_addr = iphdr->saddr;
    dst.sin_addr.s_addr = iphdr->daddr;

    printf("\n\t┌────────────────┐");
    printf("\n\t│   \033[1;36mIP Header\033[0m    │");
    printf("\n\t└────────────────┘\n");
    printf("\t\t├─ Version : %d\n",(unsigned int)iphdr->version);
    printf("\t\t├─ Internet Header Length : %d DWORDS or %d Bytes\n",(unsigned int)iphdr->ihl,((unsigned int)(iphdr->ihl))*4);
    printf("\t\t├─ Type Of Service : %d\n",(unsigned int)iphdr->tos);
    printf("\t\t├─ Total Length : %d Bytes\n",ntohs(iphdr->tot_len));
    printf("\t\t├─ Identification : %d\n",ntohs(iphdr->id));
    printf("\t\t├─ Time To Live : %d\n",(unsigned int)iphdr->ttl);
    printf("\t\t├─ Protocol : %d\n",(unsigned int)iphdr->protocol);
    printf("\t\t├─ Header Checksum : %d\n",ntohs(iphdr->check));
    printf("\t\t├─ Source IP : %s\n", inet_ntoa(src.sin_addr));
    printf("\t\t├─ Destination IP : %s\n",inet_ntoa(dst.sin_addr));
}

/**
 * print_udppckt: prints to the screen a UPD packet
 * @param buffer memory containing the packets
 * @param brecv the amount of data received
 * @return void
*/
void print_udppckt(unsigned char* buffer, ssize_t brecv, unsigned int iphdrlen) {
    // getting UDP header
    struct udphdr* udph =(struct udphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen); 

    printf("\n\t┌────────────────┐");
    printf("\n\t│   \033[1;35mUDP Header\033[0m   │");
    printf("\n\t└────────────────┘\n");
    printf("\t\t├─ Source Port : %d\n" , ntohs(udph->source));
    printf("\t\t├─ Destination Port : %d\n" , ntohs(udph->dest));
    printf("\t\t├─ UDP Length : %d\n" , ntohs(udph->len));
    printf("\t\t├─ UDP Checksum : %d\n" , ntohs(udph->check));

    print_pckt_payload(buffer, brecv, iphdrlen);
}

/**
 * print_tcppckt: prints to the screen a TCP packet
 * @param buffer memory containing the packets
 * @param brecv the amount of data received
*/
void print_tcppckt(unsigned char* buffer, ssize_t brecv, unsigned int iphdrlen) {
    struct tcphdr* tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen);
    
    printf("\n\t┌────────────────┐");
    printf("\n\t│   \033[1;33mTCP Header\033[0m   │");
    printf("\n\t└────────────────┘\n");
	printf("\t\t├─ Source Port      : %u\n", ntohs(tcph->source));
	printf("\t\t├─ Destination Port : %u\n", ntohs(tcph->dest));
	printf("\t\t├─ Sequence Number    : %u\n", ntohl(tcph->seq));
	printf("\t\t├─ Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
	printf("\t\t├─ Header Length      : %d DWORDS or %d BYTES\n" , (unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	printf("\t\t├─ Urgent Flag          : %d\n", (unsigned int)tcph->urg);
	printf("\t\t├─ Acknowledgement Flag : %d\n", (unsigned int)tcph->ack);
	printf("\t\t├─ Push Flag            : %d\n", (unsigned int)tcph->psh);
	printf("\t\t├─ Reset Flag           : %d\n", (unsigned int)tcph->rst);
	printf("\t\t├─ Synchronise Flag     : %d\n", (unsigned int)tcph->syn);
	printf("\t\t├─ Finish Flag          : %d\n", (unsigned int)tcph->fin);
	printf("\t\t├─ Window         : %d\n",ntohs(tcph->window));
	printf("\t\t├─ Checksum       : %d\n",ntohs(tcph->check));
	printf("\t\t├─ Urgent Pointer : %d\n",tcph->urg_ptr);

    print_pckt_payload(buffer, brecv, iphdrlen);
}

/**
 * print_icmppckt: prints to the screen a ICMP packet
 * @param buffer memory containing the packets
 * @param brecv the amount of data received
 * @return void
*/
void print_icmppckt(unsigned char* buffer, ssize_t brecv, unsigned int iphdrlen) {
    struct icmphdr* icmph = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen); 

    printf("\n\t┌────────────────┐");
    printf("\n\t│   \033[1;34mICMP Header\033[0m  │");
    printf("\n\t└────────────────┘\n");
	printf("\t\t├─ Type : %d", (unsigned int)(icmph->type));
			
	if ((unsigned int)(icmph->type) == 11) {
		printf("\t(TTL Expired)\n");
	} else if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY) {
		printf("\t(ICMP Echo Reply)\n");
	}

    printf("\t\t├─ Code : %d\n", (unsigned int)(icmph->code));
	printf("\t\t├─ Checksum : %d\n", ntohs(icmph->checksum));

    print_pckt_payload(buffer, brecv, iphdrlen);
}