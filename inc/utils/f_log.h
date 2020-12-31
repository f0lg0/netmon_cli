/*
+----------------------------------------+
|          file logger module            |
|                                        |
|     log incoming packets to a          |
|              txt file                  |
|                                        |
|  Author: f0lg0                         |
|  Date: 31-12-2020 (dd-mm-yyyy)         |
+----------------------------------------+
*/

#include "../includes.h"

// global pointer defined in 'netmon.c'
// I was lazy so I used a global variable instead of passing the pointer to every function
extern FILE* log_f;

/**
 * openlog: open log file to dump packets
 * @return 0 if success, 1 if failure
*/
int openlog() {
    log_f = fopen("log.txt", "a");
    if (!log_f) return 1;

    return 0;
}

/**
 * dump_ethhdr_to_log: dump sniffed eth header to log file
 * @param buffer memory containing the packets
 * @return void
*/
void dump_ethhdr_to_log(unsigned char* buffer) {
    struct ethhdr* eth = (struct ethhdr *)(buffer);

    fprintf(log_f, "\n\tEthernet Header\n");
    fprintf(log_f, "\t\t├─ Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
    fprintf(log_f, "\t\t├─ Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
    fprintf(log_f, "\t\t├─ Protocol : 0x%.2x\n",eth->h_proto);
    
}

/**
 * dump_iphdr_to_log: dump sniffed IP header to log file
 * @param buffer memory containing the packets
 * @return void
*/
void dump_iphdr_to_log(unsigned char* buffer) {
    struct iphdr* iphdr = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    struct sockaddr_in src, dst;
    bzero(&src, sizeof(src));
    bzero(&dst, sizeof(dst));

    src.sin_addr.s_addr = iphdr->saddr;
    dst.sin_addr.s_addr = iphdr->daddr;

    fprintf(log_f, "\n\tIP Header\n");
    fprintf(log_f, "\t\t├─ Version : %d\n",(unsigned int)iphdr->version);
    fprintf(log_f, "\t\t├─ Internet Header Length : %d DWORDS or %d Bytes\n",(unsigned int)iphdr->ihl,((unsigned int)(iphdr->ihl))*4);
    fprintf(log_f, "\t\t├─ Type Of Service : %d\n",(unsigned int)iphdr->tos);
    fprintf(log_f, "\t\t├─ Total Length : %d Bytes\n",ntohs(iphdr->tot_len));
    fprintf(log_f, "\t\t├─ Identification : %d\n",ntohs(iphdr->id));
    fprintf(log_f, "\t\t├─ Time To Live : %d\n",(unsigned int)iphdr->ttl);
    fprintf(log_f, "\t\t├─ Protocol : %d\n",(unsigned int)iphdr->protocol);
    fprintf(log_f, "\t\t├─ Header Checksum : %d\n",ntohs(iphdr->check));
    fprintf(log_f, "\t\t├─ Source IP : %s\n", inet_ntoa(src.sin_addr));
    fprintf(log_f, "\t\t├─ Destination IP : %s\n",inet_ntoa(dst.sin_addr));
}

/**
 * dump_pckt_payload_to_log: dump sniffed packet payload to log file
 * @param buffer memoery containing the packets
 * @param brecv amount of data received
 * @param iphdrlen length (or size) of the IP header
 * @return void
*/
void dump_pckt_payload_to_log(unsigned char* buffer, ssize_t brecv, unsigned int iphdrlen) {
    // getting packet payload
    unsigned char* data = (buffer + sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr));
    int remaining_data = brecv - (sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr));
    
    fprintf(log_f, "\n\tData\n\t");
    for(int i = 0; i < remaining_data; i++) {
        if(i != 0 && i % 16 == 0) {
            fprintf(log_f, "\n\t");
        }
        fprintf(log_f, " %.2X ", data[i]);
    }
    fprintf(log_f, "\n");
}

/**
 * dump_icmppckt_to_log: dump sniffed ICMP packet to log file
 * @param buffer memory containing the packets
 * @param brecv amount of data received
 * @param iphdrlen the length (or size) of the IP header
 * @return void
*/
void dump_icmppckt_to_log(unsigned char* buffer, ssize_t brecv, unsigned int iphdrlen) {
    struct icmphdr* icmph = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen); 

    fprintf(log_f, "\n\tICMP Header\n");
	fprintf(log_f, "\t\t├─ Type : %d", (unsigned int)(icmph->type));
			
	if ((unsigned int)(icmph->type) == 11) {
		fprintf(log_f, "\t(TTL Expired)\n");
	} else if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY) {
		fprintf(log_f, "\t(ICMP Echo Reply)\n");
	}

    fprintf(log_f, "\t\t├─ Code : %d\n", (unsigned int)(icmph->code));
	fprintf(log_f, "\t\t├─ Checksum : %d\n", ntohs(icmph->checksum));

    unsigned char* data = (buffer + sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr));
    int remaining_data = brecv - (sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr));

    dump_pckt_payload_to_log(buffer, brecv, iphdrlen);
}

/**
 * dump_tcppckt_to_log: dump sniffed TCP packet to log file
 * @param buffer memory containing the packets
 * @param brecv amount of data received
 * @param iphdrlen the length (or size) of the IP header
 * @return void
*/
void dump_tcppckt_to_log(unsigned char* buffer, ssize_t brecv, unsigned int iphdrlen) {
    struct tcphdr* tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen);
    
    fprintf(log_f, "\n\tTCP Header\n");
	fprintf(log_f, "\t\t├─ Source Port      : %u\n", ntohs(tcph->source));
	fprintf(log_f, "\t\t├─ Destination Port : %u\n", ntohs(tcph->dest));
	fprintf(log_f, "\t\t├─ Sequence Number    : %u\n", ntohl(tcph->seq));
	fprintf(log_f, "\t\t├─ Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
	fprintf(log_f, "\t\t├─ Header Length      : %d DWORDS or %d BYTES\n" , (unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	fprintf(log_f, "\t\t├─ Urgent Flag          : %d\n", (unsigned int)tcph->urg);
	fprintf(log_f, "\t\t├─ Acknowledgement Flag : %d\n", (unsigned int)tcph->ack);
	fprintf(log_f, "\t\t├─ Push Flag            : %d\n", (unsigned int)tcph->psh);
	fprintf(log_f, "\t\t├─ Reset Flag           : %d\n", (unsigned int)tcph->rst);
	fprintf(log_f, "\t\t├─ Synchronise Flag     : %d\n", (unsigned int)tcph->syn);
	fprintf(log_f, "\t\t├─ Finish Flag          : %d\n", (unsigned int)tcph->fin);
	fprintf(log_f, "\t\t├─ Window         : %d\n",ntohs(tcph->window));
	fprintf(log_f, "\t\t├─ Checksum       : %d\n",ntohs(tcph->check));
	fprintf(log_f, "\t\t├─ Urgent Pointer : %d\n",tcph->urg_ptr);

    dump_pckt_payload_to_log(buffer, brecv, iphdrlen);
}
/**
 * dump_udppckt_to_log: dump sniffed UDP packet to log file
 * @param buffer memory containing the packets
 * @param brecv amount of data received
 * @param iphdrlen the length (or size) of the IP header
 * @return void
*/
void dump_udppckt_to_log(unsigned char* buffer, ssize_t brecv, unsigned int iphdrlen) {
    // getting UDP header
    struct udphdr* udph =(struct udphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen); 

    fprintf(log_f, "\n\tUDP Header\n");
    fprintf(log_f, "\t\t├─ Source Port : %d\n" , ntohs(udph->source));
    fprintf(log_f, "\t\t├─ Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(log_f, "\t\t├─ UDP Length : %d\n" , ntohs(udph->len));
    fprintf(log_f, "\t\t├─ UDP Checksum : %d\n" , ntohs(udph->check));

    dump_pckt_payload_to_log(buffer, brecv, iphdrlen);
}
