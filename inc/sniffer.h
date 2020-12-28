/*
+----------------------------------------+
|           sniffer module               |
|                                        |
|     packet sniffer written using       |
|            raw sockets                 |
|                                        |
|  Author: f0lg0                         |
|  Date: 27-12-2020 (dd-mm-yyyy)         |
+----------------------------------------+
*/

#include "includes.h"
#define BUFF_SIZE 65536

/**
 * open_sock: open a raw socket
 * ! NEED ROOT PERMISSIONS
 * @param void
 * @return raw socket if success, -1 if failure
*/
int open_rsock() {
    printf("[LOG] Opening raw socket...\n");

    int rsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    setsockopt(rsock , SOL_SOCKET , SO_BINDTODEVICE , "wlp5s0" , strlen("wlp5s0") + 1);

    if (rsock < 0) return -1;

    printf("[LOG] Raw socket opened.\n");
    return rsock;
}

/**
 * alloc_pckts_buffer: allocate huge buffer for packets
 * @param void
 * @return pointer to the newly allocated buffer
*/
unsigned char* alloc_pckts_buffer() {
    unsigned char* buffer = malloc(BUFF_SIZE);
    bzero(buffer, BUFF_SIZE);

    return buffer;
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
    printf("\n\tEthernet Header\n");

    // %.2X --> at least 2 hex digits, if less itis prefixed with 0s 
    printf("\t\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
    printf("\t\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
    printf("\t\t|-Protocol : 0x%.2x\n",eth->h_proto);
}

/**
 * print_iphdr: extracts and prints to the screen the IP header (it comes after the Ethernet header)
 * @param buffer memory containing the packets
 * @return void
*/
void print_iphdr(unsigned char* buffer) {
    struct iphdr* ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    struct sockaddr_in src, dst;
    bzero(&src, sizeof(src));
    bzero(&dst, sizeof(dst));

    src.sin_addr.s_addr = ip->saddr;
    dst.sin_addr.s_addr = ip->daddr;

    printf("\n\tIP Header\n");
    printf("\t\t|-Version : %d\n",(unsigned int)ip->version);
    printf("\t\t|-Internet Header Length : %d DWORDS or %d Bytes\n",(unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);
    printf("\t\t|-Type Of Service : %d\n",(unsigned int)ip->tos);
    printf("\t\t|-Total Length : %d Bytes\n",ntohs(ip->tot_len));
    printf("\t\t|-Identification : %d\n",ntohs(ip->id));
    printf("\t\t|-Time To Live : %d\n",(unsigned int)ip->ttl);
    printf("\t\t|-Protocol : %d\n",(unsigned int)ip->protocol);
    printf("\t\t|-Header Checksum : %d\n",ntohs(ip->check));
    printf("\t\t|-Source IP : %s\n", inet_ntoa(src.sin_addr));
    printf("\t\t|-Destination IP : %s\n",inet_ntoa(dst.sin_addr));
}

/**
 * print_udphdr: extracts and prints to the screen the UPD header
 * @param buffer memory containing the packets
 * @param brecv the amount of data received
 * @return void
*/
void print_udphdr(unsigned char* buffer, ssize_t brecv) {
    struct iphdr* ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    // getting size from IHL (Internet Header Length), which is the number of 32-bit words.
    // multiply by 4 to get the size in bytes
    unsigned int iphdrlen = ip->ihl * 4;

    // getting UDP header
    struct udphdr* udp =(struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr)); 

    printf("\n\tUDP Header\n");
    printf("\t\t|-Source Port : %d\n" , ntohs(udp->source));
    printf("\t\t|-Destination Port : %d\n" , ntohs(udp->dest));
    printf("\t\t|-UDP Length : %d\n" , ntohs(udp->len));
    printf("\t\t|-UDP Checksum : %d\n" , ntohs(udp->check));

    // Printing Data
    unsigned char* data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
    int remaining_data = brecv - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));

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
 * recv_net_pckts: stream net packets
 * @param rsock pointer to a raw socket
 * @param buffer memory to store packets
 * @param saddr pointer to an instance of the sockaddr structure
 * @param saddrlen size of the saddr instance
 * @return received bytes if success, -1 if failure
*/
ssize_t recv_net_pckts(int* rsock, unsigned char* buffer, struct sockaddr* saddr, size_t saddrlen) {
    // using recvfrom because "it permits the application to retrieve the source address of received data" (man)
    ssize_t brecv = recvfrom(*rsock, buffer, BUFF_SIZE, 0, saddr, (socklen_t *)&saddrlen);

    if (brecv < 0) {
        printf("[ERROR] (recv_net_pckts: %d) Failed to receive data.\n", brecv);
        return -1;
    }
    return brecv;
}

/**
 * run_sniffer: receive network packets
 * @param rsock pointer to a raw socket file descriptor
 * @return 0 if success, -1 if failure
*/
int run_sniffer(int* rsock, unsigned char* buffer, int pckts_num) {
    struct sockaddr saddr;
    struct sockaddr* p_saddr = &saddr;
    size_t saddrlen = sizeof(saddr);

    ssize_t brecv;
    if (pckts_num > 0) {
        for (int i = 0; i < pckts_num; i++) {
            if ((brecv = recv_net_pckts(rsock, buffer, p_saddr, saddrlen)) == -1) return -1;
            printf("\n[>] Sniffed Packet #%d\n", i);
            print_ethhdr(buffer);
            print_iphdr(buffer);
            print_udphdr(buffer, brecv);
        }
    } else if (pckts_num == 0) {
        int i = 0;
        while (1) {
            if ((brecv = recv_net_pckts(rsock, buffer, p_saddr, saddrlen)) == -1) return -1;
            printf("\n[>] Sniffed Packet #%d\n", i);
            print_ethhdr(buffer);
            print_iphdr(buffer);
            print_udphdr(buffer, brecv);
            i++;
        }
    } else {
        return -1;
    }
    
    free(buffer);
    return 0;
}

/**
 * openlog: open log file to dump packets
 * TODO: use a pcap file instead of a txt one
 * @param log a pointer to a FILE
 * @return 0 if success, 1 if failure
*/
int openlog(FILE* log) {
    log = fopen("log.txt", "w");
    if (!log) return 1;

    return 0;
}


/**
 * dump_ethh_to_log: dump sniffed eth header to log file
 * @param log pointer to a FILE
 * @param eth pointer to a struct ethhdr
 * @return void
*/
void dump_ethh_to_log(FILE* log, struct ethhdr* eth) {
    fprintf(log, "\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
    fflush(log);
}
