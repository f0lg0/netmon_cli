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
 * print_pckts_buffer: extracts the ethernet header and prints it
 * @param buffer memory containing the packets
 * @return void
*/
void print_pckts_buffer(unsigned char* buffer) {
    /*
        Ethernet Packet
        struct ethhdr {
            unsigned char h_dest[ETH_ALEN];
            unsigned char h_source[ETH_ALEN];
            __be16 h_proto; --> packet type ID field
        } __attribute__((packed));
    */
    struct ethhdr *eth = (struct ethhdr *)(buffer);
    printf("\nEthernet Header\n");

    // %.2X --> at least 2 hex digits, if less itis prefixed with 0s 
    printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
    printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
    printf("\t|-Protocol : 0x%.2x\n",eth->h_proto);
}

/**
 * recv_net_pckts: stream net packets
 * @param rsock pointer to a raw socket
 * @param buffer memory to store packets
 * @param saddr pointer to an instance of the sockaddr structure
 * @param saddr_len size of the saddr instance
 * @return 0 if success, -1 if failure
*/
int recv_net_pckts(int* rsock, unsigned char* buffer, struct sockaddr* saddr, size_t saddr_len) {
    // using recvfrom because "it permits the application to retrieve the source address of received data" (man)
    ssize_t brecv = recvfrom(*rsock, buffer, BUFF_SIZE, 0, saddr, (socklen_t *)&saddr_len);

    if (brecv < 0) {
        printf("[ERROR] (recv_net_pckts: %d) Failed to receive data.\n", brecv);
        return -1;
    }
    return 0;
}

/**
 * run_sniffer: receive network packets
 * @param rsock pointer to a raw socket file descriptor
 * @return 0 if success, -1 if failure
*/
int run_sniffer(int* rsock, unsigned char* buffer, int pckts_num) {
    struct sockaddr saddr;
    struct sockaddr* p_saddr = &saddr;
    size_t saddr_len = sizeof(saddr);

    if (pckts_num > 0) {
        for (int i = 0; i < pckts_num; i++) {
            if (recv_net_pckts(rsock, buffer, p_saddr, saddr_len) != 0) return -1;
            print_pckts_buffer(buffer);
        }
    } else if (pckts_num == 0) {
        while (1) {
            if (recv_net_pckts(rsock, buffer, p_saddr, saddr_len) != 0) return -1;
            print_pckts_buffer(buffer);
        }
    } else {
        return -1;
    }
    
    free(buffer);
    return 0;
}

