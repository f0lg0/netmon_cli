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
 * @param rsock a pointer to an int to store the socket file descriptor
 * @return 0 if success, 1 if failure
*/
int open_rsock() {
    int rsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    setsockopt(rsock , SOL_SOCKET , SO_BINDTODEVICE , "wlp5s0" , strlen("wlp5s0") + 1);

    if (rsock < 0) return -1;

    return rsock;
}

unsigned char* alloc_pckts_buffer() {
    unsigned char* buffer = malloc(BUFF_SIZE);
    bzero(buffer, BUFF_SIZE);

    return buffer;
}

/**
 * recv_net_pckts: receive network packets
 * @param rsock pointer to a raw socket file descriptor
 * @return 0 if success, 1 if failure
*/
int recv_net_pckts(int* rsock) {
    // allocating buffer to receive data
    unsigned char* buffer = alloc_pckts_buffer();

    struct sockaddr saddr;
    size_t saddr_len = sizeof(saddr);
    
    ssize_t brecv = recvfrom(*rsock, buffer, BUFF_SIZE, 0, &saddr, (socklen_t *)&saddr_len);

    if (brecv < 0) {
        printf("[ERROR] (recv_net_pckts: %d) Failed to receive data.\n", brecv);
        return 1;
    }

    return 0;
}