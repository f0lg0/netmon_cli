/*
+----------------------------------------+
|           sniffer module               |
|                                        |
|     packet sniffer written using       |
|            raw sockets                 |
|                                        |
|  Author: f0lg0                         |
|  Date: 31-12-2020 (dd-mm-yyyy)         |
+----------------------------------------+
*/

#include "includes.h"
#include "utils/f_log.h"
#include "utils/s_log.h"
#define BUFF_SIZE 65536 // 0x10000

// global pointer defined in 'netmon.c'
// I was lazy so I used a global variable instead of passing the pointer to every function
extern FILE* log_f;

/**
 * open_sock: open a raw socket
 * ! NEED ROOT PERMISSIONS
 * @param void
 * @return raw socket if success, -1 if failure
*/
int open_rsock() {
    printf("[  \033[1;33mLOG\033[0m  ] Opening raw socket...\n");

    int rsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    setsockopt(rsock , SOL_SOCKET , SO_BINDTODEVICE , "wlp5s0" , strlen("wlp5s0") + 1);

    if (rsock < 0) return -1;

    printf("[  \033[1;33mLOG\033[0m  ] Raw socket opened.\n");
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
 * process_pcket: sorts an incoming packet
 * @param buffer memory containing packets
 * @param brecv amount of data received
 * @param totpckts the number of packets received (increases)
*/
void process_pcket(unsigned char* buffer, ssize_t brecv, int totpckts, int logfile) {
    // getting the IP header
    struct iphdr* iphdr = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    
    // getting size from IHL (Internet Header Length), which is the number of 32-bit words.
    // multiply by 4 to get the size in bytes
    unsigned int iphdrlen = iphdr->ihl * 4;

    if (logfile == 0) {
        printf("\n\033[1;32m[>] Sniffed Packet #%d\033[0m\n", totpckts);

        print_ethhdr(buffer);
        print_iphdr(buffer);

        /* vim /etc/protocols */
        switch (iphdr->protocol) {
            // ICMP
            case 1: 
                print_icmppckt(buffer, brecv, iphdrlen);
                break;

            // TCP
            case 6: 
                print_tcppckt(buffer, brecv, iphdrlen);
                break;

            // UDP
            case 17:
                print_udppckt(buffer, brecv, iphdrlen);
                break;
            
            default:
                break;
        }
    } else {
        fprintf(log_f, "\n[>] Sniffed Packet #%d\n", totpckts);
        dump_ethhdr_to_log(buffer);
        dump_iphdr_to_log(buffer);

        /* vim /etc/protocols */
        switch (iphdr->protocol) {
            // ICMP
            case 1: 
                dump_icmppckt_to_log(buffer, brecv, iphdrlen);
                break;

            // TCP
            case 6: 
                dump_tcppckt_to_log(buffer, brecv, iphdrlen);
                break;

            // UDP
            case 17:
                dump_udppckt_to_log(buffer, brecv, iphdrlen);
                break;
            
            default:
                break;
        }

        fflush(log_f);
    }

}

/**
 * run_sniffer: receive network packets
 * @param rsock pointer to a raw socket file descriptor
 * @return 0 if success, -1 if failure
*/
int run_sniffer(int* rsock, unsigned char* buffer, int pckts_num, int logfile) {
    if (logfile != 0 && logfile != 1) {
        return -1;
    } else if (logfile == 1) {
        openlog();
    };

    struct sockaddr saddr;
    struct sockaddr* p_saddr = &saddr;
    size_t saddrlen = sizeof(saddr);

    ssize_t brecv;
    if (pckts_num > 0) {
        for (int i = 0; i < pckts_num; i++) {
            if ((brecv = recv_net_pckts(rsock, buffer, p_saddr, saddrlen)) == -1) return -1;
            process_pcket(buffer, brecv, i, logfile);
        }
    } else if (pckts_num == 0) {
        int i = 0;
        while (1) {
            if ((brecv = recv_net_pckts(rsock, buffer, p_saddr, saddrlen)) == -1) return -1;
            process_pcket(buffer, brecv, i, logfile);
            i++;
        }
    } else {
        return -1;
    }
    
    free(buffer);
    return 0;
}
