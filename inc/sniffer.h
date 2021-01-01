/*
+----------------------------------------+
|           sniffer header               |
|                                        |
|            see sniffer.c               |
|                                        |
|  Author: f0lg0                         |
|  Date: 01-01-2021 (dd-mm-yyyy)         |
+----------------------------------------+
*/

#ifndef SNIFFER_H
#define SNIFFER_H
#include <stddef.h>

extern FILE* log_f;
int open_rsock();
unsigned char* alloc_pckts_buffer();
ssize_t recv_net_pckts(int* rsock, unsigned char* buffer, struct sockaddr* saddr, size_t saddrlen);
void process_pcket(unsigned char* buffer, ssize_t brecv, int totpckts, int logfile);
int run_sniffer(int* rsock, unsigned char* buffer, int pckts_num, int logfile);

#endif