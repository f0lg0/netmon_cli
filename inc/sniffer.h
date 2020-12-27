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