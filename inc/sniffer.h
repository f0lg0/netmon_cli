#include "includes.h"

/**
 * openlog: open log file to dump packets
 * TODO: use a pcap fiel instead of a txt one
 * @param log a pointer to a FILE
 * @return 0 if success, 1 if failure
*/
int openlog(FILE* log) {
    log = fopen("log.txt", "w");
    if (!log) return 1;

    return 0;
}