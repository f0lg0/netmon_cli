#ifndef INFO_GATHERING_H
#define INFO_GATHERING_H

/**
 * hostinfo: information about an host
*/
typedef struct {
    char* hostname;
    char ipstr_v4[INET_ADDRSTRLEN];
    char ipstr_v6[INET6_ADDRSTRLEN];
} hostinfo;


/* [BEGIN] host info gathering */

hostinfo* alloc_hinfo();
hostinfo* showip(char* host);

/* [END] host info gathering */

#endif