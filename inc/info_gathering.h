/*
+----------------------------------------+
|        info gathering header           |
|                                        |
|        see info_gathering.c            |
|                                        |
|  Author: f0lg0                         |
|  Date: 01-01-2021 (dd-mm-yyyy)         |
+----------------------------------------+
*/

#ifndef INFO_GATHERING_H
#define INFO_GATHERING_H

/* [BEGIN] host info gathering */

/**
 * hostinfo: information about an host
*/
typedef struct {
    char* hostname;
    char ipstr_v4[INET_ADDRSTRLEN];
    char ipstr_v6[INET6_ADDRSTRLEN];
} hostinfo;


hostinfo* alloc_hinfo();
hostinfo* showip(char* host);

/* [END] host info gathering */

#endif