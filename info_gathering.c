/*
+----------------------------------------+
|        info gathering module           |
|                                        |
|      host info gathering functions     |
|                                        |
|  Author: f0lg0                         |
|  Date: 01-01-2021 (dd-mm-yyyy)         |
+----------------------------------------+
*/

#include "inc/includes.h"
#include "inc/info_gathering.h"


/* [BEGIN] host info gathering */

/**
 * alloc_hinfo: allocate memory for the hinfo struct
 * @param void
 * @return pointer to a new hinfo struct
*/
hostinfo* alloc_hinfo() {
    hostinfo* hinfo = malloc(sizeof(hostinfo));
    hinfo->hostname = NULL;
    hinfo->ipstr_v4[0] = -1;
    hinfo->ipstr_v6[0] = -1;

    return hinfo; 
}

/**
 * showip: get public ip (v4 and v6) from hostname
 * @param host hostname as string
 * @return pointer to hinfo struct about the newly analyzed host
*/
hostinfo* showip(char* host) {
    hostinfo* hinfo = alloc_hinfo();
    hinfo->hostname = malloc(strlen(host));
    strcpy(hinfo->hostname, host);

    struct addrinfo hints, *res, *idx;
    int status;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(host, NULL, &hints, &res)) != 0) {
	    fprintf(stderr, "[ \033[1;31mERROR\033[0m ] getaddrinfo: %s\n", gai_strerror(status));
        free(hinfo->hostname);
        free(hinfo);

	    return NULL;
    }

    for (idx = res; idx != NULL; idx = idx->ai_next) {
        void *addr;

        if (idx->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)idx->ai_addr;
            addr = &(ipv4->sin_addr);
            inet_ntop(idx->ai_family, addr, hinfo->ipstr_v4, sizeof(hinfo->ipstr_v4));
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)idx->ai_addr;
            addr = &(ipv6->sin6_addr);
            inet_ntop(idx->ai_family, addr, hinfo->ipstr_v6, sizeof(hinfo->ipstr_v6));
        }
        
    }

    if (hinfo->ipstr_v4[0] == -1) {
        memcpy(hinfo->ipstr_v4, "NULL", sizeof("NULL"));
    } else if (hinfo->ipstr_v6[0] == -1) {
        memcpy(hinfo->ipstr_v6, "NULL", sizeof("NULL"));
    }

    freeaddrinfo(res);

    return hinfo;
};

/* [END] host info gathering */