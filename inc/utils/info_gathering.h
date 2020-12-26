#include "../includes.h"
#include "http_parser.h"

/**
 * hostinfo: information about an host
*/
typedef struct {
    char* hostname;
    char ipstr_v4[INET_ADDRSTRLEN];
    char ipstr_v6[INET6_ADDRSTRLEN];
} hostinfo;

/**
 * curr_netinfo: information about the current network 
*/
typedef struct {
    char* netname;
    char* dlspeed;
    char* ulspeed;
} curr_netinfo;

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

    struct addrinfo hints, *res, *p;
    int status;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(host, NULL, &hints, &res)) != 0) {
	    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
	    return NULL;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;

        // get the pointer to the address itself,
        // different fields in IPv4 and IPv6
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            inet_ntop(p->ai_family, addr, hinfo->ipstr_v4, sizeof(hinfo->ipstr_v4));
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            inet_ntop(p->ai_family, addr, hinfo->ipstr_v6, sizeof(hinfo->ipstr_v6));
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

/* [BEGIN] net info gathering */

/**
 * alloc_curr_netinfo: allocate memory for curr_netinfo struct
 * @param void
 * @return pointer to the newly created curr_netinfo struct
*/
curr_netinfo* alloc_curr_netinfo() {
    curr_netinfo* net = malloc(sizeof(curr_netinfo));
    net->netname = NULL;
    net->dlspeed = NULL;
    net->ulspeed = NULL;

    return net;
}

/*


    Create a socket using socket()
    Call connect() on it.
    Send a GET /path/filename HTTP/1.0\r\n\r\n request using either send() or write() properly.
    Receive the response using either recv() or read() properly.
    Parse the response to find out if the request succeeded and what format the file data is being sent as.
    Receive the file data, if present, using either recv() or read().
    Close the socket using close().


*/
curr_netinfo* netinfo(char* host, int devmode) {
    struct addrinfo hints, *res, *phelper;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
    hints.ai_socktype = SOCK_STREAM;

    int status;
    if ((status = getaddrinfo(host, "80", &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return NULL;
    }

    if (devmode == 1) {
        printf("[DEBUG] status: %d\n", status);
        printf("[DEBUG] res: %p\n", res);
    }

    struct addrinfo* res_v4 = NULL;
    struct addrinfo* res_v6 = NULL;
    for (phelper = res; phelper != NULL; phelper = phelper->ai_next) {
        if (devmode == 1) {
            printf("[DEBUG] phelper: %p\n", phelper);
            printf("[DEBUG] phelper->ai_family: %d\n", phelper->ai_family);
        
        }

        if (phelper->ai_family == AF_INET && !res_v4) {
            res_v4 = phelper;
        } else if (phelper->ai_family == AF_INET6 && !res_v6) {
            res_v6 = phelper;
        } else {
            continue;
        }
    }

    if (!res_v4 && !res_v6) return NULL;

    printf("[x] creating socket...\n");
    if (devmode == 1) printf("[DEBUG] res->ai_family: %d, res->ai_socktype: %d, res->ai_protocol: %d\n", res->ai_family, res->ai_socktype, res->ai_protocol);

    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    printf("[!] sockfd: %d\n", sockfd);

    printf("[x] connecting...\n");
    if (devmode == 1) printf("[DEBUG] sockfd: %d, res->ai_addr: %p, res->ai_addrlen: %d\n", sockfd, res->ai_addr, res->ai_addrlen);

    status = connect(sockfd, res->ai_addr, res->ai_addrlen);
    printf("[STATUS] connection: %d\n", status);

    char* req = "GET /dc/enwik9.zip HTTP/1.1\r\nHost: www.mattmahoney.net\r\n\n";
    ssize_t bsent = send(sockfd, req, strlen(req) , 0);
    printf("[LOG] sent: %d\n", bsent);

    // int SIZE = 1024;
    // int n;
    // FILE *fp;
    // char *filename = "recv.txt";
    // char buffer[SIZE];

    // fp = fopen(filename, "w");
    // while (1) {
    //     n = recv(sockfd, buffer, SIZE, 0);
    //     if (n <= 0){
    //         break;
    //         return NULL;
    //     }
    //     fprintf(fp, "%s", buffer);
    //     bzero(buffer, SIZE);
    // }

    long bufflen = 1024;
    char buffer[bufflen]; 

    ssize_t brecv = recv(sockfd, buffer, bufflen, 0);

    printf("[x] recv: %d\n", brecv);
    printf("[x] buffer: %p\n", buffer);


    char* result[2];
    contentinfo(buffer, result);
    printf("%s\n", result[0]);
    printf("%s\n", result[1]);

    printf("%d\n", parse_hcontentlength(result[0]));
    printf("%s\n", parse_hcontenttype(result[1]));

    free(result[0]);
    free(result[1]);

    freeaddrinfo(res); // free linked list

    return NULL;
}

float dl_speed() {

}

float ul_speed() {

}

/* [END] net info gathering */