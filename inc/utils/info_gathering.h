#include "../includes.h"

typedef struct {
    char* hostname;
    char ipstr_v4[INET_ADDRSTRLEN];
    char ipstr_v6[INET6_ADDRSTRLEN];
} hostinfo;

typedef struct {
    char* netname;
    char* dlspeed;
    char* ulspeed;
} curr_netinfo;

/* [BEGIN] host info gathering */

hostinfo* alloc_hinfo() {
    hostinfo* hinfo = malloc(sizeof(hostinfo));
    hinfo->hostname = NULL;
    hinfo->ipstr_v4[0] = -1;
    hinfo->ipstr_v6[0] = -1;

    return hinfo; 
}

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

    // char* filename = "enwik9.zip";
    // FILE *file = NULL;
    // int file_len = 308000000;
    // char* server_reply = malloc(file_len);
    // int total_len = 0;

    printf("[x] creating socket...\n");
    if (devmode == 1) printf("[DEBUG] res->ai_family: %d, res->ai_socktype: %d, res->ai_protocol: %d\n", res->ai_family, res->ai_socktype, res->ai_protocol);

    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    printf("[!] sockfd: %d\n", sockfd);

    printf("[x] connecting...\n");
    if (devmode == 1) printf("[DEBUG] sockfd: %d, res->ai_addr: %p, res->ai_addrlen: %d\n", sockfd, res->ai_addr, res->ai_addrlen);

    status = connect(sockfd, res->ai_addr, res->ai_addrlen);
    printf("[STATUS] connection: %d\n", status);

    char* req = "GET /dc/enwik9.zip HTTP/1.0\r\n\r\nHost: www.mattmahoney.net\r\n\r\n Connection: keep-alive\r\n\r\n Keep-Alive: 300\r\n";
    ssize_t bsent = send(sockfd, req, strlen(req) , 0);
    printf("[LOG] sent: %d\n", bsent);

    // remove(filename);

    // file = fopen(filename, "ab+");

    // if (!file){
    //     printf("File could not opened");
    //     return NULL;
    // }   

    // while(1) {
    //     int received_len = recv(sockfd, server_reply , sizeof(server_reply) , 0);

    //     if (received_len < 0 ){
    //         puts("recv failed");
    //         break;
    //     }

    //     total_len += received_len;
  
    //     fwrite(server_reply , received_len , 1, file);

    //     printf("\nReceived byte size = %d\nTotal lenght = %d", received_len, total_len);

    //     if( total_len >= file_len ){
    //         break;
    //     }   
    // }

    // puts("Reply received\n");

    // fclose(file);


    freeaddrinfo(res); // free linked list

    return NULL;
}

float dl_speed() {

}

float ul_speed() {

}

/* [END] net info gathering */