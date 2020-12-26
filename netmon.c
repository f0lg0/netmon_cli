#include "inc/includes.h"
#include "inc/utils/info_gathering.h"

int main(int argc, char *argv[]) {
    hostinfo* hinfo = showip("google.com");
    printf("IP addresses for %s:\n\n", "google.com");
    printf("\tIPv4: %s\n", hinfo->ipstr_v4);
    printf("\tIPv6: %s\n", hinfo->ipstr_v6);

    free(hinfo->hostname);
    free(hinfo);

    return 0;
}
