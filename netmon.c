#include "inc/includes.h"
#include "inc/utils/info_gathering.h"

int main(int argc, char *argv[]) {
    hostinfo* hinfo = showip(argv[1]);
    printf("IP addresses for %s:\n\n", argv[1]);
    printf("\tIPv4: %s\n", hinfo->ipstr_v4);
    printf("\tIPv6: %s\n", hinfo->ipstr_v6);

    return 0;
}
