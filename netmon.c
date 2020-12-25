#include "inc/includes.h"
#include "inc/utils/info_gathering.h"
#define DWL_ENWIKI "mattmahoney.net"
// SAMPLE1 (308mb): http://mattmahoney.net/dc/enwik9.zip
// SAMPLE2 = www.axmag.com/download/pdfurl-guide.pdf


int main(int argc, char *argv[]) {
    hostinfo* hinfo = showip(DWL_ENWIKI);
    printf("IP addresses for %s:\n\n", DWL_ENWIKI);
    printf("\tIPv4: %s\n", hinfo->ipstr_v4);
    printf("\tIPv6: %s\n", hinfo->ipstr_v6);

    netinfo(DWL_ENWIKI, 1);

    return 0;
}
