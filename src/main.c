#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "udp.h"  // sendMsg
#include "dns.h"  // buildDnsQuery, parseDnsResponse
#include "mdns.h" // startMonitor

static void
usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [-m] [-q | -r] OR [TYPE] <domain_name> <dns_server>\n", progname);
    fprintf(stderr, "  -m        : Monitor mDNS\n");
    fprintf(stderr, "  <domain_name> : The domain name to query\n");
    fprintf(stderr, "  <dns_server>  : The DNS server to use\n");
    fprintf(stderr, "Example 1: %s -m\n", progname);
    fprintf(stderr, "Example 4: %s www.example.com 8.8.8.8\n", progname);
    fprintf(stderr, "Example 4: %s A www.example.com 8.8.8.8\n", progname);
    fprintf(stderr, "Example 4: %s PTR 8.8.8.8.in-addr.arpa 8.8.8.8\n", progname);
}

int
main(int argc, char *argv[])
{
    int opt;
    enum monitorType monType = ALL;
    int dnsType = 0;
    char *name = NULL;
    char *dns = NULL;
    const int port = 53;
    int rc = EXIT_SUCCESS;
    int msgLen = 1024;
    uint8_t *msg = calloc(msgLen, 1);

    bool isMonitor = false;
    
    while((opt = getopt(argc, argv, "maqrh:")) != -1)  
    {  
        switch(opt)  
        {  
            case 'm':  
                isMonitor = true;  
                break;
            case 'a':
                monType = ALL;
                break;
            case 'q':
                monType = QUERY;
                break;
            case 'r':
                monType = REQUEST;
                break;
            case 'h':
                usage(argv[0]);
                goto out;
        }
    }

    if (isMonitor == true) {
        startMonitor(monType);
        goto out;
    }

    if (argc - optind < 2) {
        usage(argv[0]);
        rc = EXIT_FAILURE;
        goto out;
    }

    if ((argc - optind) == 3) {
        dnsType = STR_TO_DNS_TYPE(argv[argc - 3]);
        name = argv[argc - 2];
        dns = argv[argc - 1];
    } else if ((argc - optind) == 2) {
        dnsType = A;
        name = argv[argc - 2];
        dns = argv[argc - 1];
    }

    if (dnsType == -1) {
        fprintf(stderr, "wrong DNS type\n");
        usage(argv[0]);
        rc = EXIT_FAILURE;
        goto out;
    }

    msg = calloc(msgLen, 1);
    if (msg == NULL) {
        fprintf(stderr, "memory error\n");
        goto out;
    }

    buildDnsQuery(name, dnsType, &msg, &msgLen);
    rc = sendMsg(dns, port, msg, msgLen);
    free(msg);

out:
    return rc;
}

