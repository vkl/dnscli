#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "udp.h" // sendMsg
#include "dns.h" // buildDnsQuery, parseDnsResponse
#include "mdns.h" // startMonitor

static void
usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [-m] [-q | -r] OR <domain_name> <dns_server>\n", progname);
    fprintf(stderr, "  -m        : Monitor mDNS (requires -a, -q, or -r)\n");
    fprintf(stderr, "  -q        : Show only queries\n");
    fprintf(stderr, "  -r        : Show only replies\n");
    fprintf(stderr, "  <domain_name> : The domain name to query\n");
    fprintf(stderr, "  <dns_server>  : The DNS server to use\n");
    fprintf(stderr, "Example 1: %s -m\n", progname);
    fprintf(stderr, "Example 2: %s -m -q\n", progname);
    fprintf(stderr, "Example 3: %s -m -r\n", progname);
    fprintf(stderr, "Example 4: %s www.example.com 8.8.8.8\n", progname);
}

int
main(int argc, char *argv[])
{
    int opt;
    enum monitorType monType = ALL;
    char *dnsType = "A";
    bool isMonitor = false;
    
    while((opt = getopt(argc, argv, "maqrht:")) != -1)  
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
            case 't':
                dnsType = optarg;
                break;
            case 'h':
                usage(argv[0]);
                return EXIT_SUCCESS;
        }
    }

    if (isMonitor == true) {
        startMonitor(parseDnsResponse, monType);
        return EXIT_SUCCESS;
    }

    if (argc - optind < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *name = argv[argc - 2];
    const char *dns = argv[argc - 1];
    const int port = 53;

    int rc = 0;
    int msgLen = 1024;
    uint8_t *msg = calloc(msgLen, 1);
    buildDnsQuery(name, STR_TO_DNS_TYPE(dnsType), &msg, &msgLen);
#ifdef DEBUG_TRACE
    DEBUG_DUMP(msg, msgLen);
#endif
    rc = sendMsg(dns, port, msg, msgLen, parseDnsResponse);
    free(msg);
    return rc;
}

