#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "udp.h" // sendMsg
#include "dns.h" // buildDnsQuery, parseDnsResponse
#include "mdns.h" // startMonitor

void usage(const char *progname) {
    fprintf(stderr, "Usage: %s [-m] [-q | -r] <domain_name> <dns_server>\n", progname);
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

int main(int argc, char *argv[]) {
    int opt;
    char flags = 0;
    while((opt = getopt(argc, argv, "maqrh")) != -1)  
    {  
        switch(opt)  
        {  
            case 'm':  
                flags |= 0x1;  
                break;
            case 'q':
                flags |= 0x4; 
                break;
            case 'r':
                flags |= 0x8;
                break;
            case 'h':
                usage(argv[0]);
                return EXIT_SUCCESS;
        }
    }

    if (flags > 9) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if ((flags & 1) == 1) {
        startMonitor(parseDnsResponse, flags);
        return EXIT_SUCCESS;
    }

    if (argc - optind < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *name = argv[argc - optind - 1];
    const char *dns = argv[argc - optind];
    const int port = 53;

    int rc = 0;
    rc = sendMsg(dns, port, buildDnsQuery, (void*)name, parseDnsResponse);
    return rc;
}

