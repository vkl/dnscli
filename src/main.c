#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "udp.h" // sendMsg
#include "dns.h" // buildDnsQuery, parseDnsResponse
#include "mdns.h" // startMonitor

void usage(const char *progname) {
    fprintf(stderr, "Usage: %s [-m] OR <domain_name> <dns_server>\n", progname);
    fprintf(stderr, "  -m        : Monitor mDNS\n");
    fprintf(stderr, "  <domain_name> : The domain name to query\n");
    fprintf(stderr, "  <dns_server>  : The DNS server to use\n");
    fprintf(stderr, "Example 1: %s -m\n", progname);
    fprintf(stderr, "Example 2: %s www.example.com 8.8.8.8\n", progname);
}

void *worker(void *arg) {
    printf("arg: %s\n", (char*)arg);
    for (int i=0; i<5; i++) {
        sleep(1);
        printf("waiting... %d\n", i);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    int opt;
    char flags = 0;
    while((opt = getopt(argc, argv, "mh")) != -1)  
    {  
        switch(opt)  
        {  
            case 'm':  
                flags = (1 << 0);  
                break;
            case 'h':
                usage(argv[0]);
                return EXIT_SUCCESS;
        }
    }
    
    if ((flags & (1 << 0)) == 1) {
        startMonitor();
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
    /*
    unsigned long thread_id = 0;
    rc = pthread_create(&thread_id, NULL, worker, (void*)"thread test");

    pthread_join(thread_id, NULL);
    */
    return rc;
}

