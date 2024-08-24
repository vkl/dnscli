#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "dns.h"
#include "mdns.h"

#define MDNS_PORT 5353
#define MDNS_GROUP "224.0.0.251"

void *monitor(void *arg) {

    uint8_t flags = *((uint8_t*)arg);
    
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        return NULL;
    }
    
    struct sockaddr_in local_addr, sender_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Bind to all interfaces
    local_addr.sin_port = htons(MDNS_PORT);

    // Bind the socket to the local address and port
    if (bind(fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("Bind failed");
        close(fd);
        return NULL;
    }

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_GROUP);
    mreq.imr_interface.s_addr = INADDR_ANY;
    
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0) {
        perror("setsockopt failed");
        return NULL;
    }
    
    uint8_t *buf = calloc(1, 1024);
    ssize_t n = 0;
    do {
        n = recv(fd, buf, 1024, 0);
        /*
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("waiting for data...\n");
                sleep(3);
            } else {
                perror("recv");
            }
        } else {
            printf("Received %ld\n", n);
        }*/
        if (n < 0) {
            perror("recv");
            break;
        }
        if (arg != NULL) {
            //printf("Received %ld bytes\n", n);
            //parseMsg parseDnsResponse = (parseMsg)arg;
            DNSPacket *dnsPacket = createDNSPacket();
            if (parseDnsPacket(dnsPacket, buf, n) < 0) {
                fprintf(stderr, "error parse DNS packet\n");
                DEBUG_DUMP(buf, n);
            } else {
                if (flags == 0x3) {
                    printDnsPacket(dnsPacket);
               } else if (flags == 0x5 && IS_QUERY(dnsPacket->header.flags)) {
                    printDnsPacket(dnsPacket);   
                } else if (flags == 0x9 && !IS_QUERY(dnsPacket->header.flags)) {
                    printDnsPacket(dnsPacket); 
                }
            }
            freeDNSPacket(&dnsPacket);
            //parseDnsResponse(buf, n);
            //break;
        }
        //printf("Received: %ld bytes\n", n);
    } while (1);

    free(buf);

    return NULL;
}

void startMonitor(parseMsg __parseFunc, uint8_t flags) {
    int rc;
    pthread_t thread_id = 0;
    rc = pthread_create(&thread_id, NULL, monitor, (void*)&flags);
    pthread_join(thread_id, NULL);
}

