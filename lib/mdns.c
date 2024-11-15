#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "dns.h"
#include "mdns.h"
#include "cli.h"

int efd;

static void *
monitor(void *arg) 
{
    enum monitorType monType = *((enum monitorType*)arg);
    DNSPacket *dnsPacket;
    uint8_t sendbuf[512] = {0};
    uint16_t buflen = 0;
    
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd == -1) {
        perror("socket");
        return NULL;
    }
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(MDNS_PORT);  // Server's port
    server_addr.sin_addr.s_addr = inet_addr(MDNS_GROUP);

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
    struct pollfd fds[2];
    struct sockaddr_in src_addr;
    char src_ip[INET_ADDRSTRLEN];
    socklen_t addr_len = sizeof(src_addr);

    fds[0].fd = fd;
    fds[0].events = POLLIN;

    fds[1].fd = efd;
    fds[1].events = POLLIN;
    
    for (;;) {
        int ret = poll(fds, 2, 5000);
        if (ret == -1) {
            perror("poll");
            return NULL;
        } else if (ret == 0) {
            //printf("Timeout occurred! No events.\n\r");
            continue;
        }
        // read data
        if (fds[0].revents & POLLIN) {
            n = recvfrom(fd, buf, 1024, 0, (struct sockaddr*)&src_addr, &addr_len);
            if (n > 0) {
                inet_ntop(AF_INET, &src_addr.sin_addr, src_ip, sizeof(src_ip));
                printf("Received %zd bytes from %s:%d\n\r", n, src_ip, ntohs(src_addr.sin_port));
                DNSPacket *dnsPacket = createDNSPacket();
                if (parseDnsPacket(dnsPacket, buf, n) < 0) {
                    fprintf(stderr, "error parse DNS packet\n\r");
                    DEBUG_DUMP(buf, n);
                } else {
#ifdef DEBUG_DUMP
                    DEBUG_DUMP(buf, n);
#endif
                    if (monType == ALL) {
                        printDnsPacket(dnsPacket);
                    } else if (monType == QUERY && IS_QUERY(dnsPacket->header.flags)) {
                        printDnsPacket(dnsPacket);   
                    } else if (monType == REQUEST && !IS_QUERY(dnsPacket->header.flags)) {
                        printDnsPacket(dnsPacket); 
                    }
                }
                freeDNSPacket(&dnsPacket);
            }    
        }
        // write data
        if (fds[0].revents & POLLOUT) {
            //printf("sending packet.....\n\r");
            dnsPacket = calloc(1, sizeof(DNSPacket));
            dnsPacket->header.questionCount = 1;
            dnsPacket->header.transactionID = 0x0000;
            dnsPacket->questions = calloc(1, sizeof(DNSQuestion));
            dnsPacket->questions[0].type = PTR;
            dnsPacket->questions[0].class = IN;
            dnsPacket->questions[0].name = strdup("_googlecast._tcp.local");
            buildDNSPacket(dnsPacket, sendbuf, &buflen);

            if (sendto(fd, sendbuf, buflen, 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
                perror("sendto failed\n\r");
            }
            freeDNSPacket(&dnsPacket);
            fds[0].events &= ~POLLOUT;
        }
        // signal from user
        if (fds[1].revents & POLLIN) {
            uint64_t signal = 0;
            read(efd, &signal, sizeof(signal));
            switch (signal) {
                case (char)'q':
                    goto done;
                    break;
                case (char)'r':
                    fds[0].events |= POLLOUT;
                    break;
            } 
        }
    }

done:
    close(fd);
    free(buf);
    return NULL;
}

void 
startMonitor(parseMsg __parseFunc, enum monitorType monType) 
{
    int rc;
    
    efd = eventfd(0, 0);
    if (efd == -1) {
        perror("eventfd");
        return;
    }
    
    pthread_t monitor_id = 0;
    pthread_t interactive_id = 0; 
    pthread_create(&monitor_id, NULL, monitor, (void*)&monType);
    pthread_create(&interactive_id, NULL, interactive, NULL);

    pthread_join(monitor_id, NULL);
    pthread_join(interactive_id, NULL);
}

