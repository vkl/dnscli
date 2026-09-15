#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdatomic.h>
#include <stdbool.h>

#include "dns.h"
#include "mdns.h"
#include "cli.h"

int efd;

#define BUFF_SZ 1024
#define RING_SZ 1024
#define PKT_SZ 1024

extern uint8_t requestbuf[BUFF_SZ];

typedef struct {
    uint8_t data[PKT_SZ];
    size_t len;
} Packet;

typedef struct {
    Packet *items[RING_SZ];
    _Atomic size_t head;
    _Atomic size_t tail;
} Ring;

static int
init_ring(Ring *ring)
{
    int ret = -1;
    for (size_t i = 0; i < RING_SZ; i++) {
        ring->items[i] = malloc(sizeof(Packet));
        if (!ring->items[i]) {
            ret = -1;
            goto out;
        }
    }
    ring->head = 0;
    ring->tail = 0;
    ret = 0;

out:
    return ret;
}

static Packet*
ring_producer_slot(Ring *ring)
{
    size_t head = atomic_load_explicit(&ring->head,
            memory_order_relaxed);
    size_t next = (head + 1) % RING_SZ;
    size_t tail = atomic_load_explicit(
            &ring->tail, memory_order_acquire);
    if (next == tail)
        return NULL;       // full
    return ring->items[head];
}

static void
ring_produce(Ring *ring)
{
    size_t head = atomic_load_explicit(&ring->head,
                                       memory_order_relaxed);
    size_t next = (head + 1) % RING_SZ;
    atomic_store_explicit(&ring->head,
                          next,
                          memory_order_release);
}

static Packet*
ring_consumer_slot(Ring *ring)
{
    size_t tail = atomic_load_explicit(&ring->tail,
            memory_order_relaxed);
    size_t head = atomic_load_explicit(&ring->head,
            memory_order_acquire);
    if (tail == head)
        return NULL;       // empty
    return ring->items[tail];
}

static void
ring_consume(Ring *ring)
{
    size_t tail = atomic_load_explicit(&ring->tail,
            memory_order_relaxed);
    size_t next = (tail + 1) % RING_SZ;
    atomic_store_explicit(&ring->tail, next, memory_order_release);
}

static int
deinit_ring(Ring *ring)
{
    for (size_t i = 0; i < RING_SZ; i++) {
        free(ring->items[i]);
    }
    return 0;
}

static void *
monitor(void *arg) 
{
    enum monitorType monType = *((enum monitorType*)arg);
    uint8_t sendbuf[BUFF_SZ] = {0};
    uint8_t receivebuf[BUFF_SZ] = {0};
    uint16_t buflen = 0;
    DNSPacket *dnsPacketRequest;
    DNSPacket *dnsPacket = NULL;
    Packet *pkt = NULL;
    Packet *pktConsumer = NULL;
    // DNSPacket *dnsPacketResponse;
    struct ip_mreq mreq;
    struct sockaddr_in server_addr;
    struct sockaddr_in local_addr, sender_addr;
    ssize_t n = 0;
    struct pollfd fds[2];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    char src_ip[INET_ADDRSTRLEN];
    Ring ring;
    int *ret = malloc(sizeof(int));
    *ret = -1;

    if (init_ring(&ring) < 0) {
        fprintf(stderr, "Failed to initialize ring buffer\n");
        goto out;
    }

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd == -1) {
        perror("socket");
        goto out;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(MDNS_PORT);  // Server's port
    server_addr.sin_addr.s_addr = inet_addr(MDNS_GROUP);

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Bind to all interfaces
    local_addr.sin_port = htons(MDNS_PORT);

    // Bind the socket to the local address and port
    if (bind(fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("Bind failed");
        close(fd);
        goto out;
    }

    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_GROUP);
    mreq.imr_interface.s_addr = INADDR_ANY;
    
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0) {
        perror("setsockopt failed");
        goto out;
    }
    
    fds[0].fd = fd;
    fds[0].events = POLLIN;

    fds[1].fd = efd;
    fds[1].events = POLLIN;
    
    for (;;) {
        int ret = poll(fds, 2, 5000);
        if (ret == -1) {
            perror("poll");
            goto out;
        } else if (ret == 0) {
            continue;
        }

        // read data
        if (fds[0].revents & POLLIN) {
            pkt = ring_producer_slot(&ring);
            n = recvfrom(fd, pkt->data, sizeof(pkt->data), 0, (struct sockaddr*)&src_addr, &addr_len);
            if (n > 0) {
                pkt->len = n;
                ring_produce(&ring);
            }
            pktConsumer = ring_consumer_slot(&ring);
            ring_consume(&ring);
            printRawDnsPacket(pktConsumer->data, pktConsumer->len, printToWindow);
        }

        // write data
        if (fds[0].revents & POLLOUT) {
            dnsPacketRequest = createDNSPacket();
            dnsPacketRequest->header.questionCount = 1;
            dnsPacketRequest->header.transactionID = 0x0000;
            dnsPacketRequest->questions = calloc(1, sizeof(DNSQuestion));
            dnsPacketRequest->questions[0].type = PTR;
            dnsPacketRequest->questions[0].class = IN;
            dnsPacketRequest->questions[0].name = (char *)strdup((char *)requestbuf); //strdup("_googlecast._tcp.local");
            buildDNSPacket(dnsPacketRequest, sendbuf, &buflen);

            if (sendto(fd, sendbuf, buflen, 0, (struct sockaddr*)&server_addr,
                    sizeof(server_addr)) < 0) {
                perror("sendto failed\n\r");
            }
            freeDNSPacket(&dnsPacketRequest);
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
                case (char)'p':
                    if (fds[0].events & POLLIN) {
                        fds[0].events &= ~POLLIN;
                    } else {
                        fds[0].events |= POLLIN;
                    }
                    break;
                case (char)'c':
                    break;
                default:
                    fprintf(stderr, "Unknown signal\n\r");
                    break;
            }
        }
    }

done:
    close(fd);
    *ret = 0;

out:
    deinit_ring(&ring);
    return (void*)ret;
}

void 
startMonitor(enum monitorType monType)
{
    int rc;
    int status;
    int *ret = malloc(sizeof(int));
    
    efd = eventfd(0, 0);
    if (efd == -1) {
        perror("eventfd");
        return;
    }
    
    pthread_t monitor_id = 0;
    pthread_t interactive_id = 0; 
    pthread_create(&monitor_id, NULL, monitor, (void*)&monType);
    pthread_create(&interactive_id, NULL, interactive, NULL);

    pthread_join(monitor_id, (void*)&ret);

    if (ret != NULL) {
        status = *ret;
        free(ret);
    }

    if (status < 0) {
        fprintf(stderr, "monitor thread error\n\r");
        pthread_cancel(interactive_id);
    }
    pthread_join(interactive_id, (void*)&ret);
}
