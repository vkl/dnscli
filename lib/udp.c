#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "dns.h"
#include "udp.h"

int 
sendMulticastDNS(const char *multicast_addr, const int port, uint8_t *buffer, uint16_t buflen) 
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // Listen on any interface
    local_addr.sin_port = htons(5353);  // Bind to source port 5353

    if (bind(fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind error");
        close(fd);
        return -1;
    }

    int optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(optval)) < 0) {
        perror("setsockopt reuseaddr");
        close(fd);
        return -1;
    }

    struct sockaddr_in multicast_addr_in;
    memset(&multicast_addr_in, 0, sizeof(multicast_addr_in));
    multicast_addr_in.sin_family = AF_INET;
    multicast_addr_in.sin_addr.s_addr = inet_addr(multicast_addr);
    multicast_addr_in.sin_port = htons(port);

    int rc = sendto(fd, buffer, buflen, 0, (struct sockaddr*)&multicast_addr_in, sizeof(multicast_addr_in));
    if (rc == -1) {
        perror("sendto error");
        close(fd);
        return -1;
    }

    close(fd);  // Close the socket after sending
    return 1;   // Success
}

int 
sendMsg(const char *srv, const int port, uint8_t *msg, uint16_t msgLen) 
{
    int rc = -1;
    int timeout = 50;
    ssize_t n = 0;
    struct sockaddr_in sin;
    uint8_t buf[BUF_SZ] = {0};

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd == -1) {
        perror("socket");
        goto out;
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(srv);
    sin.sin_port = htons(port);

    if (sin.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "invalid remote IP %s\n", srv);
        goto out;
    }
    
    if (connect(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
        perror("connect error");
        goto out;
    }
    printf("Sending %d bytes to %s:%d\n", msgLen, srv, port);    
    DEBUG_DUMP(msg, msgLen);
    if ( (rc = write(fd, msg, msgLen)) != msgLen) {
        perror("write error");
        goto out;
    }

    do {
        n = recv(fd, buf, BUF_SZ, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(100000);
                timeout--;
                if (timeout <= 0) {
                    fprintf(stderr, "Could not get response from %s by timeout\n", srv);
                }
            } else {
                perror("recv");
                break;
            }
        } else {
            printf("\n\rReceived %zd bytes from %s\n\r", n, srv);
            DEBUG_DUMP(buf, n);
            printRawDnsPacket(buf, n, NULL, (struct sockaddr*)&sin);
            break;
        }
    } while (timeout > 0);

    rc = 0;

out:
    return rc;
}

