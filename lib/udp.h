#ifndef _UDP_H
#define _UDP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUF_SZ 1024

typedef void (*buildMsg) (void *arg, uint8_t *buf, int *size);
typedef int (*parseMsg) (uint8_t *buf, int size);

int sendMsg(const char *srv, const int port,
        uint8_t *msg, uint16_t msgLen, parseMsg __parseFunc);
int sendMulticastDNS(const char *multicast_addr, const int port, uint8_t *buffer, uint16_t buflen);

#endif
