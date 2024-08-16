#ifndef _UDP_H
#define _UDP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUF_SZ 1024

typedef void (*buildMsg) (void *arg, char *buf, int *size);
typedef int (*parseMsg) (char *buf, int size);

int sendMsg(const char *srv, const int port,
        buildMsg __func, void *arg, parseMsg __parseFunc);

#endif
