#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "dns.h"

#define BUF_SZ 1024

void usage(const char *progname) {
    fprintf(stderr, "Usage: %s <domain_name> <dns_server>\n", progname);
    fprintf(stderr, "Example: %s www.example.com 8.8.8.8\n", progname);
}

int main(int argc, char *argv[]) {

    if (argc < 3) {
        fprintf(stderr, "too few arguments\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    const char *name = argv[1];
    const char *dns = argv[2];
    const int port = 53;

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(dns);
    sin.sin_port = htons(port);

    if (sin.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "invalid remote IP %s\n", dns);
        return EXIT_FAILURE;
    }
    
    if (connect(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
        perror("connect error");
        return EXIT_FAILURE;
    }
    
    int buflen = 0;
    char *buf = calloc(1, BUF_SZ);
    buildDnsQuery(name, buf, &buflen);
    int rc;
    if ( (rc = write(fd, buf, buflen)) != buflen) {
        perror("write error");
        free(buf);
        return EXIT_FAILURE;
    }
    int timeout = 50; // 50 * 100_000 = 5 sec
    memset(buf, 0, BUF_SZ);
    do {
        ssize_t n = recv(fd, buf, BUF_SZ, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(100000);
                timeout--;
                if (timeout <= 0) fprintf(stderr, "Could not get response from %s by timeout\n", dns);
            } else {
                perror("recv");
                break;
            }
        } else {
            parseDnsResponse(buf, n);
            break;
        }
    } while (timeout > 0);
    free(buf);
    return EXIT_SUCCESS;
}

