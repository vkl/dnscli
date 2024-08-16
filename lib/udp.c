#include "udp.h"

int
sendMsg(const char *srv, const int port,
        buildMsg __buildFunc, void *arg, parseMsg __parseFunc) {

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd == -1) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(srv);
    sin.sin_port = htons(port);

    if (sin.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "invalid remote IP %s\n", srv);
        return -1;
    }
    
    if (connect(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
        perror("connect error");
        return -1;
    }
    
    int buflen = 0;
    char *buf = calloc(1, BUF_SZ);
    __buildFunc(arg, buf, &buflen);
    int rc;
    if ( (rc = write(fd, buf, buflen)) != buflen) {
        perror("write error");
        free(buf);
        return -1;
    }
    int timeout = 50; // 50 * 100_000 = 5 sec
    memset(buf, 0, BUF_SZ);
    do {
        ssize_t n = recv(fd, buf, BUF_SZ, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(100000);
                timeout--;
                if (timeout <= 0)
                    fprintf(stderr, "Could not get response from %s by timeout\n", srv);
            } else {
                perror("recv");
                break;
            }
        } else {
            rc = __parseFunc(buf, n);
            break;
        }
    } while (timeout > 0);
    free(buf);
    return rc;

}

