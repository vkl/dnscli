#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <pthread.h> 
#include <unistd.h>
#include <termios.h>
#include <string.h>

#include "cli.h"
//#include "mdns.h"
#include "dns.h"

extern int efd;

uint8_t requestbuf[512];

void *
interactive(void *arg)
{
    uint64_t signal = 0;
    uint16_t buflen = 0;
    uint16_t i = 0;
    uint8_t start = 0;
    DNSPacket *dnsPacket;
    
    //struct termios old_termios_p;
    //struct termios new_termios_p;

    //cfmakeraw(&new_termios_p); 
    //tcgetattr(0, &old_termios_p);
    //tcsetattr(0, TCSANOW, &new_termios_p);

    struct termios old_termios_p;
    struct termios new_termios_p;

    tcgetattr(STDIN_FILENO, &old_termios_p);
    new_termios_p = old_termios_p;
    cfmakeraw(&new_termios_p);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_termios_p);
    //printf("\e[?25l"); // hide cursor

    char key;

    for (;;) {
        if (read (0, &key, 1) != 1)
        {
            fprintf (stderr, "read() failed\n");
            goto done;
        }
        if (start == 0) {
            switch (key) {
                case 'q': // quit
                    goto done;
                    break;
                case 'r': // send request
                    i = 0;
                    start = 1;
                    memset(requestbuf, 0, 512);
                    printf("Request: ");
                    fflush(stdout);
                    break;
                default:
                    break;
            }
            continue;
        }
        
        if (key == '\r') {
            requestbuf[i] = '\0';
            printf("\n\r");
            fflush(stdout);
            //printf("Buf: %s\n\r", buf);
            signal = 'r';
            write(efd, &signal, sizeof(signal));
            start = 0;
            continue;
        }

        if (i < sizeof(requestbuf) - 1) {
            requestbuf[i++] = key;
        } else {
            fprintf(stderr, "\nInput too long\n\r");
            i = 0;
            memset(requestbuf, 0, sizeof(requestbuf));
            start = 0;
        }
        putchar(key);
        fflush(stdout);
    }

done:
    signal = (uint64_t)key;
    write(efd, &signal, sizeof(signal));

    // restore terminal
    printf("\e[?25h");
    tcsetattr(0, TCSANOW, &old_termios_p);

    return NULL;
}

