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

void *
interactive(void *arg)
{
    uint64_t signal = 0;
    uint16_t buflen = 0;
    uint8_t buf[512] = {0};
    DNSPacket *dnsPacket;
    
    struct termios old_termios_p;
    struct termios new_termios_p;

    cfmakeraw(&new_termios_p); 
    tcgetattr(0, &old_termios_p);
    tcsetattr(0, TCSANOW, &new_termios_p);
    printf("\e[?25l"); // hide cursor

    char key;

    for (;;) {
        if (read (0, &key, 1) != 1)
        {
            fprintf (stderr, "read() failed\n");
            goto done;
        }
        signal = (uint64_t)key;
        write(efd, &signal, sizeof(signal));
        switch (key) {
            case 'q': // quit
                goto done;
                break;
            case 'r': // send request
                break;
        }
    }

done:
    // restore terminal
    printf("\e[?25h");
    tcsetattr(0, TCSANOW, &old_termios_p);

    return NULL;
}

