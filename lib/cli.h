#ifndef _CLI_H
#define _CLI_H

#include <curses.h>

// #include "dns.h"

void *interactive(void *arg);
int printToWindow(const char *msg);
int printToMessageBox(const char *format, ...);
// void printDnsPacket(DNSPacket *dnsPacket, printTerminal printTerminal);

#endif

