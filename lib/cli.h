#ifndef _CLI_H
#define _CLI_H

#include <curses.h>
#include <stdint.h>

// #include "dns.h"

void *interactive(void *arg);
int printToWindow(const char *msg, int lines, uint8_t *rawPacket, size_t len);
int printToMessageBox(const char *format, ...);
void updateBottomStatus(int r, int q, int ru);
// void printDnsPacket(DNSPacket *dnsPacket, printTerminal printTerminal);

#endif

