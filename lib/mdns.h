#ifndef _MDNS_H
#define _MDNS_H

#include <stdint.h>

#include "udp.h"

void startMonitor(parseMsg __parseFunc, uint8_t flags);

#endif

