#ifndef _MDNS_H
#define _MDNS_H

#include <stdint.h>

#include "udp.h"

#define MDNS_PORT 5353
#define MDNS_GROUP "224.0.0.251"

void startMonitor(parseMsg __parseFunc, uint8_t flags);

#endif

