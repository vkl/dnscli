#ifndef _MDNS_H
#define _MDNS_H

#include <stdint.h>

#include "udp.h"

#define MDNS_PORT 5353
#define MDNS_GROUP "224.0.0.251"

enum monitorType {
    ALL,
    QUERY,
    REQUEST
};

void startMonitor(parseMsg __parseFunc, enum monitorType monType);

#endif

