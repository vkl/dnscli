#ifndef _MDNS_H
#define _MDNS_H

#include <stdint.h>

#include "udp.h"

#define MDNS_PORT 5353
#define MDNS_GROUP "224.0.0.251"
#define PKT_SZ 2048

enum monitorType {
    ALL,
    QUERY,
    REQUEST
};

typedef struct {
    uint8_t data[PKT_SZ];
    size_t len;
} Packet;

void startMonitor(enum monitorType monType);

#endif

