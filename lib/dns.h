#ifndef _DNS_H
#define _DNS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HEADER_SZ 12
#define MAX_LABEL 63
#define MAX_DOMAIN_NAME 255
#define MAX_IPV4_ADDR 16 

typedef enum DNSType {
    A = 1,      // a host address
    NS = 2,     //an authoritative name server
    MD = 3,     // a mail destination (Obsolete - use MX)
    MF = 4,     // a mail forwarder (Obsolete - use MX)
    CNAME = 5,  // the canonical name for an alias
    SOA = 6,    // marks the start of a zone of authority
    PTR = 12,   // a domain name pointer
    HINFO = 13, // host information
    MINFO = 14, // mailbox or mail list information
    MX = 15,    // mail exchange
    TXT = 16    // text strings
} DNSType;

typedef enum DNSClass {
    IN = 1,     // the Internet
    CS = 2,     // the CSNET class (Obsolete)
    CH = 3,     // the CHAOS class
    HS = 4      // Hesiod [Dyer 87]
} DNSClass;


#define DNS_TYPE(type)                   \
do {                                     \
    switch ((type)) {                    \
        case A:                          \
            printf("type A, ");          \
            break;                       \
        case NS:                         \
            printf("type NS, ");         \
            break;                       \
        case CNAME:                      \
            printf("type CNAME, ");      \
            break;                       \
        default:                         \
            printf("type Unknown, ");    \
            break;                       \
    }                                    \
} while(0)

#define DNS_CLASS(class)                 \
do {                                     \
    switch ((class)) {                   \
        case IN:                         \
            printf("Class IN");         \
            break;                       \
        default:                         \
            printf("Class unknown");    \
            break;                       \
    }                                    \
} while(0)

void buildDnsQuery(const char *name, char *buffer, int *buflen);
int parseDnsResponse(char *buf, int buflen);
void parseAddr(char *buffer, int *pos);
void parseAnswer(char *buffer, int *pos);
void parseQuery(char *buffer, int *pos);
void parseName(char *buffer, int *pos, const char *prefix);


#endif
