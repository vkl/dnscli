#ifndef _DNS_H
#define _DNS_H

#include <stdint.h>

#define HEADER_SZ 12
#define MAX_LABEL 63
#define MAX_DOMAIN_NAME 255
#define MAX_IPV4_ADDR 16

// DNS Header structure
typedef struct {
    uint16_t transactionID;    // Transaction ID
    uint16_t flags;            // Flags and Code
    uint16_t questionCount;    // Number of Questions
    uint16_t answerCount;      // Number of Answer RRs
    uint16_t authorityCount;   // Number of Authority RRs
    uint16_t additionalCount;  // Number of Additional RRs
} __attribute__((packed)) DNSHeader;

// DNS Question structure
typedef struct {
    char *name;                // Domain name (not typically fixed size, might need to use a dynamic array)
    uint16_t type;             // Type of query
    uint16_t class;            // Class of query
} DNSQuestion;

// DNS Resource Record (RR) structure
typedef struct {
    char *name;                // Domain name (not typically fixed size)
    uint16_t type;             // Type of record
    uint16_t class;            // Class of record
    uint32_t ttl;              // Time to Live
    uint16_t dataLength;       // Length of RDATA
    char *data;                // RDATA (variable length)
} __attribute__((packed)) DNSResourceRecord;

// DNS Packet structure
typedef struct {
    DNSHeader header;          // DNS Header
    DNSQuestion *questions;    // Array of DNS Questions
    DNSResourceRecord *answers; // Array of DNS Answers
    DNSResourceRecord *authorities; // Array of DNS Authorities
    DNSResourceRecord *additionals; // Array of DNS Additional Records
} DNSPacket;

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
    TXT = 16,    // text strings
    AAAA = 28,   // a ipv6 host address
    SRV = 33,    // server selection
    ANY = 255    // any  
} DNSType;

typedef enum DNSClass {
    IN = 1,     // the Internet
    CS = 2,     // the CSNET class (Obsolete)
    CH = 3,     // the CHAOS class
    HS = 4      // Hesiod [Dyer 87]
} DNSClass;

#define DNS_TYPE_TO_STRING(type) \
    ((type) == A ? "A" : \
    (type) == NS ? "NS" : \
    (type) == MD ? "MD" : \
    (type) == MF ? "MF" : \
    (type) == CNAME ? "CNAME" : \
    (type) == SOA ? "SOA" : \
    (type) == PTR ? "PTR" : \
    (type) == HINFO ? "HINFO" : \
    (type) == MINFO ? "MINFO" : \
    (type) == MX ? "MX" : \
    (type) == TXT ? "TXT" : \
    (type) == AAAA ? "AAAA" : \
    (type) == SRV ? "SRV" : \
    (type) == ANY ? "ANY" : "UNKNOWN")

#define DNS_CLASS_TO_STRING(class) \
    (((class) & 0x7FFF) == 0x0001 ? "IN" : \
    ((class) & 0x7FFF) == 0x0002 ? "CS" : \
    ((class) & 0x7FFF) == 0x0003 ? "CH" : \
    ((class) & 0x7FFF) == 0x0004 ? "HS" : "UNKNOWN")

#define IS_QUERY(flags) (!((flags) & (1 << 15)))

#define DEBUG_DUMP(buf,n)                \
do {                                     \
    int cnt = 0;                         \
    for (int i=0; i<(n); i++) {          \
        printf("%02x ",                  \
                (unsigned char)(buf)[i]);\
        cnt++;                           \
        if (cnt % 8 == 0) printf(" ");   \
        if (cnt % 16 == 0) printf("\n"); \
    }                                    \
    if (cnt % 16 != 0) printf("\n");     \
} while(0)

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
        case PTR:                        \
            printf("type PTR,  ");       \
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
            printf("Class IN");          \
            break;                       \
        default:                         \
            printf("Class unknown");     \
            break;                       \
    }                                    \
} while(0)

DNSPacket *createDNSPacket();
void freeDNSPacket(DNSPacket **dnsPacket);

void buildDnsQuery(void *arg, char *buffer, int *buflen);
int parseDnsResponse(char *buf, int buflen);
void parseAddr(char *buffer, int *pos);
int parseIPv4Addr(char *buffer, uint16_t *pos, char *name);
int parseSRVRR(char *buffer, uint16_t *pos, char *name);
void parseAnswer(char *buffer, int *pos);
void parseQuery(char *buffer, int *pos);
void parseName(char *buffer, int *pos, const char *prefix);
int parseDnsPacket(DNSPacket *dnsPacket, char *buf, int n);
void parseDNSPacketReplyFields(DNSPacket *dnsPacket, char *buf, uint16_t *pos);

int parseDNSPacketQueries(DNSQuestion *dnsQuestions,
        uint16_t cnt, char *buf, uint16_t *pos);

int parseDNSPacketResourceRecords(DNSResourceRecord *dnsResourceRecords,
        uint16_t cnt, char *buf, uint16_t *pos);

void printDnsPacket(DNSPacket *dnsPacket);

#endif
