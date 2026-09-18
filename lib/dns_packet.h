#ifndef _DNS_PACKET_H
#define _DNS_PACKET_H

#include <arpa/inet.h>
#include <stdint.h>

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

DNSPacket *createDNSPacket();
void freeDNSPacket(DNSPacket **dnsPacket);
void buildDNSPacket(DNSPacket *dnsPacket, uint8_t *buffer, uint16_t *buflen);
int parseIPv6Addr(uint8_t *buffer, uint16_t *pos, DNSResourceRecord *dnsResourceRecord);
int parseIPv4Addr(uint8_t *buffer, uint16_t *pos, DNSResourceRecord *dnsResourceRecord);
int parseOPTRR(uint8_t *buffer, uint16_t *pos, DNSResourceRecord *dnsResourceRecord);
int parseSRVRR(uint8_t *buffer, uint16_t *pos, DNSResourceRecord *dnsResourceRecord);
int parseTXTRR(uint8_t *buffer, uint16_t *pos, DNSResourceRecord *dnsResourceRecord);
int parseDnsPacket(DNSPacket *dnsPacket, uint8_t *buf, int n);
int parseDNSPacketQueries(DNSQuestion *dnsQuestions,
        uint16_t cnt, uint8_t *buf, uint16_t *pos);
int parseDNSPacketResourceRecords(DNSResourceRecord *dnsResourceRecords,
        uint16_t cnt, uint8_t *buf, uint16_t *pos);

#endif