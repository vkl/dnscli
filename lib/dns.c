#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "dns.h"

void buildDnsQuery(void *arg, char *buffer, int *buflen) {
    char *name = (char*)arg;
    char *query;
    char header[HEADER_SZ] = {0};
    
    header[0] = 0xAA;      // Transaction ID
    header[1] = 0xBB;
    
    // flags
    header[2] |= (1 << 0); // Query
    header[3] = 0;
    
    header[4] = 0;         // Number of questions
    header[5] = 1;

    memcpy(buffer, header, HEADER_SZ);
    
    // Question section
    char buf[MAX_DOMAIN_NAME] = {0};
    strcpy(buf, name);

    char *token = strtok(buf, ".");
    int i = HEADER_SZ;
    
    while(token) {
        int len = strlen(token);
        buffer[i] = (char)len;
        i++;
        memcpy(&buffer[i], token, len);
        i += len;
        token = strtok(NULL, ".");
    }

    // End of question section
    buffer[i] = 0; i++; // Terminaton of QNAME
    buffer[i] = 0; i++; // QTYPE
    buffer[i] = 1; i++;
    buffer[i] = 0; i++; // QCLASS
    buffer[i] = 1;

    *buflen = i + 1;
}

DNSPacket *createDNSPacket() {
    DNSPacket (*dnsPacket) = calloc(1, sizeof(DNSPacket));
    return dnsPacket;
}

void freeDNSPacket(DNSPacket *(*dnsPacket)) {
    if ((*dnsPacket) == NULL)
        return;
    for (uint16_t i=0; i < (*dnsPacket)->header.questionCount; i++) {
        free((*dnsPacket)->questions[i].name);
    }
    free((*dnsPacket)->questions);
    for (uint16_t i=0; i < (*dnsPacket)->header.answerCount; i++) {
        free((*dnsPacket)->answers[i].name);
        free((*dnsPacket)->answers[i].data);
    }
    free((*dnsPacket)->answers);
    for (uint16_t i=0; i < (*dnsPacket)->header.authorityCount; i++) {
        free((*dnsPacket)->authorities[i].name);
        free((*dnsPacket)->authorities[i].data);
    }
    free((*dnsPacket)->authorities);
    for (uint16_t i=0; i < (*dnsPacket)->header.additionalCount; i++) {
        free((*dnsPacket)->additionals[i].name);
        free((*dnsPacket)->additionals[i].data);
    }
    free((*dnsPacket)->additionals);
    free((*dnsPacket));
    *dnsPacket = NULL;
}

int parseSRVRR(char *buf, uint16_t *pos, char *name) {

    return 1;
}

int parseDNSName(char *buf, uint16_t *pos, char *name) {
    int j = 0;
    int label_len = 0;
    int tmp_pos = *pos;  // Temporary position to track compressed names
    int tmp = 0;         // Store the original position when following a compression pointer

    while (buf[tmp_pos] != 0) {
        if ((buf[tmp_pos] & 0xC0) == 0xC0) {
            if (tmp == 0) {
                tmp = tmp_pos + 2;  // Save the current position to return after the compressed label
            }
            tmp_pos = ((buf[tmp_pos] & 0x3F) << 8) | buf[tmp_pos + 1];
        } else {
            label_len = buf[tmp_pos];
            tmp_pos++;

            memcpy(&name[j], &buf[tmp_pos], label_len);
            j += label_len;
            name[j++] = '.';
            
            tmp_pos += label_len;
        }
    }
    name[j - 1] = '\0';  // Replace the last '.' with a null terminator
    *pos = tmp > 0 ? tmp : tmp_pos + 1;  // Restore position after name parsing
    return 1;
}

void printDnsPacket(DNSPacket *dnsPacket) {
    if (dnsPacket == NULL)
        return;
    IS_QUERY(dnsPacket->header.flags) ? printf("Query\n") : printf("Reply\n");
    printf("Qst: %d, Ans: %d, AuthCnt: %d, AddCnt: %d\n",
            dnsPacket->header.questionCount,
            dnsPacket->header.answerCount, 
            dnsPacket->header.authorityCount,
            dnsPacket->header.additionalCount);
    for (uint16_t i = 0; i < dnsPacket->header.questionCount; i++) {
        printf("%s: type %s, class %s\n",
                dnsPacket->questions[i].name,
                DNS_TYPE_TO_STRING(dnsPacket->questions[i].type),
                DNS_CLASS_TO_STRING(dnsPacket->questions[i].class));
    }
    for (uint16_t i = 0; i < dnsPacket->header.answerCount; i++) {
        printf("%s: type %s, class %s, %s\n",
                dnsPacket->answers[i].name,
                DNS_TYPE_TO_STRING(dnsPacket->answers[i].type),
                DNS_CLASS_TO_STRING(dnsPacket->answers[i].class),
                dnsPacket->answers[i].data);
    }
    for (uint16_t i = 0; i < dnsPacket->header.authorityCount; i++) {
        printf("%s: type %s, class %s, %s\n",
                dnsPacket->authorities[i].name,
                DNS_TYPE_TO_STRING(dnsPacket->authorities[i].type),
                DNS_CLASS_TO_STRING(dnsPacket->authorities[i].class),
                dnsPacket->authorities[i].data);
    }
    for (uint16_t i = 0; i < dnsPacket->header.additionalCount; i++) {
        printf("%s: type %s, class %s, %s\n",
                dnsPacket->additionals[i].name,
                DNS_TYPE_TO_STRING(dnsPacket->additionals[i].type),
                DNS_CLASS_TO_STRING(dnsPacket->additionals[i].class),
                dnsPacket->additionals[i].data);
    }

}

int parseDnsPacket(DNSPacket *dnsPacket, char *buf, int buflen) {
    
    uint16_t pos = 0;
    
    memcpy(&dnsPacket->header, buf, HEADER_SZ);
    dnsPacket->header.transactionID = ntohs(dnsPacket->header.transactionID);
    dnsPacket->header.flags = ntohs(dnsPacket->header.flags);
    dnsPacket->header.questionCount = ntohs(dnsPacket->header.questionCount);
    dnsPacket->header.answerCount = ntohs(dnsPacket->header.answerCount);
    dnsPacket->header.authorityCount = ntohs(dnsPacket->header.authorityCount);
    dnsPacket->header.additionalCount = ntohs(dnsPacket->header.additionalCount);

    pos += HEADER_SZ;

    dnsPacket->questions = calloc(dnsPacket->header.questionCount, sizeof(DNSQuestion));
    if (!dnsPacket->questions) {
        return -1;
    }
    if (parseDNSPacketQueries(dnsPacket->questions, 
            dnsPacket->header.questionCount, buf, &pos) < 0) return -1;
        
    dnsPacket->answers = calloc(dnsPacket->header.answerCount, sizeof(DNSResourceRecord));
    if (!dnsPacket->answers) {
        return -1;
    }
    if (parseDNSPacketResourceRecords(dnsPacket->answers,
            dnsPacket->header.answerCount, buf, &pos) < 0) return -1;

    dnsPacket->authorities = calloc(dnsPacket->header.authorityCount, sizeof(DNSResourceRecord));
    if (!dnsPacket->authorities) {
        return -1;
    }
    if (parseDNSPacketResourceRecords(dnsPacket->authorities,
            dnsPacket->header.authorityCount, buf, &pos) < 0) return -1;

    dnsPacket->additionals = calloc(dnsPacket->header.additionalCount, sizeof(DNSResourceRecord));
    if (!dnsPacket->additionals) {
        return -1;
    }
    if (parseDNSPacketResourceRecords(dnsPacket->additionals,
            dnsPacket->header.additionalCount, buf, &pos) < 0) return -1;

    return 1;
}

int parseDNSPacketResourceRecords(DNSResourceRecord *dnsResourceRecords,
        uint16_t cnt, char *buf, uint16_t *pos) {

    char name[MAX_DOMAIN_NAME]; 

    for (uint16_t i = 0; i < cnt; i++) {

        DNSResourceRecord *dnsResourceRecord = &dnsResourceRecords[i];
        
        memset(name, 0, MAX_DOMAIN_NAME);
        if (!parseDNSName(buf, pos, name)) {
            return -1;
        }
        dnsResourceRecord->name = strdup(name);
        if (!dnsResourceRecord->name) {
            fprintf(stderr, "query name error\n");
            return -1;
        }

        memcpy(&dnsResourceRecord->type, &buf[(*pos)], sizeof(uint16_t));
        dnsResourceRecord->type = ntohs(dnsResourceRecord->type);
        (*pos) += sizeof(uint16_t);

        memcpy(&dnsResourceRecord->class, &buf[(*pos)], sizeof(uint16_t));
        dnsResourceRecord->class = ntohs(dnsResourceRecord->class);
        (*pos) += sizeof(dnsResourceRecord->class);

        memcpy(&dnsResourceRecord->ttl, &buf[(*pos)], sizeof(uint32_t));
        dnsResourceRecord->ttl = ntohl(dnsResourceRecord->ttl);
        (*pos) += sizeof(uint32_t);

        memcpy(&dnsResourceRecord->dataLength, &buf[(*pos)], sizeof(uint16_t));
        dnsResourceRecord->dataLength = ntohs(dnsResourceRecord->dataLength);
        (*pos) += sizeof(uint16_t);

        if (dnsResourceRecord->type == 0 || dnsResourceRecords->class == 0 || 
                dnsResourceRecord->ttl == 0 || dnsResourceRecords->dataLength == 0) {
            fprintf(stderr, "attrs error\n");
            return -1;
        }    
        switch (dnsResourceRecord->type) {
            case SRV:
                //dnsResourceRecord->data = calloc(dnsResourceRecord->dataLength, 1);
                //if (!dnsResourceRecord->data) {
                //    return -1;
                //}
                //if (!parseSRVRR(buf, pos, dnsResourceRecord->data)) {
                //    return -1;
                //}
                (*pos) += dnsResourceRecord->dataLength;
                break;
            case PTR:
            case CNAME:
                memset(name, 0, MAX_DOMAIN_NAME);
                if (!parseDNSName(buf, pos, name)) {
                    fprintf(stderr, "CNME, PTR error\n");
                    return -1;
                }
                dnsResourceRecord->data = strdup(name);
                if (!dnsResourceRecord->data) {
                    return -1;
                }
                break;
            case A:
                memset(name, 0, MAX_DOMAIN_NAME);
                if (!parseIPv4Addr(buf, pos, name)) {
                    fprintf(stderr, "IPv4 error\n");
                    return -1;
                }
                dnsResourceRecord->data = strdup(name);
                if (!dnsResourceRecord->data) {
                    return -1;
                }
                break;
            //case AAAA:
            //case TXT:
            default:
                (*pos) += dnsResourceRecord->dataLength;
                break;
        }
    }

    return 1;
}

int parseDNSPacketQueries(DNSQuestion *dnsQuestions, uint16_t cnt,
        char *buf, uint16_t *pos) {

    char name[MAX_DOMAIN_NAME]; 
    for (uint16_t i = 0; i < cnt; i++) {

        DNSQuestion *dnsQuestion = &dnsQuestions[i];
        
        memset(name, 0, MAX_DOMAIN_NAME);
        if (!parseDNSName(buf, pos, name)) {
            return -1;
        }

        dnsQuestion->name = strdup(name);
        if (!dnsQuestion->name) {
            return -1;
        }

        memcpy(&dnsQuestion->type, &buf[(*pos)], sizeof(uint16_t));
        dnsQuestion->type = ntohs(dnsQuestion->type);
        (*pos) += sizeof(uint16_t);

        memcpy(&dnsQuestion->class, &buf[(*pos)], sizeof(uint16_t));
        dnsQuestion->class = ntohs(dnsQuestion->class);
        (*pos) += sizeof(dnsQuestion->class);    
    }

    return 1;
}

int parseDnsResponse(char *buf, int buflen) {
    printf("received %d\n", buflen);
    DNSPacket *dnsPacket = createDNSPacket();
    if (parseDnsPacket(dnsPacket, buf, buflen) < 0)
        return -1;
    printDnsPacket(dnsPacket);
    freeDNSPacket(&dnsPacket);
    return 0;
}

int parseIPv4Addr(char *buffer, uint16_t *pos, char *name) {
    int k = 0;                            
    for (int j=0; j<4; j++) {             
        k += sprintf(&name[k], "%d.", (unsigned char)buffer[*pos]);
        (*pos)++;                          
    }                                
    name[k-1] = 0;
    return 1;
}

void parseAddr(char *buffer, int *pos) {
    char ipv4addr[MAX_IPV4_ADDR] = {0};
    int k = 0;                            
    for (int j=0; j<4; j++) {             
        k += sprintf(&ipv4addr[k], "%d.", (unsigned char)buffer[*pos]);
        (*pos)++;                          
    }                                
    (ipv4addr)[k-1] = 0;
    printf("addr: %s ", ipv4addr);
}

void parseAnswer(char *buffer, int *pos) {
    parseName(buffer, pos, "");
    int type = (buffer[(*pos)] << 8) | buffer[(*pos)+1];
    DNS_TYPE(type);
    DNS_CLASS((buffer[(*pos)+2] << 8) | buffer[(*pos+3)]);
    (*pos) += 4;
    // Time to Live
    int ttl = 0;
    ttl = (buffer[(*pos)] << 24) | (buffer[(*pos) + 1] << 16) \
          | (buffer[(*pos) + 2] << 8) | buffer[(*pos) + 3];
    (*pos) += 4;
    printf(", TTL %d, ", ttl > 0 ? ttl : 0);
    // Data length
    unsigned char dataLen = 0;
    dataLen = (buffer[(*pos)] << 8) | buffer[(*pos) + 1];
    (*pos) += 2;
    printf("Data length %d, ", dataLen);
    switch (type) {
        case CNAME:
            parseName(buffer, pos, "cname: ");
            break;
        case A:
            parseAddr(buffer, pos);
            break;
    }
}

void parseQuery(char *buffer, int *pos) {
    parseName(buffer, pos, "");
    DNS_TYPE((buffer[(*pos)] << 8) | buffer[(*pos)+1]);
    DNS_CLASS((buffer[(*pos)+2] << 8) | buffer[(*pos+3)]);
    (*pos) += 4;
}

void parseName(char *buffer, int *pos, const char *prefix) {
    int j = 0;
    int label_len = 0;
    int tmp_pos = *pos;  // Temporary position to track compressed names
    int tmp = 0;         // Store the original position when following a compression pointer
    char name[MAX_DOMAIN_NAME] = {0};

    while (buffer[tmp_pos] != 0) {
        // Check for compression pointer (two most significant bits set)
        if ((buffer[tmp_pos] & 0xC0) == 0xC0) {
            if (tmp == 0) {
                tmp = tmp_pos + 2;  // Save the current position to return after the compressed label
            }
            tmp_pos = ((buffer[tmp_pos] & 0x3F) << 8) | buffer[tmp_pos + 1];
        } else {
            label_len = buffer[tmp_pos];
            tmp_pos++;

            memcpy(&name[j], &buffer[tmp_pos], label_len);
            j += label_len;
            name[j++] = '.';
            
            tmp_pos += label_len;
        }
    }
    name[j - 1] = 0;  // Replace the last '.' with a null terminator
    *pos = tmp > 0 ? tmp : tmp_pos + 1;  // Restore position after name parsing
    printf("%s%s ", prefix, name);
}

