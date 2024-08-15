#include "dns.h"

void buildDnsQuery(const char *name, char *buffer, int *buflen) {
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

int parseDnsResponse(char *buf, int buflen) {
    if (buflen < 12) {
        fprintf(stderr, "Buffer too small for a DNS header\n");
        return -1;
    }
    char flags = buf[2];
    if ( flags && (1<<8) == 0) {
        fprintf(stderr, "Not response\n");
        return -1;
    }
    int ansRR = (buf[6] << 8) | buf[7];
    int authRR = (buf[8] << 8) | buf[9];
    int addRR = (buf[10] << 8) | buf[11];

    int i = 12;
    int j = 0;
    int label_len = 0;

    // Query Section
    parseQuery(buf, &i);
    printf("\n");
    for (int answer = 0; answer < ansRR; answer++) {
        parseAnswer(buf, &i);
        printf("\n");
    }
    return 0;
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

