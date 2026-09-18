#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>
#include <assert.h>

#include "dns.h"
#include "cli.h"

#define MSG_SZ 1024

typedef int (*outputFunc)(const char *, ...);

/* static variables */

/* static function prototypes */
static bool parseIPv4AddrS(uint8_t *buffer, uint16_t *pos, char *ipv4Str,
        int maxLen);
static bool parseIPv6AddrS(uint8_t *buffer, uint16_t *pos, char *ipv6Str,
        int maxLen);
static int parseSRV(uint8_t *buffer, uint16_t *pos, char *message,
        int *msgPos);
static void parseResourceRecords(uint8_t *buffer, uint16_t *pos,
        DNSType type, int dataLength, char *message, int *msgPos);
static int parseReplies(uint8_t *buffer, int buflen, uint16_t *pos, uint16_t count,
        char *message, int *msgPos, const char *label);
static void debug_dump(uint8_t *buf, int n, outputFunc output);
static inline void addToMsg(char *message, int *msgPos, const char *format, ...);

/*
[15:38:36] QUERY  Q=2 A=0 AUTH=0 ADD=0
  Q  PTR  IN  _rdlink._tcp.local
  Q  PTR  IN  _companion-link._tcp.local

[15:38:29] REPLY  Q=0 A=1 AUTH=0 ADD=3
  A  PTR  IN  TTL=120  _googlezone._tcp.local
  +  SRV  IN  TTL=120  48743c35-ea1a-bf8f-41ee-39096071fa7d._googlezone._tcp.local
  +  TXT  IN  TTL=4500  48743c35-ea1a-bf8f-41ee-39096071fa7d._googlezone._tcp.local
  +  PTR  IN  TTL=120  _googlezone._tcp.local
*/
int
printRawDnsPacket(uint8_t *buffer, int buflen, printTerminal printer,
        struct sockaddr *src_addr)
{
    int ret = 0;
    uint16_t transactionID = ntohs(*(uint16_t*)&buffer[0]);
    uint16_t flags = ntohs(*(uint16_t*)&buffer[2]);
    uint16_t questionCount = ntohs(*(uint16_t*)&buffer[4]);
    uint16_t answerCount = ntohs(*(uint16_t*)&buffer[6]);
    uint16_t authorityCount = ntohs(*(uint16_t*)&buffer[8]);
    uint16_t additionalCount = ntohs(*(uint16_t*)&buffer[10]);
    time_t now = time(NULL);
    struct tm local_time;
    char timestamp[20] = {0};
    char message[MSG_SZ] = {0};
    char name[MAX_DOMAIN_NAME] = {0};
    uint16_t pos = HEADER_SZ;
    uint16_t type, class, i;
    int msgPos = 0;

    printTerminal output = (printer != NULL) ? printer : puts;

    localtime_r(&now, &local_time);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &local_time);

    updateBottomStatus(!IS_QUERY(flags), IS_QUERY(flags), 0);

    /*
     * DNS Packet header
     */
    addToMsg(message, &msgPos,
            "[%s] %s  from %s:%d  Q=%d, A=%d, AUTH=%d, ADD=%d\n\r",
            timestamp,
            IS_QUERY(flags) ? "QUERY" : "REPLY",
            (src_addr != NULL) ? inet_ntoa(((struct sockaddr_in*)src_addr)->sin_addr) : "unknown",
            (src_addr != NULL) ? ntohs(((struct sockaddr_in*)src_addr)->sin_port) : 0,
            questionCount, answerCount, authorityCount, additionalCount);

    if (questionCount > 0) {
        for (i = 0; i < questionCount; i++) {
            name[0] = '\0';
            parseDNSName(buffer, &pos, name);
            type = ntohs(*(uint16_t*)&buffer[pos]);
            pos += 2;
            class = ntohs(*(uint16_t*)&buffer[pos]);
            pos += 2;
            /* Q  PTR  IN  _companion-link._tcp.local */
            addToMsg(message, &msgPos,
                    "  Q  %s%s  %s\n\r",
                    DNS_TYPE_TO_STRING(type),
                    DNS_CLASS_TO_STRING(class),
                    name);
        }
    }

    if (answerCount > 0) {
        ret = parseReplies(buffer, buflen, &pos, answerCount, message, &msgPos, "A");
        if (ret < 0) {
            goto out;
        }
    }

    if (authorityCount > 0) {
        ret = parseReplies(buffer, buflen, &pos, authorityCount, message, &msgPos, "AUTH");
        if (ret < 0) {
            goto out;
        }
    }

    if (additionalCount > 0) {
        ret = parseReplies(buffer, buflen, &pos, additionalCount, message, &msgPos, "+");
        if (ret < 0) {
            goto out;
        }
    }

    addToMsg(message, &msgPos, "\n\r");
    output(message);
    ret = 0;

out:
    return ret;
}

void
buildDnsQuery(const char *name, const DNSType dnsType,
        uint8_t **buffer, int *buflen)
{
    char *query;
    char header[HEADER_SZ] = {0};
    
    header[0] = 0xAA;      // Transaction ID
    header[1] = 0xBB;
    
    // flags
    header[2] |= (1 << 0); // Query
    header[3] = 0;
    
    header[4] = 0;         // Number of questions
    header[5] = 1;

    memcpy((*buffer), header, HEADER_SZ);
    
    // Question section
    char buf[MAX_DOMAIN_NAME] = {0};
    strcpy(buf, name);

    char *token = strtok(buf, ".");
    int i = HEADER_SZ;
    
    while(token) {
        int len = strlen(token);
        (*buffer)[i] = (char)len;
        i++;
        memcpy(&(*buffer)[i], token, len);
        i += len;
        token = strtok(NULL, ".");
    }

    // End of question section
    (*buffer)[i] = 0; i++; // Terminaton of QNAME
    *((uint16_t*)&(*buffer)[i]) = htons(dnsType); i = i + 2;
    (*buffer)[i] = 0; i++; // QCLASS
    (*buffer)[i] = 1;

    *buflen = i + 1;
}


int
parseDNSName(uint8_t *buf, uint16_t *pos, char *name)
{
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

/****************************************************************************************/
static bool
parseIPv4AddrS(uint8_t *buffer, uint16_t *pos, char *ipv4Str, int maxLen) 
{
    bool ret = false;
    if (maxLen < MAX_IPV4_ADDR) {
        fprintf(stderr, "IPv4 string buffer too small\n");
        return ret;
    }                           
    sprintf(ipv4Str, "%d.%d.%d.%d",
        (uint8_t)buffer[*pos],
        (uint8_t)buffer[(*pos)+1],
        (uint8_t)buffer[(*pos)+2],
        (uint8_t)buffer[(*pos)+3]);
    (*pos) += 4;
    ret = true;
    return ret;
}

static bool
parseIPv6AddrS(uint8_t *buffer, uint16_t *pos, char *ipv6Str, int maxLen) 
{
    bool ret = false;
    int j = 0, k = 0;
    if (maxLen < MAX_IPV6_ADDR) {
        fprintf(stderr, "IPv6 string buffer too small\n");
        return ret;
    }
    for (j = 0; j < 8; j++) {             
        k += sprintf(ipv6Str + k, "%02x%02x:",
                (uint8_t)buffer[*pos], (uint8_t)buffer[(*pos)+1]);
        (*pos) += 2;                          
    }
    ipv6Str[k-1] = 0;
    ret = true;
    return ret;
}

static void
parseResourceRecords(uint8_t *buffer, uint16_t *pos, DNSType type, int dataLength,
        char *message, int *msgPos)
{
    char ipv4s[MAX_IPV4_ADDR] = {0};
    char ipv6s[MAX_IPV6_ADDR] = {0};
    char name[MAX_DOMAIN_NAME] = {0};
    switch (type) {
    case PTR:
    case CNAME:
        if (!parseDNSName(buffer, pos, name)) {
            fprintf(stderr, "Failed to parse DNS name\n");
        } else {
            addToMsg(message, msgPos, "       -> %s\n\r", name);
        }
        break;
    case A:
        if (!parseIPv4AddrS(buffer, pos, ipv4s, sizeof(ipv4s))) {
            fprintf(stderr, "Failed to parse IPv4 address\n");
        } else {
            addToMsg(message, msgPos, "       -> %s\n\r", ipv4s);
        }
        break;
    case AAAA:
        if (!parseIPv6AddrS(buffer, pos, ipv6s, sizeof(ipv6s))) {
            fprintf(stderr, "Failed to parse IPv6 address\n");
        } else {
            addToMsg(message, msgPos, "       -> %s\n\r", ipv6s);
        }
        break;
    case SRV:
        parseSRV(buffer, pos, message, msgPos);
        break;
    case NSEC:
    default:
        *pos += dataLength;
        break;
    }
}

static int
parseReplies(uint8_t *buffer, int buflen, uint16_t *pos, uint16_t count,
        char *message, int *msgPos, const char *label)
{
    int ret = 0;
    uint16_t i = 0;
    char name[MAX_DOMAIN_NAME] = {0};
    uint16_t type, rawClass, class, dataLength;
    uint32_t ttl;

    for (i = 0; i < count; i++) {
        name[0] = '\0';
        parseDNSName(buffer, pos, name);
        type = ntohs(*(uint16_t*)&buffer[*pos]);
        *pos += 2;
        class = ntohs(*(uint16_t*)&buffer[*pos]);
        *pos += 2;
        ttl = ntohl(*(uint32_t*)&buffer[*pos]);
        *pos += 4;
        dataLength = ntohs(*(uint16_t*)&buffer[*pos]);
        *pos += 2;

        if (strcmp(DNS_TYPE_TO_STRING(type), "UNKNOWN") == 0) {
            // printToMessageBox("Unknown DNS type: %u\n\r", type);
            // debug_dump(buffer, buflen, printToMessageBox);
            // ret = -1;
            // goto out;
        }

        if (strcmp(DNS_CLASS_TO_STRING(class), "UNKNOWN") == 0) {
            // name[0] = 0;
            // printToMessageBox("pos before: %d\n", tmp);
            // parseDNSName(buffer, &tmp, name);
            // printToMessageBox("Name: %s, pos: %u\n\r", name, tmp);
            // uint16_t type =
            //     ((uint16_t)buffer[tmp] << 8) |
            //     buffer[tmp + 1];
            // printToMessageBox("Type bytes: %02x %02x\n\r",
            //                 buffer[tmp], buffer[tmp + 1]);
            // tmp += 2;
            // printToMessageBox("After type: pos=%u\n\r", tmp);
            // uint16_t rawClass =
            //     ((uint16_t)buffer[tmp] << 8) |
            //     buffer[tmp + 1];
            // printToMessageBox("Class bytes: %02x %02x\n\r",
            //                 buffer[tmp], buffer[tmp + 1]);
            // printToMessageBox("Raw class: 0x%04x\n\r", rawClass);
            // debug_dump(buffer, buflen, printToMessageBox);
            // ret = -1;
            // goto out;
        }

        addToMsg(message, msgPos,
                "  %s  %s%s  TTL=%u %s\n\r",
                label,
                DNS_TYPE_TO_STRING(type),
                DNS_CLASS_TO_STRING(class),
                ttl,
                name);
        parseResourceRecords(buffer, pos, type, dataLength, message,
            msgPos);
    }
    ret = 0;

out:
    return ret;
}

static int
parseSRV(uint8_t *buffer, uint16_t *pos, char *message,
        int *msgPos)
{
    char target[MAX_DOMAIN_NAME] = {0};
    uint16_t priority = (buffer[(*pos)] << 8) | buffer[(*pos) + 1];
    uint16_t weight = (buffer[(*pos) + 2] << 8) | buffer[(*pos) + 3];
    uint16_t port = (buffer[(*pos) + 4] << 8) | buffer[(*pos) + 5];
    (*pos) += 6;
    if (parseDNSName(buffer, pos, target) < 0)
        return -1;
    addToMsg(message, msgPos, "       -> %u %u %u %s\n\r",
            priority, weight, port, target);    
    return 1;
}

static void
debug_dump(uint8_t *buf, int n, outputFunc output)
{
    int i = 0, cnt = 0;
    if (buf == NULL || n <= 0)
        return;
    char msg[n * 3 + n / 8 + n / 16 + 2];
    size_t pos = 0;
    size_t len = sizeof(msg);
    outputFunc out = (output != NULL) ? output : printf;
    msg[0] = 0;
    for (i = 0; i < n; i++) {
        pos += snprintf(msg + pos, len - pos, "%02x ", buf[i]);
        cnt++;  
        if (cnt % 8 == 0)
            pos += snprintf(msg + pos, len - pos, " ");
        if (cnt % 16 == 0)
            pos += snprintf(msg + pos, len - pos, "\n");
    }    
    if (cnt % 16 != 0)
        snprintf(msg + pos, len - pos, "\n");
    out("%s", msg);
}

static inline void
addToMsg(char *message, int *msgPos, const char *format, ...)
{
    int n = 0;
    if (*msgPos >= MSG_SZ)
        return;

    va_list args;
    va_start(args, format);
    n = vsnprintf(message + *msgPos, MSG_SZ - *msgPos, format, args);
    va_end(args);

    if (n < 0)
        return;

    if (n >= MSG_SZ - *msgPos) {
        *msgPos = MSG_SZ - 1;
    } else {
        *msgPos += n;
    }
}