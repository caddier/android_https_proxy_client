
#include "tun2http.h"




//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;


#define IP_REC_STATE_FREE  0
#define IP_REC_STATE_USED  1

typedef  struct FakeIPAddressRecord {
    struct FakeIPAddressRecord *next;
    char qname[255];
    int32_t ipaddr;
    int32_t state; // 0 freed , 1 used
    int64_t alloc_time; //alloc time for this ip  million seconds
    int64_t timeout; //timeout for this record, seconds
}FakeIPAddressRecord;


struct FakeIPAddressRecord *g_fakeip_list = NULL;
uint16_t g_ip_current_index = 0;


//return 0 illegal  or legal 1
int32_t isllegaldomain(char *domainname) {
    if (strstr(domainname, "ri-v3.presage.io") != NULL ||
        strstr(domainname, "it-v2.presage.io") != NULL) {
        return 0;
    }
    return 1;
}


//return ip address network order
int32_t alloc_ipaddress(char *qname) {
    struct FakeIPAddressRecord * node = g_fakeip_list;
    while(node != NULL) {
        if(strcmp(node->qname, qname) == 0 && node->state == IP_REC_STATE_FREE) {
            node->state = IP_REC_STATE_USED;
            return node->ipaddr;
        }
        node = node->next;
    }
    FakeIPAddressRecord *new_node = malloc(sizeof(struct FakeIPAddressRecord));
    g_ip_current_index ++;
    //26.26.xxx.xxx
    new_node->ipaddr = htonl( 26 << 24 | 26 << 16 | g_ip_current_index & 0xFF00 | g_ip_current_index & 0xFF) ;
    new_node->next = g_fakeip_list;
    g_fakeip_list = new_node;
    strcpy(new_node->qname, qname);
    new_node->state = IP_REC_STATE_USED;
    new_node->alloc_time = get_ms();
    new_node->timeout = 3600;
    return new_node->ipaddr;
}

int32_t get_domain_from_ip(int32_t fake_ip, char *domain_buffer) {
    if( domain_buffer == NULL) {
        return -1;
    }
    struct FakeIPAddressRecord * node = g_fakeip_list;
    while(node != NULL) {
        if ( node->ipaddr == fake_ip ) {
            strcpy(domain_buffer, node->qname);
            domain_buffer[strlen(node->qname)] = '\0';
            return 0;
        }
        node = node->next;
    }
    return -1;
}


//return freed address , network order
int32_t free_ipaddress(char *qname) {
    struct FakeIPAddressRecord * node = g_fakeip_list;
    while(node != NULL) {
        if(strcmp(node->qname, qname) == 0 && node->state == IP_REC_STATE_USED) {
            node->state = IP_REC_STATE_FREE;
            return node->ipaddr;
        }
        node = node->next;
    }
}

//success return network order ipaddress, failed  return 0
int32_t free_ipaddress_byip(int32_t ipaddr) {
    struct FakeIPAddressRecord * node = g_fakeip_list;
    while(node != NULL) {
        if(node->ipaddr == ipaddr && node->state == IP_REC_STATE_USED) {
            node->state = IP_REC_STATE_FREE;
            return node->ipaddr;
        }
        node = node->next;
    }
    return 0;
}

//success return qname rawbuffer data len. failed -1
int32_t get_qname_raw_buffer(const uint8_t *data, const size_t datalen, uint16_t off, char *qname_raw, int32_t *raw_len) {
    char qname[DNS_QNAME_MAX] = {0};
    int32_t offset = get_qname(data, datalen, off, qname);
    if(offset <= 0) {
        return -1;
    }
    memcpy(qname_raw, &data[off], offset - off);
    *raw_len = offset - off;
    return *raw_len;
}


int32_t get_qname(const uint8_t *data, const size_t datalen, uint16_t off, char *qname) {
    *qname = 0;

    uint16_t c = 0;
    uint8_t noff = 0;
    uint16_t ptr = off;
    uint8_t len = *(data + ptr);
    while (len) {
        if (len & 0xC0) {
            ptr = (uint16_t) ((len & 0x3F) * 256 + *(data + ptr + 1));
            len = *(data + ptr);
            log_android(ANDROID_LOG_DEBUG, "DNS qname compression ptr %d len %d", ptr, len);
            if (!c) {
                c = 1;
                off += 2;
            }
        } else if (ptr + 1 + len <= datalen && noff + len <= DNS_QNAME_MAX) {
            memcpy(qname + noff, data + ptr + 1, len);
            *(qname + noff + len) = '.';
            noff += (len + 1);

            ptr += (len + 1);
            len = *(data + ptr);
        }
        else
            break;
    }
    ptr++;

    if (len > 0 || noff == 0) {
        log_android(ANDROID_LOG_ERROR, "DNS qname invalid len %d noff %d", len, noff);
        return -1;
    }

    *(qname + noff - 1) = 0;
    log_android(ANDROID_LOG_DEBUG, "qname %s", qname);

    return (c ? off : ptr);
}

void parse_dns_response(const struct arguments *args, const struct udp_session *u,
                        const uint8_t *data, size_t *datalen) {
    if (*datalen < sizeof(struct dns_header) + 1) {
        log_android(ANDROID_LOG_ERROR, "DNS response length %d", *datalen);
        return;
    }

    // Check if standard DNS query
    // TODO multiple qnames
    struct dns_header *dns = (struct dns_header *) data;
    int qcount = ntohs(dns->q_count);
    int acount = ntohs(dns->ans_count);
    if (dns->qr == 1 && dns->opcode == 0 && qcount > 0 && acount > 0) {
        log_android(ANDROID_LOG_DEBUG, "DNS response qcount %d acount %d", qcount, acount);
        if (qcount > 1)
            log_android(ANDROID_LOG_ERROR, "DNS response qcount %d acount %d", qcount, acount);

        // http://tools.ietf.org/html/rfc1035
        char name[DNS_QNAME_MAX + 1];
        int32_t off = sizeof(struct dns_header);

        uint16_t qtype;
        uint16_t qclass;
        char qname[DNS_QNAME_MAX + 1];

        //process dns query part
        for (int q = 0; q < 1; q++) {
            off = get_qname(data, *datalen, (uint16_t) off, name);
            if (off > 0 && off + 4 <= *datalen) {
                // TODO multiple qnames?
                if (q == 0) {
                    strcpy(qname, name);
                    qtype = ntohs(*((uint16_t *) (data + off)));
                    qclass = ntohs(*((uint16_t *) (data + off + 2)));
                    log_android(ANDROID_LOG_DEBUG,
                                "DNS question %d qtype %d qclass %d qname %s",
                                q, qtype, qclass, qname);
                }
                off += 4;
            }
            else {
                log_android(ANDROID_LOG_ERROR,
                            "DNS response Q invalid off %d datalen %d", off, *datalen);
                return;
            }
        }

        //parse dns answer part
        int32_t aoff = off;
        for (int a = 0; a < acount; a++) {
            off = get_qname(data, *datalen, (uint16_t) off, name);
            if (off > 0 && off + 10 <= *datalen) {
                uint16_t qtype = ntohs(*((uint16_t *) (data + off)));
                uint16_t qclass = ntohs(*((uint16_t *) (data + off + 2)));
                uint32_t ttl = ntohl(*((uint32_t *) (data + off + 4)));
                uint16_t rdlength = ntohs(*((uint16_t *) (data + off + 8)));
                off += 10;

                if (off + rdlength <= *datalen) {
                    if (qclass == DNS_QCLASS_IN &&
                        (qtype == DNS_QTYPE_A || qtype == DNS_QTYPE_AAAA)) {

                        char rd[INET6_ADDRSTRLEN + 1];
                        if (qtype == DNS_QTYPE_A)
                            inet_ntop(AF_INET, data + off, rd, sizeof(rd));
                        else if (qclass == DNS_QCLASS_IN && qtype == DNS_QTYPE_AAAA)
                            inet_ntop(AF_INET6, data + off, rd, sizeof(rd));
                    }
                    else
                        log_android(ANDROID_LOG_DEBUG,
                                    "DNS answer %d qname %s qclass %d qtype %d ttl %d length %d",
                                    a, name, qclass, qtype, ttl, rdlength);

                    off += rdlength;
                }
                else {
                    log_android(ANDROID_LOG_ERROR,
                                "DNS response A invalid off %d rdlength %d datalen %d ttl %d ",
                                off, rdlength, *datalen, ttl);
                    return;
                }
            }
            else {
                log_android(ANDROID_LOG_ERROR,
                            "DNS response A invalid off %d datalen %d", off, *datalen);
                return;
            }
        }
    }
    else if (acount > 0)
        log_android(ANDROID_LOG_ERROR,
                    "DNS response qr %d opcode %d qcount %d acount %d",
                    dns->qr, dns->opcode, qcount, acount);
}

int get_dns_query(const struct arguments *args, const struct udp_session *u,
                  const uint8_t *data, const size_t datalen,
                  uint16_t *qtype, uint16_t *qclass, char *qname) {
    if (datalen < sizeof(struct dns_header) + 1) {
        log_android(ANDROID_LOG_WARN, "DNS query length %d", datalen);
        return -1;
    }

    // Check if standard DNS query
    // TODO multiple qnames
    const struct dns_header *dns = (struct dns_header *) data;
    int qcount = ntohs(dns->q_count);
    if (dns->qr == 0 && dns->opcode == 0 && qcount > 0) {
        if (qcount > 1)
            log_android(ANDROID_LOG_WARN, "DNS query qcount %d", qcount);

        // http://tools.ietf.org/html/rfc1035
        int off = get_qname(data, datalen, sizeof(struct dns_header), qname);
        if (off > 0 && off + 4 == datalen) {
            *qtype = ntohs(*((uint16_t *)(data + off)));
            *qclass = ntohs(*((uint16_t *)(data + off + 2)));
            return 0;
        }
        else
            log_android(ANDROID_LOG_WARN, "DNS query invalid off %d datalen %d", off, datalen);
    }

    return -1;
}

int check_domain(const struct arguments *args, const struct udp_session *u,
                 const uint8_t *data, const size_t datalen,
                 uint16_t qclass, uint16_t qtype, const char *name) {
    log_android(ANDROID_LOG_DEBUG, "check_domain %s", name);
    return 1;
}




//create dns response from dns request data
int create_dns_response(const uint8_t *data, size_t datalen, char *out, int32_t *out_len) {
    memcpy(out, data, datalen);
    struct dns_header *dns = (struct dns_header *)(out);
    char *ptr = out;
    int question_count = ntohs(dns->q_count);
    char qname[DNS_QNAME_MAX + 1] = {0};
    int16_t qtype = 0;
    int16_t qclass = 0;
    int off = get_qname(data, datalen, sizeof(struct dns_header), qname);
    if (question_count == 1) {
        if (off > 0 ) {
            char *hex_str = NULL;
            hex(data + off, datalen - off, &hex_str);
            log_android(ANDROID_LOG_DEBUG, " off %d str: %s", off, hex_str);
            hex_free(hex_str);
            qtype = ntohs(*((int16_t *)(out + off)));
            qclass = ntohs(*((int16_t *)(out + off + 2)));
            dns->qr = 1; //set response flag
            off += 4; //skip qtype and qclass
            if (ntohs(dns->q_count) >= 1 && qtype == DNS_QTYPE_A && qclass == DNS_QCLASS_IN) {
                if (ntohs(dns->q_count) == 1) {
                    dns->ans_count = htons(1); // set answer count to 1
                    ptr += off;
                    char qname_raw[DNS_QNAME_MAX + 1] = {0};
                    int32_t qname_raw_len = DNS_QNAME_MAX + 1;
                    int32_t ret = 0;
                    ret = get_qname_raw_buffer(data, datalen, sizeof(struct dns_header), qname_raw, &qname_raw_len);
                    if (ret < 0) {
                        log_android(ANDROID_LOG_ERROR, "get qname buffer failed ");
                        return -1;
                    }
                    memcpy(ptr, qname_raw, qname_raw_len);
                    ptr += qname_raw_len;
                    *(int16_t *)ptr = htons(qtype);
                    ptr += 2;
                    *(int16_t *)ptr = htons(qclass);
                    ptr += 2;
                    *(int32_t *)ptr = htonl(3600);
                    ptr += 4;
                    *(int16_t *)ptr = htons(4); //rdlength
                    ptr += 2;
                    int32_t ipaddress = alloc_ipaddress(qname);
                    struct in_addr addr;
                    addr.s_addr = ipaddress;
                    char str_ip[255] = {0};
                    inet_ntop(AF_INET, &addr, str_ip, 255);
                    log_android(ANDROID_LOG_DEBUG, "alloc domain %s => ip %s", qname, str_ip);
                    *(int32_t *)ptr = ipaddress;
                    ptr += 4;
                    *out_len = ptr - out;
                    return 0;
                } else {
                    log_android(ANDROID_LOG_ERROR, "not support count > 1 %d ", dns->q_count);
                    return -1;
                }
            } else if (ntohs(dns->q_count) >= 1  && qtype == DNS_QTYPE_AAAA && qclass == DNS_QCLASS_IN) {
                //ipv6
                dns->rcode = htonl(4); // means not support for ipv6 query
                *out_len = datalen;
                return 0;
            } else {
                log_android(ANDROID_LOG_ERROR, "qtype or qclass not support %d %d ", qtype, qclass);
                return -1;
            }
        } else {
            log_android(ANDROID_LOG_ERROR, "DNS query invalid off %d datalen %d", off, datalen);
            return -1;
        }

    } else {
        log_android(ANDROID_LOG_ERROR, "currently, we do not support multiple dns request");
        return -1;
    }

}
