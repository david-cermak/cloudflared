#include "dns_utils.h"

#include <string.h>
#include <unistd.h>

#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/inet.h"

// Private esp-dns header (C-only); do not include this from C++.
#include "../managed_components/espressif__esp_dns/esp_dns_utils.h"

#ifndef DNS_RRTYPE_SRV
#define DNS_RRTYPE_SRV 33
#endif

static uint16_t read_u16_be(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

// Decode a DNS name at `offset` into `out` (dot-separated, NUL terminated).
// Handles RFC1035 compression pointers. On success returns 1, and writes number of bytes consumed
// (from the original offset, before following pointers) into `consumed`.
static int decode_dns_name(const uint8_t *msg,
                           size_t msg_len,
                           size_t offset,
                           char *out,
                           size_t out_len,
                           size_t *consumed)
{
    size_t cur = offset;
    size_t out_pos = 0;
    size_t jumped_consumed = 0;
    int jumped = 0;
    int depth = 0;

    if (out_len == 0) {
        return 0;
    }
    out[0] = '\0';
    *consumed = 0;

    while (1) {
        if (cur >= msg_len) {
            return 0;
        }
        uint8_t len = msg[cur];

        if (len == 0) {
            if (!jumped) {
                *consumed = (cur - offset) + 1;
            } else {
                *consumed = jumped_consumed;
            }
            // NUL terminate
            if (out_pos >= out_len) {
                out[out_len - 1] = '\0';
            } else {
                out[out_pos] = '\0';
            }
            return 1;
        }

        // Compression pointer: 11xxxxxx xxxxxxxx
        if ((len & 0xC0) == 0xC0) {
            if (cur + 1 >= msg_len) {
                return 0;
            }
            uint16_t ptr = (uint16_t)(((uint16_t)(len & 0x3F) << 8) | (uint16_t)msg[cur + 1]);
            if (!jumped) {
                jumped = 1;
                jumped_consumed = (cur - offset) + 2;
            }
            cur = ptr;
            if (++depth > 20) {
                return 0;
            }
            continue;
        }

        // Label
        if (cur + 1 + len > msg_len) {
            return 0;
        }
        if (out_pos != 0) {
            if (out_pos + 1 >= out_len) {
                return 0;
            }
            out[out_pos++] = '.';
        }
        if (out_pos + len >= out_len) {
            return 0;
        }
        memcpy(out + out_pos, msg + cur + 1, len);
        out_pos += len;
        cur += 1 + len;
    }
}

static int skip_dns_name(const uint8_t *msg, size_t msg_len, size_t *offset)
{
    char tmp[DNS_UTILS_MAX_NAME];
    size_t consumed = 0;
    if (!decode_dns_name(msg, msg_len, *offset, tmp, sizeof(tmp), &consumed)) {
        return 0;
    }
    *offset += consumed;
    return 1;
}

int dns_utils_lookup_srv_udp(const char *dns_server_ip,
                             uint16_t dns_port,
                             const char *srv_domain,
                             int timeout_ms,
                             dns_utils_srv_record_t *out_records,
                             size_t out_capacity,
                             size_t *out_count)
{
    if (!dns_server_ip || !srv_domain || !out_records || !out_count) {
        return -1;
    }
    *out_count = 0;

    uint8_t query[512];
    uint16_t query_id = 0;
    size_t qlen = esp_dns_create_query(query, sizeof(query), srv_domain, DNS_RRTYPE_SRV, &query_id);
    if (qlen == (size_t)-1) {
        return -2;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        return -3;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(dns_port);
    to.sin_addr.s_addr = inet_addr(dns_server_ip);

    int sent = sendto(sock, query, (int)qlen, 0, (struct sockaddr *)&to, sizeof(to));
    if (sent < 0) {
        close(sock);
        return -4;
    }

    uint8_t resp[1024];
    int rlen = recvfrom(sock, resp, sizeof(resp), 0, NULL, NULL);
    close(sock);
    if (rlen <= 0) {
        return -5;
    }

    const uint8_t *msg = resp;
    const size_t msg_len = (size_t)rlen;
    if (msg_len < sizeof(dns_header_t)) {
        return -6;
    }

    const dns_header_t *hdr = (const dns_header_t *)msg;
    if (ntohs(hdr->id) != query_id) {
        return -7;
    }

    uint16_t qd = ntohs(hdr->qdcount);
    uint16_t an = ntohs(hdr->ancount);

    size_t off = sizeof(dns_header_t);

    // Skip questions
    for (uint16_t i = 0; i < qd; ++i) {
        if (!skip_dns_name(msg, msg_len, &off)) {
            return -8;
        }
        if (off + sizeof(dns_question_t) > msg_len) {
            return -9;
        }
        off += sizeof(dns_question_t);
    }

    // Parse answers
    for (uint16_t i = 0; i < an; ++i) {
        if (*out_count >= out_capacity) {
            break;
        }
        if (!skip_dns_name(msg, msg_len, &off)) {
            break;
        }
        if (off + SIZEOF_DNS_ANSWER_FIXED > msg_len) {
            break;
        }

        const dns_answer_t *ans = (const dns_answer_t *)(msg + off);
        uint16_t type = ntohs(ans->type);
        uint16_t cls = ntohs(ans->class);
        uint16_t rdlen = ntohs(ans->data_len);

        off += SIZEOF_DNS_ANSWER_FIXED;
        if (off + rdlen > msg_len) {
            break;
        }

        if (type == DNS_RRTYPE_SRV && cls == DNS_RRCLASS_IN && rdlen >= 6) {
            const uint8_t *rdata = msg + off;
            dns_utils_srv_record_t rec;
            memset(&rec, 0, sizeof(rec));
            rec.priority = read_u16_be(rdata + 0);
            rec.weight = read_u16_be(rdata + 2);
            rec.port = read_u16_be(rdata + 4);

            size_t consumed = 0;
            if (decode_dns_name(msg, msg_len, off + 6, rec.target, sizeof(rec.target), &consumed)) {
                out_records[*out_count] = rec;
                (*out_count)++;
            }
        }

        off += rdlen;
    }

    return (*out_count > 0) ? 0 : -10;
}

int dns_utils_resolve_host_ips(const char *hostname,
                               char out_ips[][DNS_UTILS_MAX_IP_STR],
                               size_t out_capacity,
                               size_t *out_count)
{
    if (!hostname || !out_ips || !out_count) {
        return -1;
    }
    *out_count = 0;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(hostname, NULL, &hints, &res);
    if (rc != 0) {
        return rc; // caller prints numeric rc
    }

    for (struct addrinfo *p = res; p != NULL && *out_count < out_capacity; p = p->ai_next) {
        char buf[DNS_UTILS_MAX_IP_STR];
        memset(buf, 0, sizeof(buf));

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;
            if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) == NULL) {
                continue;
            }
        } else if (p->ai_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)p->ai_addr;
            if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)) == NULL) {
                continue;
            }
        } else {
            continue;
        }

        strncpy(out_ips[*out_count], buf, DNS_UTILS_MAX_IP_STR - 1);
        out_ips[*out_count][DNS_UTILS_MAX_IP_STR - 1] = '\0';
        (*out_count)++;
    }

    freeaddrinfo(res);
    return (*out_count > 0) ? 0 : -2;
}






