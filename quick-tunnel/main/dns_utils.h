#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Keep these constants "sane" and independent of NI_MAXHOST / platform headers.
// - 255 is max DNS name length (RFC1035); we allow 256 including NUL.
#define DNS_UTILS_MAX_NAME 256
#define DNS_UTILS_MAX_IP_STR 64

typedef struct {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    char target[DNS_UTILS_MAX_NAME]; // decoded hostname, dot-separated, NUL-terminated
} dns_utils_srv_record_t;

// Perform a UDP SRV lookup against a specific DNS server (e.g. 1.1.1.1:53).
// Returns 0 on success, non-zero on error.
int dns_utils_lookup_srv_udp(const char *dns_server_ip,
                             uint16_t dns_port,
                             const char *srv_domain,
                             int timeout_ms,
                             dns_utils_srv_record_t *out_records,
                             size_t out_capacity,
                             size_t *out_count);

// Resolve hostname to numeric IP strings via getaddrinfo().
// Returns 0 on success, non-zero on error. `out_ips` will be filled with NUL-terminated strings.
int dns_utils_resolve_host_ips(const char *hostname,
                               char out_ips[][DNS_UTILS_MAX_IP_STR],
                               size_t out_capacity,
                               size_t *out_count);

#ifdef __cplusplus
} // extern "C"
#endif



