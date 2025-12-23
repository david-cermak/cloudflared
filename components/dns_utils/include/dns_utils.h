#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <cstdint>
#include <string>
#include <vector>

namespace dns_utils {

struct SrvRecord {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    std::string target; // may include trailing dot
};

// Look up SRV records for a fully-qualified SRV domain like:
//   _v2-origintunneld._tcp.argotunnel.com
//
// Returns records ordered according to RFC2782:
// - sorted by priority asc
// - randomized by weight within same priority
std::vector<SrvRecord> lookup_srv(const std::string& srv_domain);

// Resolve hostname to numeric IP strings (both v4/v6 depending on system + filters).
std::vector<std::string> resolve_host_ips(const std::string& hostname);

// Helpers
std::string strip_trailing_dot(std::string s);

} // namespace dns_utils

#endif // DNS_UTILS_H



