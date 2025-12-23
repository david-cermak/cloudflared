#ifndef EDGE_DISCOVERY_H
#define EDGE_DISCOVERY_H

#include <cstdint>
#include <string>
#include <vector>

// Mirrors the relevant Go edgediscovery/allregions types (minimal for Phase 2)

enum class ConfigIPVersion : int8_t {
    Auto = 2,
    IPv4Only = 4,
    IPv6Only = 6,
};

enum class EdgeIPVersion : int8_t {
    V4 = 4,
    V6 = 6,
};

struct EdgeAddr {
    std::string ip;
    uint16_t port;
    EdgeIPVersion ip_version;
};

class EdgeDiscovery {
public:
    // Returns list-of-lists. Each inner list corresponds to a single SRV record's resolved IPs.
    // (In Go: [][]*EdgeAddr returned by edgeDiscovery()).
    std::vector<std::vector<EdgeAddr>> ResolveEdgeAddrs(const std::string& region = "",
                                                        ConfigIPVersion override_ip_version = ConfigIPVersion::Auto);
};

#endif // EDGE_DISCOVERY_H



