#include "edge_discovery.h"

#include "dns_utils.h"

#include <stdexcept>

namespace {

constexpr const char* kSrvProto = "tcp";
constexpr const char* kSrvName = "argotunnel.com";
constexpr const char* kSrvService = "v2-origintunneld";

static std::string getRegionalServiceName(const std::string& region) {
    if (!region.empty()) {
        return region + "-" + std::string(kSrvService);
    }
    return std::string(kSrvService);
}

static std::string makeSrvDomain(const std::string& srvService) {
    // Example: _v2-origintunneld._tcp.argotunnel.com
    return "_" + srvService + "._" + std::string(kSrvProto) + "." + std::string(kSrvName);
}

static EdgeIPVersion ipVersionOfString(const std::string& ip) {
    // Quick heuristic: IPv6 contains ':'
    return (ip.find(':') != std::string::npos) ? EdgeIPVersion::V6 : EdgeIPVersion::V4;
}

} // namespace

std::vector<std::vector<EdgeAddr>> EdgeDiscovery::ResolveEdgeAddrs(const std::string& region,
                                                                   ConfigIPVersion override_ip_version) {
    const std::string srvService = getRegionalServiceName(region);
    const std::string domain = makeSrvDomain(srvService);

    // 1) SRV lookup (with RFC2782 ordering)
    const auto srvRecords = dns_utils::lookup_srv(domain);

    // 2) Resolve each SRV target to IPs and map to EdgeAddr
    std::vector<std::vector<EdgeAddr>> resolvedAddrPerSRV;
    resolvedAddrPerSRV.reserve(srvRecords.size());

    for (const auto& srv : srvRecords) {
        const auto ips = dns_utils::resolve_host_ips(srv.target);

        std::vector<EdgeAddr> addrs;
        addrs.reserve(ips.size());

        for (const auto& ip : ips) {
            const EdgeIPVersion v = ipVersionOfString(ip);
            if (override_ip_version == ConfigIPVersion::IPv4Only && v != EdgeIPVersion::V4) {
                continue;
            }
            if (override_ip_version == ConfigIPVersion::IPv6Only && v != EdgeIPVersion::V6) {
                continue;
            }
            EdgeAddr a;
            a.ip = ip;
            a.port = srv.port;
            a.ip_version = v;
            addrs.push_back(std::move(a));
        }

        if (addrs.empty()) {
            throw std::runtime_error("SRV target " + dns_utils::strip_trailing_dot(srv.target) +
                                     " resolved to no usable IPs after filtering");
        }

        resolvedAddrPerSRV.push_back(std::move(addrs));
    }

    if (resolvedAddrPerSRV.size() < 2) {
        throw std::runtime_error("expected at least 2 Cloudflare regions, but SRV only returned " +
                                 std::to_string(resolvedAddrPerSRV.size()));
    }

    return resolvedAddrPerSRV;
}


