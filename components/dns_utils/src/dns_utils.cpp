#include "dns_utils.h"

#include <algorithm>
#include <cstring>
#include <netdb.h>
#include <random>
#include <stdexcept>

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <arpa/nameser.h>
#include <resolv.h>
#endif

namespace dns_utils {
namespace {

std::vector<SrvRecord> order_srv_records(std::vector<SrvRecord> records) {
    std::stable_sort(records.begin(), records.end(),
                     [](const SrvRecord& a, const SrvRecord& b) { return a.priority < b.priority; });

    std::random_device rd;
    std::mt19937 rng(rd());

    std::vector<SrvRecord> ordered;
    ordered.reserve(records.size());

    size_t i = 0;
    while (i < records.size()) {
        size_t j = i;
        while (j < records.size() && records[j].priority == records[i].priority) {
            ++j;
        }

        std::vector<SrvRecord> group(records.begin() + static_cast<long>(i),
                                     records.begin() + static_cast<long>(j));

        while (!group.empty()) {
            uint32_t sum = 0;
            for (const auto& r : group) {
                sum += r.weight;
            }

            size_t pick = 0;
            if (sum == 0) {
                std::uniform_int_distribution<size_t> dist(0, group.size() - 1);
                pick = dist(rng);
            } else {
                std::uniform_int_distribution<uint32_t> dist(1, sum);
                uint32_t x = dist(rng);
                for (size_t idx = 0; idx < group.size(); ++idx) {
                    if (x <= group[idx].weight) {
                        pick = idx;
                        break;
                    }
                    x -= group[idx].weight;
                }
            }

            ordered.push_back(group[pick]);
            group.erase(group.begin() + static_cast<long>(pick));
        }

        i = j;
    }

    return ordered;
}

std::vector<SrvRecord> lookup_srv_system(const std::string& srv_domain) {
#if !(defined(__linux__) || defined(__APPLE__) || defined(__unix__))
    (void)srv_domain;
    throw std::runtime_error("dns_utils::lookup_srv not implemented on this platform");
#else
    // Use libresolv; handles compressed names in SRV answers.
    std::vector<uint8_t> answer(64 * 1024);
    (void)res_init();

    int len = res_query(srv_domain.c_str(), ns_c_in, ns_t_srv, answer.data(), static_cast<int>(answer.size()));
    if (len < 0) {
        throw std::runtime_error("res_query failed for " + srv_domain);
    }

    ns_msg handle;
    if (ns_initparse(answer.data(), len, &handle) < 0) {
        throw std::runtime_error("ns_initparse failed for " + srv_domain);
    }

    int count = ns_msg_count(handle, ns_s_an);
    if (count <= 0) {
        throw std::runtime_error("SRV response contained no answers for " + srv_domain);
    }

    std::vector<SrvRecord> records;
    records.reserve(static_cast<size_t>(count));

    for (int i = 0; i < count; ++i) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) != 0) {
            continue;
        }

        if (ns_rr_type(rr) != ns_t_srv) {
            continue;
        }

        const uint8_t* rdata = ns_rr_rdata(rr);
        const int rdlen = ns_rr_rdlen(rr);
        if (rdlen < 6) {
            continue;
        }

        uint16_t prio = static_cast<uint16_t>(ns_get16(rdata));
        uint16_t weight = static_cast<uint16_t>(ns_get16(rdata + 2));
        uint16_t port = static_cast<uint16_t>(ns_get16(rdata + 4));

        char target[NS_MAXDNAME];
        std::memset(target, 0, sizeof(target));

        int explen = dn_expand(answer.data(), answer.data() + len, rdata + 6, target, sizeof(target));
        if (explen < 0) {
            continue;
        }

        SrvRecord rec;
        rec.priority = prio;
        rec.weight = weight;
        rec.port = port;
        rec.target = std::string(target);
        records.push_back(std::move(rec));
    }

    if (records.empty()) {
        throw std::runtime_error("No SRV records parsed from response for " + srv_domain);
    }

    return records;
#endif
}

} // namespace

std::string strip_trailing_dot(std::string s) {
    if (!s.empty() && s.back() == '.') {
        s.pop_back();
    }
    return s;
}

std::vector<SrvRecord> lookup_srv(const std::string& srv_domain) {
    auto records = lookup_srv_system(srv_domain);
    return order_srv_records(std::move(records));
}

std::vector<std::string> resolve_host_ips(const std::string& hostname) {
    const std::string host = strip_trailing_dot(hostname);

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;

    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc != 0) {
        throw std::runtime_error("getaddrinfo failed for " + host + ": " + gai_strerror(rc));
    }

    std::vector<std::string> out;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        char buf[NI_MAXHOST];
        std::memset(buf, 0, sizeof(buf));

        int nirc = getnameinfo(p->ai_addr, p->ai_addrlen, buf, sizeof(buf), nullptr, 0, NI_NUMERICHOST);
        if (nirc != 0) {
            continue;
        }
        out.emplace_back(buf);
    }
    freeaddrinfo(res);

    if (out.empty()) {
        throw std::runtime_error("hostname " + host + " resolved to no IPs");
    }
    return out;
}

} // namespace dns_utils


