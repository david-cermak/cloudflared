# Phase 2 Implementation Notes - Edge Discovery

## Overview

Phase 2 implements DNS SRV lookup to discover Cloudflare edge servers. This phase discovers the actual IP addresses and ports where Cloudflare edge servers are listening for tunnel connections.

## Status (C++ Implementation)

- **Host**: ✅ implemented + tested (`cpp-cloudflared` binary + unit test)
- **ESP32**: ✅ implemented + tested (logs SRV answers and resolved `ip:port` on device)
- **Go parity**: ⏳ DoT fallback + strict side-by-side comparison is still optional work

## Go Implementation Analysis

### Key Files
- `edgediscovery/allregions/discovery.go` - Core DNS SRV lookup logic
- `edgediscovery/allregions/regions.go` - Region management and address allocation
- `edgediscovery/edgediscovery.go` - High-level edge discovery interface

### DNS SRV Query Details

**Service Name**: `v2-origintunneld`
**Protocol**: `tcp`
**Domain**: `argotunnel.com`
**Full SRV Query**: `_v2-origintunneld._tcp.argotunnel.com`

**Regional Variants**: 
- If region is specified (e.g., `us`), query becomes: `_us-v2-origintunneld._tcp.argotunnel.com`
- Global service (no region): `_v2-origintunneld._tcp.argotunnel.com`

### Implementation Flow

1. **SRV Lookup**:
   - Call `net.LookupSRV(srvService, srvProto, srvName)`
   - Returns: `cname string, addrs []*net.SRV, err error`
   - SRV records contain: `Priority`, `Weight`, `Port`, `Target` (hostname)

2. **Fallback to DoT (DNS over TLS)**:
   - If regular DNS lookup fails, fallback to Cloudflare DoT
   - DoT server: `1.1.1.1:853` (cloudflare-dns.com)
   - Uses TLS connection with custom resolver
   - Timeout: 15 seconds
   - Reason: Some DNS resolvers return compressed SRV records (Go issue #27546)

3. **Resolve SRV Targets**:
   - For each SRV record, resolve `Target` hostname to IP addresses
   - Call `net.LookupIP(srv.Target)` - returns both IPv4 and IPv6
   - Create `EdgeAddr` structure for each IP:
     ```go
     type EdgeAddr struct {
         TCP       *net.TCPAddr  // IP + Port from SRV record
         UDP       *net.UDPAddr  // Same IP + Port (QUIC uses UDP)
         IPVersion EdgeIPVersion // V4 or V6
     }
     ```

4. **Region Organization**:
   - Returns `[][]*EdgeAddr` - array of EdgeAddr arrays
   - Each inner array represents one region (from CNAME)
   - Expects at least 2 regions (for HA)
   - Regions are split into `region1` and `region2`

### Key Structures

```go
// EdgeAddr represents an edge server address
type EdgeAddr struct {
    TCP       *net.TCPAddr  // For HTTP2 connections
    UDP       *net.UDPAddr  // For QUIC connections
    IPVersion EdgeIPVersion // V4 or V6
}

// EdgeIPVersion enum
const (
    V4 EdgeIPVersion = 4
    V6 EdgeIPVersion = 6
)
```

### Important Details

1. **SRV Record Sorting**:
   - Go's `net.LookupSRV` automatically sorts by priority
   - Randomizes by weight within same priority
   - This ordering is important for load balancing

2. **IP Version Detection**:
   - Uses `ip.To4() != nil` to detect IPv4
   - Otherwise assumes IPv6

3. **Port from SRV**:
   - The port comes from the SRV record, not from A/AAAA lookup
   - Both TCP and UDP use the same port number

4. **Multiple IPs per Target**:
   - One SRV target can resolve to multiple IPs (IPv4 + IPv6)
   - Each IP gets its own EdgeAddr entry

5. **Error Handling**:
   - If SRV lookup fails, tries DoT fallback
   - If DoT also fails, returns error with helpful messages
   - If any SRV target fails to resolve, entire discovery fails

### Testing Strategy

**Manual Verification**:
```bash
# Test SRV lookup manually
dig SRV _v2-origintunneld._tcp.argotunnel.com

# Test with specific DNS server
dig @1.1.1.1 SRV _v2-origintunneld._tcp.argotunnel.com

# Test IP resolution for a target
dig A <target-from-srv-record>
dig AAAA <target-from-srv-record>
```

**Expected Output**:
- Multiple SRV records with different priorities/weights
- Each SRV record has a target hostname
- Each target resolves to multiple IPs (IPv4 and IPv6)
- At least 2 distinct regions (CNAME groups)

## C++ Implementation Plan

### Library Choices

**Host Platform**:
- DNS SRV lookup: `getaddrinfo` with `AI_SERVICE` flag (if available) OR c-ares library
- DNS over TLS fallback: OpenSSL + custom DoT implementation OR c-ares with DoT support
- IP resolution: `getaddrinfo` (supports both IPv4 and IPv6)

**ESP32 Platform**:
- DNS SRV lookup: Custom implementation using esp-dns low-level functions OR c-ares library
- DNS over TLS fallback: **esp-dns component** (`esp_dns_init_dot()`) - already available in project
- IP resolution: **esp-dns component** via `getaddrinfo()` hook (supports A/AAAA records)
- Note: esp-dns hooks into LWIP resolver and supports DoT/DoH/TCP/UDP protocols

**Alternative**: Use c-ares library for both platforms (C library, ESP32-compatible)

### Implementation Steps

1. **Create EdgeAddr structure** (C++ equivalent):
   ```cpp
   struct EdgeAddr {
       std::string tcp_ip;
       uint16_t tcp_port;
       std::string udp_ip;
       uint16_t udp_port;
       bool is_ipv6;
   };
   ```

2. **Implement DNS SRV lookup**:
   - **Host**: Use c-ares library or system resolver (`getaddrinfo` with service)
   - **ESP32**: Use esp-dns low-level functions (`esp_dns_create_query`, `esp_dns_parse_response`) 
     - Extend to support SRV record type (type 33)
     - Parse SRV records (priority, weight, port, target)
     - Sort by priority, randomize by weight

3. **Implement DoT fallback**:
   - **Host**: Custom DoT implementation (OpenSSL + TLS connection to 1.1.1.1:853)
   - **ESP32**: Use **esp-dns component** - `esp_dns_init_dot()`:
     ```cpp
     esp_dns_config_t dot_config = {
         .dns_server = "1.1.1.1",  // or "cloudflare-dns.com"
         .port = ESP_DNS_DEFAULT_DOT_PORT,  // 853
         .timeout_ms = 15000,
         .tls_config = {
             .crt_bundle_attach = esp_crt_bundle_attach,
         }
     };
     esp_dns_handle_t dot_handle = esp_dns_init_dot(&dot_config);
     // Then use esp-dns for SRV queries via low-level API
     ```

4. **Resolve SRV targets**:
   - **Host**: Use `getaddrinfo()` or c-ares
   - **ESP32**: Use **esp-dns component** via `getaddrinfo()` hook (automatic A/AAAA resolution)
   - Handle both IPv4 and IPv6
   - Create EdgeAddr for each IP

5. **Organize by regions**:
   - Group EdgeAddrs by CNAME (if available)
   - Return vector of vectors (regions)
   - Verify at least 2 regions

### ESP32 Implementation Details

**Using esp-dns Component**:
- Component location: `quick-tunnel/managed_components/espressif__esp_dns`
- Supports: UDP, TCP, DoT, DoH protocols
- Hooks into LWIP resolver via `CONFIG_LWIP_HOOK_NETCONN_EXT_RESOLVE_CUSTOM`
- Provides low-level DNS functions: `esp_dns_create_query()`, `esp_dns_parse_response()`
- **Limitation**: Only handles A/AAAA records via `getaddrinfo()` hook
- **Solution**: Extend low-level functions to support SRV record type (33)

**SRV Record Implementation**:
- Create DNS query with QTYPE=33 (SRV)
- Parse SRV response format: `Priority (2 bytes) + Weight (2 bytes) + Port (2 bytes) + Target (variable)`
- Use esp-dns DoT for secure fallback when regular DNS fails

### Testing Plan

1. **Instrument Go version**:
   - Add detailed logging to `edgeDiscovery()` function
   - Log SRV query domain
   - Log each SRV record (priority, weight, port, target)
   - Log resolved IPs for each target
   - Log final EdgeAddr structures
   - Add environment variable to stop after discovery

2. **Test Go version**:
   - Run with debug logging
   - Capture output
   - Verify SRV records match manual `dig` output
   - Verify IP resolution

3. **Implement C++ version**:
   - Match Go behavior exactly
   - Same SRV query
   - Same fallback logic
   - Same IP resolution

4. **Compare implementations**:
   - Run both side-by-side
   - Compare SRV records received
   - Compare IPs resolved
   - Compare EdgeAddr structures created
   - Verify same regions discovered

## Notes

- **DoT Fallback**: Important for environments with problematic DNS resolvers
- **SRV Sorting**: Must preserve priority/weight ordering from Go stdlib
- **Multiple Regions**: Required for HA - must handle gracefully if only 1 region
- **IPv6 Support**: Must handle both IPv4 and IPv6 addresses
- **Port Handling**: Port comes from SRV record, not DNS A/AAAA lookup

## Actual C++ Implementation (what we built)

### Host (Linux)

**Reusable DNS utility**:
- `components/dns_utils/include/dns_utils.h`
- `components/dns_utils/src/dns_utils.cpp`

Implementation details:
- **SRV lookup**: uses system resolver via `libresolv` (`res_query` + `ns_initparse` + `dn_expand`)
  - Handles compressed names in SRV answers
  - Applies RFC2782 ordering (priority + weighted random within same priority)
- **A/AAAA resolution**: uses `getaddrinfo()` to get both IPv4 and IPv6 for each SRV target

**Cloudflare-specific wrapper**:
- `components/cloudflared/include/edge_discovery.h`
- `components/cloudflared/src/edge_discovery.cpp`

Entry points:
- `./build/cpp-cloudflared --phase2 [region]` prints SRV groups and resolved `ip:port`
- `ctest --test-dir build -R test_phase2_srv` runs a minimal sanity test

### ESP32 (ESP-IDF)

We intentionally **do not include esp-dns private headers from C++**, because `esp_dns_utils.h` is private and not C++-safe.

Instead:
- `quick-tunnel/main/dns_utils.c` (plain C) includes the private esp-dns header and implements:
  - SRV UDP query using `esp_dns_create_query(..., qtype=33)`
  - SRV response parsing (including RFC1035 compression pointers)
  - hostname → IP string list using `getaddrinfo()` + `inet_ntop()`
- `quick-tunnel/main/dns_utils.h` exposes a C/C++-safe API used by:
  - `quick-tunnel/main/quick-tunnel.cpp`

Current behavior:
- SRV queries are sent to **Cloudflare resolver** `1.1.1.1:53` for determinism.
- DoT fallback is not implemented yet (parity with Go is Phase 2.6 in `PLAN.md`).

## References

- Go net.LookupSRV: https://golang.org/pkg/net/#Resolver.LookupSRV
- DNS SRV RFC: https://tools.ietf.org/html/rfc2782
- Go DNS compression issue: https://github.com/golang/go/issues/27546
- Cloudflare DoT: https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-tls/
- ESP-DNS Component: `quick-tunnel/managed_components/espressif__esp_dns/`
  - Header: `include/esp_dns.h`
  - Utils: `esp_dns_utils.h` (low-level DNS query/parse functions)
  - Supports DoT: `esp_dns_init_dot()` with Cloudflare DNS (1.1.1.1:853)

