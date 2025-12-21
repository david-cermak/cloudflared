# C++ Quick Tunnel Implementation Plan

## Overview

Minimal C++ rewrite of cloudflared's quick tunnel functionality with ESP32 compatibility. Each component is implemented, tested, and verified before moving to the next.

## Library Choices (ESP32-Compatible)

- **HTTP Client**: libcurl (host) / esp_http_client (ESP32)
- **JSON Parser**: cJSON (both platforms)
- **QUIC Library**: ngtcp2 (both platforms)
- **TLS**: OpenSSL (host) / mbedTLS (ESP32)
- **RPC/Serialization**: Cap'n Proto (both platforms)
- **DNS**: System resolver (host) / ESP-IDF DNS (ESP32)

## Implementation Phases

### Phase 1: Quick Tunnel Request ✅

**Goal**: Request a quick tunnel from trycloudflare.com and parse the response.

#### 1.1 Implement C++ Host Version ✅
- [x] Create HTTP client wrapper (libcurl)
- [x] Implement POST request to `https://api.trycloudflare.com/tunnel`
- [x] Parse JSON response using cJSON
- [x] Extract: `id`, `secret`, `account_tag`, `hostname`
- [x] Print tunnel URL to console
- [x] Exit after successful request
- [x] Set up CMake build system
- [x] Fix cJSON linking issues

**Files Created**:
- `components/cloudflared/src/quick_tunnel.cpp/h` - Quick tunnel request implementation
- `components/cloudflared/src/http_client_host.cpp/h` - libcurl-based HTTP client
- `components/cloudflared/src/main.cpp` - Host entry point for phase 1
- `components/cloudflared/include/` - Public headers
- `CMakeLists.txt` - Host build configuration

**Status**: ✅ COMPLETED - Working and tested

#### 1.2 Instrument/Extract Go Version ✅
- [x] Add verbose logging to Go's `quick_tunnel.go`
- [x] Log HTTP request details (method, URL, headers)
- [x] Log raw JSON response body
- [x] Log parsed fields (tunnel ID, account tag, hostname, secret)
- [x] Add environment variable `QUICK_TUNNEL_REQUEST_ONLY=1` to stop after tunnel creation

**Files Modified**:
- `cmd/cloudflared/tunnel/quick_tunnel.go` - Added debug logging

**Status**: ✅ COMPLETED

#### 1.3 Compare Host C++ vs Go ✅
- [x] Run both implementations side-by-side
- [x] Compare HTTP request headers
- [x] Compare response parsing
- [x] Compare extracted values
- [x] Use tshark/Wireshark to capture network traffic
- [x] Verify: Same API endpoint, same request format, same response handling

**Status**: ✅ COMPLETED

#### 1.4 Implement C++ ESP32 Version ✅
- [x] Create ESP32 HTTP client wrapper (esp_http_client)
- [x] Implement same quick tunnel request logic
- [x] Handle ESP32-specific: WiFi connection, certificate validation
- [x] Use cJSON (same as host version)
- [x] Print tunnel URL via serial
- [x] Create platform abstraction layer

**Files Created**:
- `components/cloudflared/src/http_client_esp32.cpp/h` - ESP-IDF HTTP client wrapper
- `quick-tunnel/main/quick-tunnel.cpp` - ESP32 entry point

**Status**: ✅ COMPLETED

#### 1.5 Compare ESP32 vs Host vs Go ✅
- [x] Run all three implementations
- [x] Compare request format
- [x] Compare response parsing
- [x] Compare extracted credentials
- [x] Verify: ESP32 produces same results as host and Go versions

**Status**: ✅ COMPLETED

---

### Phase 2: Edge Discovery ⏳

**Goal**: Discover Cloudflare edge servers via DNS SRV lookup.

#### 2.1 Instrument/Extract Go Version ⏳
- [ ] Add logging to `edgediscovery/allregions/discovery.go`
- [ ] Log: SRV query domain, SRV records (priority, weight, port, target)
- [ ] Log: Resolved IPs for each SRV target
- [ ] Log: EdgeAddr structures (TCP/UDP addresses, IP version)
- [ ] Log: Regions discovered (expect at least 2)
- [ ] Run edge discovery only (modify Go code to stop after discovery)
- [ ] Test with `dig` command to verify SRV records manually

**Status**: ⏳ IN PROGRESS

#### 2.2 Implement C++ Host Version ⏳
- [ ] DNS SRV lookup for `_v2-origintunneld._tcp.argotunnel.com`
- [ ] Implement fallback to DoT (DNS over TLS) if regular DNS fails
- [ ] Resolve returned hostnames to IP addresses (both IPv4 and IPv6)
- [ ] Create EdgeAddr structures (TCP/UDP addresses, IP version)
- [ ] Handle multiple regions (expect at least 2)
- [ ] Print discovered edge addresses

**Files to Create**:
- `components/cloudflared/src/edge_discovery.cpp/h` - DNS SRV lookup and resolution

**Status**: ⏳ PENDING

#### 2.3 Compare Host C++ vs Go ⏳
- [ ] Compare DNS queries (SRV domain, fallback behavior)
- [ ] Compare resolved IPs
- [ ] Compare edge selection logic
- [ ] Compare region handling
- [ ] Verify: Same SRV records, same IP resolution, same structure

**Status**: ⏳ PENDING

#### 2.4 Implement C++ ESP32 Version ⏳
- [ ] Use ESP-IDF DNS resolver or c-ares port
- [ ] Same DNS SRV lookup logic
- [ ] Handle ESP32 network stack

**Status**: ⏳ PENDING

#### 2.5 Compare All Versions ⏳
- [ ] Verify all three resolve to same edge addresses

**Status**: ⏳ PENDING

---

### Phase 3: QUIC Connection ⏳

**Goal**: Establish QUIC connection to Cloudflare edge with TLS.

#### 3.1 Implement C++ Host Version ⏳
- [ ] Initialize ngtcp2
- [ ] Create QUIC connection to discovered edge IP
- [ ] TLS handshake: `quic.cftunnel.com`, ALPN: `argotunnel`
- [ ] Configure QUIC parameters (packet size, timeouts)
- [ ] Test connection establishment only

**Files to Create**:
- `src/quic_connection.cpp/h` - QUIC connection management

**Status**: ⏳ PENDING

#### 3.2 Instrument/Extract Go Version ⏳
- [ ] Add logging to `connection/quic.go` and `supervisor/tunnel.go`
- [ ] Log: QUIC config, TLS handshake details, connection state
- [ ] Capture: QUIC packets, TLS negotiation

**Status**: ⏳ PENDING

#### 3.3 Compare Host C++ vs Go ⏳
- [ ] Use tshark to capture QUIC packets
- [ ] Compare: Initial packets, TLS handshake, connection parameters
- [ ] Verify: Same QUIC version, same TLS cipher suites

**Status**: ⏳ PENDING

#### 3.4 Implement C++ ESP32 Version ⏳
- [ ] Port ngtcp2 to ESP32 (or use existing port)
- [ ] Use mbedTLS instead of OpenSSL
- [ ] Same QUIC connection logic

**Status**: ⏳ PENDING

#### 3.5 Compare All Versions ⏳
- [ ] Verify all establish same QUIC connection parameters

**Status**: ⏳ PENDING

---

### Phase 4: Control Stream & Registration ⏳

**Goal**: Open control stream and register tunnel via Cap'n Proto RPC.

#### 4.1 Implement C++ Host Version ⏳
- [ ] Generate Cap'n Proto C++ code from `tunnelrpc.capnp`
- [ ] Open first stream on QUIC connection (control stream)
- [ ] Implement `RegisterConnection` RPC
- [ ] Send: TunnelAuth (accountTag + tunnelSecret), TunnelID, ConnectionOptions
- [ ] Receive: ConnectionDetails (UUID, location)
- [ ] Print registration success

**Files to Create**:
- `src/control_stream.cpp/h` - Control stream and RPC
- `proto/tunnelrpc.capnp` - Copy from Go project
- Generated Cap'n Proto code

**Status**: ⏳ PENDING

#### 4.2 Instrument/Extract Go Version ⏳
- [ ] Add logging to `connection/control.go` and `tunnelrpc/`
- [ ] Log: RPC request serialization, response deserialization
- [ ] Capture: Cap'n Proto messages on wire

**Status**: ⏳ PENDING

#### 4.3 Compare Host C++ vs Go ⏳
- [ ] Capture Cap'n Proto messages with tshark
- [ ] Compare: Message structure, serialized data
- [ ] Verify: Same RPC format, same authentication

**Status**: ⏳ PENDING

#### 4.4 Implement C++ ESP32 Version ⏳
- [ ] Same Cap'n Proto code (should work on ESP32)
- [ ] May need memory optimization
- [ ] Same RPC logic

**Status**: ⏳ PENDING

#### 4.5 Compare All Versions ⏳
- [ ] Verify all register with same credentials and receive same response

**Status**: ⏳ PENDING

---

### Phase 5: Data Stream Handler ⏳

**Goal**: Accept incoming QUIC streams and parse ConnectRequest.

#### 5.1 Implement C++ Host Version ⏳
- [ ] Accept incoming QUIC streams
- [ ] Read Cap'n Proto `ConnectRequest` from stream
- [ ] Extract metadata (HTTP method, host, headers)
- [ ] Parse request body
- [ ] Print request details (for testing, don't proxy yet)

**Files to Create**:
- `src/data_stream.cpp/h` - Data stream handling

**Status**: ⏳ PENDING

#### 5.2 Instrument/Extract Go Version ⏳
- [ ] Add logging to `connection/quic_connection.go`
- [ ] Log: Stream acceptance, ConnectRequest parsing
- [ ] Capture: Stream data, Cap'n Proto messages

**Status**: ⏳ PENDING

#### 5.3 Compare Host C++ vs Go ⏳
- [ ] Compare: Stream acceptance, ConnectRequest parsing
- [ ] Verify: Same request metadata extraction

**Status**: ⏳ PENDING

#### 5.4 Implement C++ ESP32 Version ⏳
- [ ] Same data stream logic
- [ ] Handle ESP32 memory constraints

**Status**: ⏳ PENDING

#### 5.5 Compare All Versions ⏳
- [ ] Verify all handle streams identically

**Status**: ⏳ PENDING

---

### Phase 6: HTTP Proxy to Origin ⏳

**Goal**: Proxy HTTP requests to local origin and return responses.

#### 6.1 Implement C++ Host Version ⏳
- [ ] Create HTTP client for origin (libcurl)
- [ ] Build HTTP request from ConnectRequest metadata
- [ ] Forward to local origin (localhost:8000)
- [ ] Read response
- [ ] Write response headers and body back through QUIC stream
- [ ] Test with simple HTTP server

**Files to Create**:
- `src/proxy.cpp/h` - HTTP proxying logic
- `src/http_client_origin.cpp/h` - Origin HTTP client

**Status**: ⏳ PENDING

#### 6.2 Instrument/Extract Go Version ⏳
- [ ] Add logging to `proxy/proxy.go`
- [ ] Log: Request forwarding, response handling
- [ ] Capture: HTTP requests to origin

**Status**: ⏳ PENDING

#### 6.3 Compare Host C++ vs Go ⏳
- [ ] Compare: HTTP requests to origin, response handling
- [ ] Verify: Same request format, same response forwarding

**Status**: ⏳ PENDING

#### 6.4 Implement C++ ESP32 Version ⏳
- [ ] Use esp_http_client for origin requests
- [ ] Same proxying logic
- [ ] Handle ESP32 network stack

**Status**: ⏳ PENDING

#### 6.5 Compare All Versions ⏳
- [ ] Verify all proxy requests identically

**Status**: ⏳ PENDING

---

### Phase 7: Full Integration ⏳

**Goal**: Wire all components together for complete quick tunnel.

#### 7.1 Implement C++ Host Version ⏳
- [ ] Integrate all phases in main.cpp
- [ ] Handle graceful shutdown (SIGINT/SIGTERM)
- [ ] Error handling and reconnection logic
- [ ] Test end-to-end with local HTTP server

**Status**: ⏳ PENDING

#### 7.2 Compare with Go Version ⏳
- [ ] Run both side-by-side
- [ ] Compare: Full flow, timing, behavior
- [ ] Use tshark for packet-level comparison

**Status**: ⏳ PENDING

#### 7.3 Implement C++ ESP32 Version ⏳
- [ ] Full integration on ESP32
- [ ] Handle ESP32-specific: WiFi, power management
- [ ] Test on hardware

**Status**: ⏳ PENDING

#### 7.4 Final Comparison ⏳
- [ ] All three implementations work identically
- [ ] Document any differences or limitations

**Status**: ⏳ PENDING

---

## Progress Summary

- **Phase 1**: ✅ 5/5 sub-phases completed - COMPLETED
- **Phase 2**: ⏳ 0/5 sub-phases completed
- **Phase 3**: ⏳ 0/5 sub-phases completed
- **Phase 4**: ⏳ 0/5 sub-phases completed
- **Phase 5**: ⏳ 0/5 sub-phases completed
- **Phase 6**: ⏳ 0/5 sub-phases completed
- **Phase 7**: ⏳ 0/4 sub-phases completed

**Overall Progress**: 5/34 sub-phases completed (~15%)

## Notes

- Start simple: Each phase should be minimal but correct
- Verify before moving forward: Don't proceed to next phase until current phase matches Go
- Use Go implementation as reference: It's the "source of truth"
- ESP32 constraints: May need optimizations (memory, CPU)
- Cap'n Proto on ESP32: May need to use lite mode or optimize memory usage

