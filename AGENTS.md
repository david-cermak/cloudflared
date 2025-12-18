# C++ Cloudflared Quick Tunnel - Agent Documentation

## Project Overview

This project is a minimal C++ rewrite of cloudflared's quick tunnel functionality, designed to work on both host systems (Linux/Windows) and ESP32. The goal is to create a lightweight, ESP32-compatible implementation that can establish a Cloudflare tunnel connection and proxy HTTP requests.

## Original Implementation

The reference implementation is the Go version of cloudflared, located in the parent directory. Key files:
- `cmd/cloudflared/tunnel/quick_tunnel.go` - Quick tunnel request logic
- `connection/quic_connection.go` - QUIC connection handling
- `connection/control.go` - Control stream and tunnel registration
- `edgediscovery/allregions/discovery.go` - Edge server discovery
- `proxy/proxy.go` - HTTP proxying to origin

## Architecture

The implementation follows an incremental approach, building and verifying each component before moving to the next:

1. **Quick Tunnel Request** - Request tunnel credentials from trycloudflare.com
2. **Edge Discovery** - Find Cloudflare edge servers via DNS SRV lookup
3. **QUIC Connection** - Establish QUIC connection with TLS
4. **Control Stream** - Register tunnel via Cap'n Proto RPC
5. **Data Stream Handler** - Accept and parse incoming requests
6. **HTTP Proxy** - Forward requests to local origin
7. **Full Integration** - Wire everything together

## Library Choices

### HTTP Client
- **Host**: libcurl (C library, widely available)
- **ESP32**: esp_http_client (ESP-IDF native)

### JSON Parser
- **Both**: cJSON (lightweight, ESP32-friendly, single implementation)

### QUIC Library
- **Both**: ngtcp2 (C library, ESP32-compatible)
- **TLS**: OpenSSL (host) / mbedTLS (ESP32)

### RPC/Serialization
- **Both**: Cap'n Proto (C++ library, may need optimization for ESP32)

### DNS
- **Host**: System resolver (getaddrinfo) or c-ares
- **ESP32**: ESP-IDF DNS resolver or c-ares port

## Project Structure

```
cpp-cloudflared/
├── CMakeLists.txt          # Build configuration
├── README.md               # User-facing documentation
├── AGENTS.md               # This file - agent documentation
├── PLAN.md                 # Implementation plan and checklist
├── PHASE1_NOTES.md         # Phase 1 specific notes
├── test_phase1.sh          # Test script for Phase 1
├── src/
│   ├── main.cpp           # Host entry point
│   ├── quick_tunnel.cpp/h # Quick tunnel request
│   └── http_client_host.cpp/h # libcurl HTTP client
├── third_party/
│   └── cjson/             # Bundled cJSON library
└── build/                  # Build directory
```

## Development Approach

### Incremental Verification
Each phase is implemented and verified before moving to the next:
1. Implement C++ host version
2. Instrument/extract Go version for comparison
3. Compare implementations
4. Implement ESP32 version
5. Compare all versions

### Testing Strategy
- **Unit Tests**: Each component tested in isolation
- **Integration Tests**: Phases tested incrementally
- **Comparison Tests**: C++ compared with Go at each phase
- **Packet Capture**: tshark/Wireshark for protocol verification
- **ESP32 Hardware Tests**: Test on actual ESP32 hardware

## Key Learnings from Phase 1

### Quick Tunnel API
- **Endpoint**: `https://api.trycloudflare.com/tunnel`
- **Method**: POST (empty body)
- **Headers**: 
  - `Content-Type: application/json`
  - `User-Agent: <version string>`
- **Response**: JSON with structure:
  ```json
  {
    "success": true,
    "result": {
      "id": "<uuid>",
      "name": "<name>",
      "hostname": "<hostname>.trycloudflare.com",
      "account_tag": "<hex string>",
      "secret": "<base64-encoded bytes>"
    }
  }
  ```

### Implementation Details
- Secret field is base64-encoded in JSON, needs decoding to binary
- Tunnel ID is a UUID string
- Account tag is a hex string
- Hostname is the tunnel URL (without https:// prefix)

### Build System
- CMake for cross-platform builds
- cJSON bundled as subdirectory (can use system package if available)
- libcurl required for host builds
- ESP32 will use ESP-IDF component system

## Debugging and Instrumentation

### Go Version Instrumentation
Added debug logging to Go implementation:
- HTTP request/response details
- Raw JSON response body
- Parsed field values
- Environment variable `QUICK_TUNNEL_REQUEST_ONLY=1` to stop after tunnel creation

### Comparison Testing
- Run both implementations side-by-side
- Compare network traffic with tshark
- Verify JSON parsing matches
- Check extracted credentials

## Next Steps

See PLAN.md for detailed implementation checklist. Current status:
- ✅ Phase 1.1: C++ Host Version - Quick Tunnel Request
- ✅ Phase 1.2: Instrument Go Version
- ⏳ Phase 1.3: Compare Host C++ vs Go (ready for testing)
- ⏳ Phase 1.4: C++ ESP32 Version
- ⏳ Phase 1.5: Compare All Versions

## Notes for Future Development

- Keep implementations minimal but correct
- Verify before moving forward
- Use Go implementation as "source of truth"
- ESP32 constraints may require optimizations (memory, CPU)
- Cap'n Proto on ESP32 may need lite mode or memory optimization

