# C++ Cloudflared Quick Tunnel Implementation

Minimal C++ implementation of cloudflared's quick tunnel functionality, designed for both host systems (Linux/Windows) and ESP32.

## Phase 1: Quick Tunnel Request (Current)

This phase implements requesting a quick tunnel from trycloudflare.com and parsing the response.

## Dependencies

### Host (Linux/Windows)

- **libcurl**: HTTP client library
  - Ubuntu/Debian: `sudo apt install libcurl4-openssl-dev` or `libcurl4-gnutls-dev`
  - Or install via package manager for your distribution

- **cJSON**: JSON parser (bundled in `third_party/cjson/`)
  - Automatically downloaded and built if not found in system

- **CMake**: Build system (version 3.15+)
  - Ubuntu/Debian: `sudo apt install cmake build-essential`

## Building

```bash
cd cpp-cloudflared
mkdir -p build
cd build
cmake ..
make
```

## Running

```bash
./cpp-cloudflared
```

This will:
1. Request a new quick tunnel from `https://api.trycloudflare.com/tunnel`
2. Parse the JSON response
3. Display the tunnel URL and credentials
4. Exit (Phase 1.1 - tunnel request only)

## Project Structure

```
cpp-cloudflared/
├── CMakeLists.txt          # Build configuration
├── README.md               # This file
├── src/
│   ├── main.cpp           # Entry point
│   ├── quick_tunnel.cpp/h # Quick tunnel request logic
│   └── http_client_host.cpp/h # libcurl HTTP client wrapper
└── third_party/
    └── cjson/             # cJSON library (bundled)
```

## Implementation Status

- [x] Phase 1.1: C++ Host Version - Quick Tunnel Request
- [ ] Phase 1.2: Instrument/Extract Go Version
- [ ] Phase 1.3: Compare Host C++ vs Go
- [ ] Phase 1.4: C++ ESP32 Version
- [ ] Phase 1.5: Compare All Versions

## Notes

- The implementation uses libcurl for HTTP requests on host systems
- cJSON is used for JSON parsing (ESP32-compatible)
- Base64 decoding is implemented for the tunnel secret field
- The code exits after successful tunnel request (Phase 1.1 only)
