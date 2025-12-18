#!/bin/bash
# Test script for Phase 1: Quick Tunnel Request
# Compares C++ and Go implementations

set -e

echo "=== Phase 1.2 & 1.3: Quick Tunnel Request Comparison ==="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -f "CMakeLists.txt" ]; then
    echo "Error: Must run from cpp-cloudflared directory"
    exit 1
fi

# Build C++ version if needed
if [ ! -f "build/cpp-cloudflared" ]; then
    echo "Building C++ version..."
    mkdir -p build
    cd build
    cmake .. || {
        echo -e "${RED}CMake failed. Please install dependencies:${NC}"
        echo "  - libcurl development package (libcurl4-openssl-dev)"
        echo "  - cmake and build-essential"
        exit 1
    }
    make || {
        echo -e "${RED}Build failed${NC}"
        exit 1
    }
    cd ..
fi

echo -e "${GREEN}=== Running Go version (with debug logging) ===${NC}"
echo "Set log level to debug and QUICK_TUNNEL_REQUEST_ONLY=1"
echo "Note: Go version may not terminate automatically, use Ctrl+C if needed"
echo ""

# Find cloudflared binary (in parent directory)
CLOUDFLARED_BIN="../cloudflared"
if [ ! -f "$CLOUDFLARED_BIN" ]; then
    echo -e "${RED}Error: cloudflared binary not found at $CLOUDFLARED_BIN${NC}"
    echo "Please ensure cloudflared is built in the parent directory"
    exit 1
fi

# Run Go version with timeout (30 seconds should be enough for tunnel request)
timeout 30 bash -c "QUICK_TUNNEL_REQUEST_ONLY=1 \"$CLOUDFLARED_BIN\" tunnel --url localhost:8000 --loglevel debug" 2>&1 | tee go_output.txt || {
    # If timeout occurs, that's expected - the Go version doesn't terminate after tunnel creation
    # unless QUICK_TUNNEL_REQUEST_ONLY is properly handled
    echo -e "${YELLOW}Note: Go version may have timed out (expected behavior)${NC}"
}

echo ""
echo -e "${GREEN}=== Running C++ version ===${NC}"
echo ""
./build/cpp-cloudflared 2>&1 | tee cpp_output.txt

echo ""
echo -e "${YELLOW}=== Comparison Summary ===${NC}"
echo ""
echo "Check the output files:"
echo "  - go_output.txt: Go implementation output"
echo "  - cpp_output.txt: C++ implementation output"
echo ""
echo "Key things to compare:"
echo "  1. HTTP request URL and headers"
echo "  2. HTTP response status code"
echo "  3. JSON response body"
echo "  4. Parsed tunnel ID, account tag, hostname"
echo "  5. Secret length and first bytes"
echo ""

# Extract tunnel URLs for comparison
GO_URL=$(grep -oP 'https://[a-z0-9-]+\.trycloudflare\.com' go_output.txt | head -1 || echo "")
CPP_URL=$(grep -oP 'https://[a-z0-9-]+\.trycloudflare\.com' cpp_output.txt | head -1 || echo "")

if [ -n "$GO_URL" ] && [ -n "$CPP_URL" ]; then
    if [ "$GO_URL" = "$CPP_URL" ]; then
        echo -e "${GREEN}✓ Both implementations got the same tunnel URL${NC}"
    else
        echo -e "${YELLOW}⚠ Different tunnel URLs (expected if run at different times)${NC}"
        echo "  Go:   $GO_URL"
        echo "  C++:  $CPP_URL"
    fi
fi

echo ""
echo "For detailed network comparison, use tshark:"
echo "  sudo tshark -i any -f 'host api.trycloudflare.com' -w capture.pcap"
echo "  Then run both implementations and compare packets"



