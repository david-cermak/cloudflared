#include "quick_tunnel.h"
#include "edge_discovery.h"
#ifdef NGTCP2_FOUND
#include "quic_client.h"
#endif
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <string>

void printTunnelInfo(const QuickTunnelCredentials& creds) {
    std::cout << "\n";
    std::cout << "+--------------------------------------------------------------------------------------------+\n";
    std::cout << "|  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |\n";
    std::cout << "|  https://" << creds.hostname << std::string(75 - creds.hostname.length(), ' ') << "|\n";
    std::cout << "+--------------------------------------------------------------------------------------------+\n";
    std::cout << "\n";
    
    std::cout << "Tunnel ID: " << creds.id << "\n";
    std::cout << "Account Tag: " << creds.account_tag << "\n";
    std::cout << "Secret length: " << creds.secret.size() << " bytes\n";
    
    // Print secret as hex for debugging (first 16 bytes)
    if (!creds.secret.empty()) {
        std::cout << "Secret (first 16 bytes, hex): ";
        size_t print_len = std::min(creds.secret.size(), size_t(16));
        for (size_t i = 0; i < print_len; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(creds.secret[i]);
        }
        std::cout << std::dec << "\n";
    }
}

static void printEdgeDiscovery(const std::vector<std::vector<EdgeAddr>>& groups) {
    std::cout << "\n";
    std::cout << "Discovered " << groups.size() << " SRV groups (Go uses the first 2 as regions)\n";
    for (size_t group = 0; group < groups.size(); ++group) {
        std::cout << "\n";
        std::cout << "SRV group " << group << ":\n";
        for (const auto& addr : groups[group]) {
            const char* v = (addr.ip_version == EdgeIPVersion::V4) ? "4" : "6";
            std::cout << "  - " << addr.ip << ":" << addr.port << " (IP" << v << ")\n";
        }
    }
    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    try {
        // Phase selection:
        // - default: Phase 1 (quick tunnel request only)
        // - --phase2 [region]: Phase 2 (edge discovery DNS only)
        // - --phase3 [test_server]: Phase 3 (QUIC connection test)
        if (argc > 1 && std::string(argv[1]) == "--phase2") {
            std::string region;
            if (argc > 2) {
                region = argv[2];
            }

            std::cout << "Running Phase 2 (Edge Discovery DNS SRV lookup)";
            if (!region.empty()) {
                std::cout << " for region '" << region << "'";
            }
            std::cout << "...\n";

            EdgeDiscovery discovery;
            auto groups = discovery.ResolveEdgeAddrs(region, ConfigIPVersion::Auto);
            printEdgeDiscovery(groups);

            std::cout << "Edge discovery completed successfully.\n";
            std::cout << "Exiting (Phase 2 - DNS only).\n";
            return 0;
        }

#ifdef NGTCP2_FOUND
        if (argc > 1 && std::string(argv[1]) == "--phase3") {
            std::string test_server = "cloudflare-quic.com";
            uint16_t port = 443;
            
            if (argc > 2) {
                test_server = argv[2];
            }
            if (argc > 3) {
                port = static_cast<uint16_t>(std::stoi(argv[3]));
            }

            std::cout << "Running Phase 3 (QUIC Connection Test)\n";
            std::cout << "Connecting to: " << test_server << ":" << port << "\n";
            std::cout << "\n";

            QuicConnectionResult result = QuicClient::ConnectToTestServer(test_server, port);
            
            if (result.success) {
                std::cout << "\n";
                std::cout << "+--------------------------------------------------------------------------------------------+\n";
                std::cout << "|  QUIC connection test completed successfully!                                              |\n";
                std::cout << "+--------------------------------------------------------------------------------------------+\n";
                std::cout << "\n";
                std::cout << "Server: " << result.server_name << ":" << result.port << "\n";
                std::cout << "Status: " << result.error_message << "\n";
                std::cout << "\n";
                std::cout << "Exiting (Phase 3 - QUIC test).\n";
                return 0;
            } else {
                std::cerr << "\n";
                std::cerr << "QUIC connection test failed:\n";
                std::cerr << "  Error: " << result.error_message << "\n";
                std::cerr << "\n";
                return 1;
            }
        }
#else
        if (argc > 1 && std::string(argv[1]) == "--phase3") {
            std::cerr << "Error: QUIC support not available (ngtcp2 not found)\n";
            std::cerr << "Please install libngtcp2-dev or build ngtcp2 from source\n";
            return 1;
        }
#endif

        std::string quick_service = "https://api.trycloudflare.com";
        
        // Parse command line arguments (optional quick-service URL)
        if (argc > 1) {
            quick_service = argv[1];
        }
        
        std::cout << "Requesting new quick Tunnel on " << quick_service << "...\n";
        
        QuickTunnel tunnel(quick_service);
        QuickTunnelCredentials creds = tunnel.requestTunnel();
        
        printTunnelInfo(creds);
        
        std::cout << "Quick tunnel request completed successfully.\n";
        std::cout << "Exiting (Phase 1.1 - tunnel request only).\n";
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
