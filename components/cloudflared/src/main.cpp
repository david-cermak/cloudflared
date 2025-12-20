#include "quick_tunnel.h"
#include <iostream>
#include <iomanip>
#include <stdexcept>

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

int main(int argc, char* argv[]) {
    try {
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
