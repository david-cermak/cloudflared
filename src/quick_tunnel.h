#ifndef QUICK_TUNNEL_H
#define QUICK_TUNNEL_H

#include <string>
#include <vector>
#include "http_client_host.h"

struct QuickTunnelCredentials {
    std::string id;           // Tunnel UUID
    std::vector<uint8_t> secret;  // Tunnel secret (binary)
    std::string account_tag;   // Account tag
    std::string hostname;      // Tunnel hostname (e.g., "xxx.trycloudflare.com")
};

class QuickTunnel {
public:
    QuickTunnel(const std::string& quick_service_url = "https://api.trycloudflare.com");
    
    // Request a new quick tunnel
    QuickTunnelCredentials requestTunnel();
    
private:
    std::string quick_service_url_;
    HttpClientHost http_client_;
    
    // Parse JSON response
    QuickTunnelCredentials parseResponse(const std::string& json_response);
};

#endif // QUICK_TUNNEL_H
