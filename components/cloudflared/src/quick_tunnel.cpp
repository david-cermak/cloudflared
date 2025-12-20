#include <quick_tunnel.h>
#include <cJSON.h>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <algorithm>

#if defined(ESP_PLATFORM) || defined(ESP_IDF_VERSION)
#include "esp_log.h"
#define QUICK_TUNNEL_TAG "QUICK_TUNNEL"
#else
#include <iostream>
#endif

// Base64 decoding helper (simple implementation)
static std::vector<uint8_t> base64_decode(const std::string& encoded) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> result;
    int val = 0, valb = -8;
    
    for (unsigned char c : encoded) {
        if (c == '=') break;
        if (c == ' ' || c == '\n' || c == '\r') continue;
        
        size_t pos = chars.find(c);
        if (pos == std::string::npos) {
            throw std::runtime_error("Invalid base64 character");
        }
        
        val = (val << 6) + pos;
        valb += 6;
        
        if (valb >= 0) {
            result.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    
    return result;
}

QuickTunnel::QuickTunnel(const std::string& quick_service_url)
    : quick_service_url_(quick_service_url) {
}

QuickTunnelCredentials QuickTunnel::requestTunnel() {
    std::string url = quick_service_url_ + "/tunnel";
    
    // Prepare headers
    std::vector<std::pair<std::string, std::string>> headers;
    headers.emplace_back("Content-Type", "application/json");
    headers.emplace_back("User-Agent", "cpp-cloudflared/0.1.0");
    
    // Make POST request (empty body for quick tunnel)
    HttpResponse response = http_client_.post(url, "", headers);
    
    if (response.status_code != 200) {
        std::string error_msg = "Quick tunnel request failed with status code: " + 
                                std::to_string(response.status_code) + 
                                ", response: " + response.body;
#ifdef ESP_PLATFORM
        ESP_LOGE(QUICK_TUNNEL_TAG, "%s", error_msg.c_str());
#else
        std::cerr << error_msg << std::endl;
#endif
        throw std::runtime_error(error_msg);
    }
    
    // Parse JSON response
    return parseResponse(response.body);
}

QuickTunnelCredentials QuickTunnel::parseResponse(const std::string& json_response) {
    QuickTunnelCredentials creds;
    
    cJSON* json = cJSON_Parse(json_response.c_str());
    if (!json) {
        const char* error_ptr = cJSON_GetErrorPtr();
        std::string error_msg = error_ptr != nullptr ? 
            ("JSON parse error: " + std::string(error_ptr)) : 
            "JSON parse error: unknown";
#ifdef ESP_PLATFORM
        ESP_LOGE(QUICK_TUNNEL_TAG, "%s", error_msg.c_str());
#else
        std::cerr << error_msg << std::endl;
#endif
        throw std::runtime_error(error_msg);
    }
    
    // Check for success field
    cJSON* success = cJSON_GetObjectItemCaseSensitive(json, "success");
    if (cJSON_IsBool(success) && !cJSON_IsTrue(success)) {
        cJSON_Delete(json);
        std::string error_msg = "Quick tunnel request was not successful";
#ifdef ESP_PLATFORM
        ESP_LOGE(QUICK_TUNNEL_TAG, "%s", error_msg.c_str());
#endif
        throw std::runtime_error(error_msg);
    }
    
    // Get result object
    cJSON* result = cJSON_GetObjectItemCaseSensitive(json, "result");
    if (!cJSON_IsObject(result)) {
        cJSON_Delete(json);
        std::string error_msg = "JSON response missing 'result' object";
#ifdef ESP_PLATFORM
        ESP_LOGE(QUICK_TUNNEL_TAG, "%s", error_msg.c_str());
#endif
        throw std::runtime_error(error_msg);
    }
    
    // Extract id
    cJSON* id = cJSON_GetObjectItemCaseSensitive(result, "id");
    if (cJSON_IsString(id) && id->valuestring != nullptr) {
        creds.id = id->valuestring;
    } else {
        cJSON_Delete(json);
        std::string error_msg = "JSON response missing or invalid 'id' field";
#ifdef ESP_PLATFORM
        ESP_LOGE(QUICK_TUNNEL_TAG, "%s", error_msg.c_str());
#endif
        throw std::runtime_error(error_msg);
    }
    
    // Extract secret (base64 encoded string in JSON, decode to binary)
    cJSON* secret = cJSON_GetObjectItemCaseSensitive(result, "secret");
    if (cJSON_IsString(secret) && secret->valuestring != nullptr) {
        // The secret is base64 encoded in the JSON response
        // Decode it to binary
        std::string secret_str = secret->valuestring;
        try {
            creds.secret = base64_decode(secret_str);
        } catch (const std::exception& e) {
            cJSON_Delete(json);
            std::string error_msg = "Failed to decode secret from base64: " + std::string(e.what());
#ifdef ESP_PLATFORM
            ESP_LOGE(QUICK_TUNNEL_TAG, "%s", error_msg.c_str());
#endif
            throw std::runtime_error(error_msg);
        }
    } else {
        cJSON_Delete(json);
        std::string error_msg = "JSON response missing or invalid 'secret' field";
#ifdef ESP_PLATFORM
        ESP_LOGE(QUICK_TUNNEL_TAG, "%s", error_msg.c_str());
#endif
        throw std::runtime_error(error_msg);
    }
    
    // Extract account_tag
    cJSON* account_tag = cJSON_GetObjectItemCaseSensitive(result, "account_tag");
    if (cJSON_IsString(account_tag) && account_tag->valuestring != nullptr) {
        creds.account_tag = account_tag->valuestring;
    } else {
        cJSON_Delete(json);
        std::string error_msg = "JSON response missing or invalid 'account_tag' field";
#ifdef ESP_PLATFORM
        ESP_LOGE(QUICK_TUNNEL_TAG, "%s", error_msg.c_str());
#endif
        throw std::runtime_error(error_msg);
    }
    
    // Extract hostname
    cJSON* hostname = cJSON_GetObjectItemCaseSensitive(result, "hostname");
    if (cJSON_IsString(hostname) && hostname->valuestring != nullptr) {
        creds.hostname = hostname->valuestring;
    } else {
        cJSON_Delete(json);
        std::string error_msg = "JSON response missing or invalid 'hostname' field";
#ifdef ESP_PLATFORM
        ESP_LOGE(QUICK_TUNNEL_TAG, "%s", error_msg.c_str());
#endif
        throw std::runtime_error(error_msg);
    }
    
    cJSON_Delete(json);
    return creds;
}
