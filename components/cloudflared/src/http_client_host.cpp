#include "http_client_host.h"
#include <curl/curl.h>
#include <sstream>
#include <iostream>

struct HttpClientHost::Impl {
    CURL* curl;
    
    Impl() {
        curl = curl_easy_init();
        if (!curl) {
            throw std::runtime_error("Failed to initialize libcurl");
        }
    }
    
    ~Impl() {
        if (curl) {
            curl_easy_cleanup(curl);
        }
    }
};

// Callback function to write response data
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* data) {
    size_t total_size = size * nmemb;
    data->append((char*)contents, total_size);
    return total_size;
}

// Callback function to write response headers
static size_t HeaderCallback(char* buffer, size_t size, size_t nitems, std::vector<std::pair<std::string, std::string>>* headers) {
    size_t total_size = size * nitems;
    std::string header_line(buffer, total_size);
    
    // Remove trailing newline/carriage return
    if (!header_line.empty() && header_line.back() == '\n') {
        header_line.pop_back();
    }
    if (!header_line.empty() && header_line.back() == '\r') {
        header_line.pop_back();
    }
    
    // Parse header (format: "Name: Value")
    size_t colon_pos = header_line.find(':');
    if (colon_pos != std::string::npos) {
        std::string name = header_line.substr(0, colon_pos);
        std::string value = header_line.substr(colon_pos + 1);
        
        // Trim whitespace
        name.erase(0, name.find_first_not_of(" \t"));
        name.erase(name.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);
        
        if (!name.empty()) {
            headers->emplace_back(name, value);
        }
    }
    
    return total_size;
}

HttpClientHost::HttpClientHost() : pImpl(std::make_unique<Impl>()) {
    // Initialize libcurl globally (thread-safe in modern versions)
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

HttpClientHost::~HttpClientHost() {
    // Cleanup libcurl globally
    curl_global_cleanup();
}

HttpResponse HttpClientHost::post(const std::string& url,
                                  const std::string& body,
                                  const std::vector<std::pair<std::string, std::string>>& headers) {
    HttpResponse response;
    std::string response_body;
    std::vector<std::pair<std::string, std::string>> response_headers;
    
    CURL* curl = pImpl->curl;
    
    // Reset curl handle
    curl_easy_reset(curl);
    
    // Set URL
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    
    // Set POST method
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    
    // Set write callback
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
    
    // Set header callback
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response_headers);
    
    // Build custom headers
    struct curl_slist* curl_headers = nullptr;
    for (const auto& header : headers) {
        std::string header_str = header.first + ": " + header.second;
        curl_headers = curl_slist_append(curl_headers, header_str.c_str());
    }
    if (curl_headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
    }
    
    // SSL options
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    // Follow redirects
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    // Perform request
    CURLcode res = curl_easy_perform(curl);
    
    // Clean up headers
    if (curl_headers) {
        curl_slist_free_all(curl_headers);
    }
    
    if (res != CURLE_OK) {
        throw std::runtime_error("curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));
    }
    
    // Get status code
    long status_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    response.status_code = static_cast<int>(status_code);
    response.body = response_body;
    response.headers = response_headers;
    
    return response;
}

HttpResponse HttpClientHost::get(const std::string& url,
                                 const std::vector<std::pair<std::string, std::string>>& headers) {
    HttpResponse response;
    std::string response_body;
    std::vector<std::pair<std::string, std::string>> response_headers;
    
    CURL* curl = pImpl->curl;
    
    // Reset curl handle
    curl_easy_reset(curl);
    
    // Set URL
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    
    // Set GET method (default)
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    
    // Set write callback
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
    
    // Set header callback
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response_headers);
    
    // Build custom headers
    struct curl_slist* curl_headers = nullptr;
    for (const auto& header : headers) {
        std::string header_str = header.first + ": " + header.second;
        curl_headers = curl_slist_append(curl_headers, header_str.c_str());
    }
    if (curl_headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
    }
    
    // SSL options
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    // Follow redirects
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    // Perform request
    CURLcode res = curl_easy_perform(curl);
    
    // Clean up headers
    if (curl_headers) {
        curl_slist_free_all(curl_headers);
    }
    
    if (res != CURLE_OK) {
        throw std::runtime_error("curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));
    }
    
    // Get status code
    long status_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    response.status_code = static_cast<int>(status_code);
    response.body = response_body;
    response.headers = response_headers;
    
    return response;
}
