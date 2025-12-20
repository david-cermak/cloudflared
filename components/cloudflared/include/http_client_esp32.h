#ifndef HTTP_CLIENT_ESP32_H
#define HTTP_CLIENT_ESP32_H

#include <string>
#include <vector>

struct HttpResponse {
    int status_code;
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;
};

class HttpClientEsp32 {
public:
    HttpClientEsp32();
    ~HttpClientEsp32();

    // Perform HTTP POST request
    HttpResponse post(const std::string& url, 
                     const std::string& body = "",
                     const std::vector<std::pair<std::string, std::string>>& headers = {});

    // Perform HTTP GET request
    HttpResponse get(const std::string& url,
                     const std::vector<std::pair<std::string, std::string>>& headers = {});

private:
    class Impl;
    class Impl* pImpl;
};

#endif // HTTP_CLIENT_ESP32_H

