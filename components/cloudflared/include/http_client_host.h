#ifndef HTTP_CLIENT_HOST_H
#define HTTP_CLIENT_HOST_H

#include <string>
#include <vector>
#include <memory>

struct HttpResponse {
    int status_code;
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;
};

class HttpClientHost {
public:
    HttpClientHost();
    ~HttpClientHost();

    // Perform HTTP POST request
    HttpResponse post(const std::string& url, 
                     const std::string& body = "",
                     const std::vector<std::pair<std::string, std::string>>& headers = {});

    // Perform HTTP GET request
    HttpResponse get(const std::string& url,
                     const std::vector<std::pair<std::string, std::string>>& headers = {});

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

#endif // HTTP_CLIENT_HOST_H
