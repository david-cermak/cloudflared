#include "http_client_esp32.h"
#include "esp_log.h"
#include "esp_http_client.h"
#include "esp_tls.h"
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include "esp_crt_bundle.h"
#endif
#include <string>
#include <sstream>
#include <cstring>

static const char *TAG = "HTTP_CLIENT_ESP32";

// Event handler for esp_http_client
static esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    HttpResponse* response = (HttpResponse*)evt->user_data;
    
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            if (response && evt->header_key && evt->header_value) {
                response->headers.emplace_back(evt->header_key, evt->header_value);
            }
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            if (response && evt->data) {
                response->body.append((char*)evt->data, evt->data_len);
            }
            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            break;
        case HTTP_EVENT_REDIRECT:
            ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
            break;
        default:
            break;
    }
    return ESP_OK;
}

struct HttpClientEsp32::Impl {
    // No persistent state needed for ESP32 HTTP client
    // Each request creates its own client handle
};

HttpClientEsp32::HttpClientEsp32() : pImpl(new Impl()) {
}

HttpClientEsp32::~HttpClientEsp32() {
    delete pImpl;
}

HttpResponse HttpClientEsp32::post(const std::string& url,
                                   const std::string& body,
                                   const std::vector<std::pair<std::string, std::string>>& headers) {
    HttpResponse response;
    
    esp_http_client_config_t config = {};
    config.url = url.c_str();
    config.event_handler = http_event_handler;
    config.user_data = &response;
    config.timeout_ms = 10000;
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    config.crt_bundle_attach = esp_crt_bundle_attach;
#endif
    
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        throw std::runtime_error("Failed to initialize ESP HTTP client");
    }
    
    // Set method to POST
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    
    // Set headers
    for (const auto& header : headers) {
        esp_http_client_set_header(client, header.first.c_str(), header.second.c_str());
    }
    
    // Set post data
    if (!body.empty()) {
        esp_http_client_set_post_field(client, body.c_str(), body.length());
    }
    
    // Perform request
    esp_err_t err = esp_http_client_perform(client);
    
    if (err == ESP_OK) {
        response.status_code = esp_http_client_get_status_code(client);
        ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %" PRId64,
                response.status_code,
                esp_http_client_get_content_length(client));
    } else {
        esp_http_client_cleanup(client);
        throw std::runtime_error("HTTP POST request failed: " + std::string(esp_err_to_name(err)));
    }
    
    esp_http_client_cleanup(client);
    return response;
}

HttpResponse HttpClientEsp32::get(const std::string& url,
                                  const std::vector<std::pair<std::string, std::string>>& headers) {
    HttpResponse response;
    
    esp_http_client_config_t config = {};
    config.url = url.c_str();
    config.event_handler = http_event_handler;
    config.user_data = &response;
    config.timeout_ms = 10000;
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    config.crt_bundle_attach = esp_crt_bundle_attach;
#endif
    
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        throw std::runtime_error("Failed to initialize ESP HTTP client");
    }
    
    // Set method to GET (default, but explicit)
    esp_http_client_set_method(client, HTTP_METHOD_GET);
    
    // Set headers
    for (const auto& header : headers) {
        esp_http_client_set_header(client, header.first.c_str(), header.second.c_str());
    }
    
    // Perform request
    esp_err_t err = esp_http_client_perform(client);
    
    if (err == ESP_OK) {
        response.status_code = esp_http_client_get_status_code(client);
        ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %" PRId64,
                response.status_code,
                esp_http_client_get_content_length(client));
    } else {
        esp_http_client_cleanup(client);
        throw std::runtime_error("HTTP GET request failed: " + std::string(esp_err_to_name(err)));
    }
    
    esp_http_client_cleanup(client);
    return response;
}

