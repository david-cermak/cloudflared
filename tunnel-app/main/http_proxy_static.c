/*
 * Static-page HTTP proxy backend.
 *
 * When the origin URL is "static://", incoming requests are answered
 * with a fixed HTML page embedded in the binary.  No network I/O,
 * no external origin — ideal for ESP32 self-test and demos.
 */

#include "http_proxy_static.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "esp_log.h"

static const char *TAG = "http_static";

static const char DEFAULT_PAGE[] =
    "<!DOCTYPE html>\n"
    "<html><head><meta charset=\"utf-8\"><title>cpp-cloudflared</title></head>\n"
    "<body><h1>Hello from cpp-cloudflared</h1>\n"
    "<p>This page is served directly from the ESP32 tunnel binary.</p></body></html>\n";

static const char *s_page     = DEFAULT_PAGE;
static size_t      s_page_len = sizeof(DEFAULT_PAGE) - 1;

void http_proxy_static_set_page(const char *html, size_t len)
{
    if (html && len > 0) {
        s_page     = html;
        s_page_len = len;
    } else {
        s_page     = DEFAULT_PAGE;
        s_page_len = sizeof(DEFAULT_PAGE) - 1;
    }
}

int http_proxy_static_forward(const cf_connect_request_t *req,
                              const uint8_t *body, size_t body_len,
                              cf_http_response_t *resp)
{
    (void)body;
    (void)body_len;

    memset(resp, 0, sizeof(*resp));
    resp->status_code = 200;

    /* Content-Type */
    snprintf(resp->headers[0].key, sizeof(resp->headers[0].key), "Content-Type");
    snprintf(resp->headers[0].val, sizeof(resp->headers[0].val), "text/html; charset=utf-8");

    /* Content-Length */
    snprintf(resp->headers[1].key, sizeof(resp->headers[1].key), "Content-Length");
    snprintf(resp->headers[1].val, sizeof(resp->headers[1].val), "%zu", s_page_len);

    resp->header_count = 2;

    resp->body = malloc(s_page_len);
    if (!resp->body) {
        ESP_LOGE(TAG, "malloc failed for static page body");
        return -1;
    }
    memcpy(resp->body, s_page, s_page_len);
    resp->body_len = s_page_len;

    ESP_LOGI(TAG, "serving static page (%zu bytes) for %s", s_page_len,
             req ? req->dest : "?");
    return 0;
}
