#pragma once
#include "tunnel_types.h"

/*
 * Phase 6: HTTP Proxy - Forward requests to local origin.
 *
 * When a data stream carries an HTTP request, this module:
 * 1. Extracts method, host, path, headers from ConnectRequest metadata
 * 2. Makes an HTTP request to the local origin server
 * 3. Returns the response for encoding back to the edge
 *
 * On ESP32, this would use esp_http_client.
 * On Linux host, this uses POSIX sockets for simplicity.
 */

/* Configuration for the proxy */
typedef struct {
    const char *origin_url;     /* e.g. "http://localhost:8080" */
    int connect_timeout_ms;     /* Default: 5000 */
    int read_timeout_ms;        /* Default: 30000 */
} http_proxy_config_t;

/* Initialize proxy with configuration. Returns 0 on success. */
int http_proxy_init(const http_proxy_config_t *config);

/* Forward a request to the origin and get the response.
 * Extracts HTTP method, host, path, headers from the ConnectRequest metadata.
 * The `body` and `body_len` are the raw HTTP body from the QUIC stream
 * (data received after the ConnectRequest on the same stream).
 *
 * Returns 0 on success. Caller must free resp->body if non-NULL.
 */
int http_proxy_forward(const cf_connect_request_t *req,
                       const uint8_t *body, size_t body_len,
                       cf_http_response_t *resp);

/* Free response body allocated by http_proxy_forward */
void http_proxy_free_response(cf_http_response_t *resp);

/* Cleanup proxy resources */
void http_proxy_cleanup(void);
