#pragma once
#include "tunnel_types.h"

/*
 * Static-page HTTP proxy backend.
 *
 * Serves a built-in HTML page without any network I/O.
 * Activated when origin URL is "static://".
 */

/* Override the default page (NULL/0 resets to built-in default). */
void http_proxy_static_set_page(const char *html, size_t len);

/* Fulfil a request with the static page. Same signature as http_proxy_forward. */
int http_proxy_static_forward(const cf_connect_request_t *req,
                              const uint8_t *body, size_t body_len,
                              cf_http_response_t *resp);
