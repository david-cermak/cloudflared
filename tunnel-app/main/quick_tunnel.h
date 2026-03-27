#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * Quick Tunnel provisioning via api.trycloudflare.com.
 *
 * Makes an HTTPS POST to the quick-tunnel service and parses the JSON
 * response to obtain tunnel credentials.  Uses esp_http_client + cJSON,
 * so it works on both ESP32 and the Linux host target.
 *
 * TLS certificate verification is skipped (CONFIG_ESP_TLS_INSECURE)
 * to avoid bundling CA certs.
 */

#define QT_MAX_UUID_STR   48
#define QT_MAX_ACCT_TAG  128
#define QT_MAX_HOSTNAME  256
#define QT_MAX_SECRET     64

typedef struct {
    char   id[QT_MAX_UUID_STR];          /* tunnel UUID string */
    char   account_tag[QT_MAX_ACCT_TAG];
    char   hostname[QT_MAX_HOSTNAME];    /* e.g. "foo-bar.trycloudflare.com" */
    uint8_t secret[QT_MAX_SECRET];       /* decoded tunnel secret */
    size_t  secret_len;
    bool    ok;
} quick_tunnel_result_t;

/*
 * Provision a new quick tunnel.
 * Returns 0 on success (result->ok == true) or -1 on hard failure.
 */
int quick_tunnel_provision(quick_tunnel_result_t *result);
