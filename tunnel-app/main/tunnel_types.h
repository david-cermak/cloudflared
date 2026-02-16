#pragma once
/*
 * Shared type definitions for Cloudflare Tunnel components.
 * These types are used across Phase 3–7 implementations.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ── Cloudflare edge constants ─────────────────────────────────── */
#define CF_EDGE_SNI       "quic.cftunnel.com"
#define CF_EDGE_ALPN      "argotunnel"
#define CF_EDGE_SRV_HOST  "region1.v2.argotunnel.com"
#define CF_EDGE_PORT      7844

/* ── Data stream protocol constants ─────────────────────────────── */
static const uint8_t CF_DATA_STREAM_SIGNATURE[6] = {
    0x0A, 0x36, 0xCD, 0x12, 0xA1, 0x3E
};
#define CF_DATA_STREAM_VERSION "01"

static const uint8_t CF_RPC_STREAM_SIGNATURE[6] = {
    0x52, 0xBB, 0x82, 0x5C, 0xDB, 0x65
};

/* ── Tunnel credentials (Phase 1 output) ────────────────────────── */
typedef struct {
    char id[64];               /* Tunnel UUID string */
    uint8_t secret[32];        /* Tunnel secret (decoded from base64) */
    size_t secret_len;
    char account_tag[128];     /* Account tag (hex string) */
    char hostname[256];        /* Tunnel hostname (xxx.trycloudflare.com) */
} cf_tunnel_creds_t;

/* ── Edge address (Phase 2 output) ──────────────────────────────── */
typedef struct {
    char ip[64];
    uint16_t port;
    int family;                /* AF_INET or AF_INET6 */
} cf_edge_addr_t;

/* ── Tunnel authentication for registration ─────────────────────── */
typedef struct {
    const char *account_tag;
    const uint8_t *tunnel_secret;
    size_t tunnel_secret_len;
} cf_tunnel_auth_t;

/* ── Connection options for registration ────────────────────────── */
typedef struct {
    const uint8_t *client_id;     /* UUID bytes (16 bytes, can be NULL) */
    const char *version;          /* e.g. "cpp-cloudflared/0.1.0" */
    const char *arch;             /* e.g. "linux_amd64" */
    bool replace_existing;
    uint8_t compression_quality;
    uint8_t num_previous_attempts;
} cf_conn_options_t;

/* ── Registration result ────────────────────────────────────────── */
typedef struct {
    bool success;
    char uuid[64];               /* Connection UUID as hex string */
    char location[32];           /* Airport code e.g. "SJC" */
    bool tunnel_is_remote;
    /* Error fields (if !success) */
    char error[256];
    int64_t retry_after_ns;
    bool should_retry;
} cf_registration_result_t;

/* ── ConnectRequest (incoming from edge, Phase 5) ───────────────── */
typedef enum {
    CF_CONN_TYPE_HTTP      = 0,
    CF_CONN_TYPE_WEBSOCKET = 1,
    CF_CONN_TYPE_TCP       = 2,
} cf_connection_type_t;

typedef struct {
    char key[128];
    char val[512];
} cf_metadata_t;

#define CF_MAX_METADATA 32

typedef struct {
    char dest[512];
    cf_connection_type_t type;
    cf_metadata_t metadata[CF_MAX_METADATA];
    size_t metadata_count;
} cf_connect_request_t;

/* ── ConnectResponse (outgoing to edge, Phase 5) ────────────────── */
typedef struct {
    char error[256];             /* Empty string = no error */
    cf_metadata_t metadata[CF_MAX_METADATA];
    size_t metadata_count;
} cf_connect_response_t;

/* ── HTTP proxy response (Phase 6) ──────────────────────────────── */
typedef struct {
    int status_code;
    uint8_t *body;
    size_t body_len;
    cf_metadata_t headers[CF_MAX_METADATA];
    size_t header_count;
} cf_http_response_t;
