/*
 * Phase 7: Integration main entry point for the Cloudflare Tunnel.
 *
 * Wires together all phases:
 *   Phase 3 — QUIC connection to Cloudflare edge (quic_tunnel)
 *   Phase 4 — Control stream registration (control_stream)
 *   Phase 5 — Data stream handling (data_stream)
 *   Phase 6 — HTTP proxy forwarding (http_proxy)
 *
 * Supports two modes:
 *   - "phase3" (default): Connect and verify QUIC handshake only
 *   - "full": Full tunnel with control stream registration and proxying
 *
 * On the ESP-IDF linux host target, mode/edge/port can be set via
 * environment variables CF_MODE, CF_EDGE, CF_PORT.
 *
 * Full mode requires:
 *   CF_TUNNEL_ID       — Tunnel UUID (hex string, 32 chars or with dashes)
 *   CF_ACCOUNT_TAG     — Account tag
 *   CF_TUNNEL_SECRET   — Base64-encoded tunnel secret
 *   CF_ORIGIN_URL      — Local origin URL (e.g. http://localhost:8080)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>

#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_random.h"

#include "tunnel_types.h"
#include "quic_tunnel.h"
#include "http_proxy.h"
#include "control_stream.h"
#include "data_stream.h"
#include "capnp_minimal.h"

static const char *TAG = "cf_tunnel";

/* ── Base64 decoder (minimal, for tunnel secret) ─────────────────── */

static const uint8_t b64_table[256] = {
    ['A']=0,  ['B']=1,  ['C']=2,  ['D']=3,  ['E']=4,  ['F']=5,
    ['G']=6,  ['H']=7,  ['I']=8,  ['J']=9,  ['K']=10, ['L']=11,
    ['M']=12, ['N']=13, ['O']=14, ['P']=15, ['Q']=16, ['R']=17,
    ['S']=18, ['T']=19, ['U']=20, ['V']=21, ['W']=22, ['X']=23,
    ['Y']=24, ['Z']=25,
    ['a']=26, ['b']=27, ['c']=28, ['d']=29, ['e']=30, ['f']=31,
    ['g']=32, ['h']=33, ['i']=34, ['j']=35, ['k']=36, ['l']=37,
    ['m']=38, ['n']=39, ['o']=40, ['p']=41, ['q']=42, ['r']=43,
    ['s']=44, ['t']=45, ['u']=46, ['v']=47, ['w']=48, ['x']=49,
    ['y']=50, ['z']=51,
    ['0']=52, ['1']=53, ['2']=54, ['3']=55, ['4']=56, ['5']=57,
    ['6']=58, ['7']=59, ['8']=60, ['9']=61,
    ['+']=62, ['/']=63,
};

static int base64_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t in_len = strlen(in);
    size_t i = 0, o = 0;

    while (i < in_len) {
        /* Skip whitespace */
        while (i < in_len && (in[i] == '\n' || in[i] == '\r' || in[i] == ' '))
            i++;
        if (i >= in_len) break;

        uint32_t sextet[4] = {0};
        int pad = 0;
        for (int j = 0; j < 4 && i < in_len; j++, i++) {
            if (in[i] == '=') { pad++; sextet[j] = 0; }
            else sextet[j] = b64_table[(uint8_t)in[i]];
        }

        uint32_t triple = (sextet[0] << 18) | (sextet[1] << 12) |
                           (sextet[2] << 6)  | sextet[3];

        if (o < out_cap) out[o++] = (uint8_t)(triple >> 16);
        if (pad < 2 && o < out_cap) out[o++] = (uint8_t)(triple >> 8);
        if (pad < 1 && o < out_cap) out[o++] = (uint8_t)(triple);
    }
    *out_len = o;
    return 0;
}

/* ── UUID parser (hex string to 16 bytes) ────────────────────────── */

static int parse_uuid(const char *str, uint8_t out[16])
{
    uint8_t buf[16];
    int bi = 0;

    for (int i = 0; str[i] && bi < 16; i++) {
        if (str[i] == '-') continue;
        if (!isxdigit((unsigned char)str[i]) ||
            !isxdigit((unsigned char)str[i + 1])) {
            return -1;
        }
        unsigned int val;
        sscanf(str + i, "%2x", &val);
        buf[bi++] = (uint8_t)val;
        i++; /* skip second hex char (loop will also increment) */
    }

    if (bi != 16) return -1;
    memcpy(out, buf, 16);
    return 0;
}

/* ── Phase 3 test mode ─────────────────────────────────────────────── */

static int phase3_test(const char *edge_server, uint16_t port);

static int phase3_event_cb(quic_tunnel_ctx_t *ctx, qt_event_t event,
                           uint64_t stream_id, const uint8_t *data, size_t len,
                           void *user_data)
{
    (void)stream_id; (void)data; (void)len; (void)user_data;

    switch (event) {
    case QT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "=== PHASE 3 SUCCESS: QUIC handshake completed! ===");
        quic_tunnel_close(ctx);
        return 0;
    case QT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "Disconnected from edge");
        return 0;
    default:
        return 0;
    }
}

static int phase3_test(const char *edge_server, uint16_t port)
{
    ESP_LOGI(TAG, "=== Phase 3 Test: QUIC handshake to %s:%u ===", edge_server, port);

    quic_tunnel_ctx_t ctx = {0};
    quic_tunnel_config_t config = {
        .edge_server = edge_server,
        .edge_port = port,
        .event_cb = phase3_event_cb,
        .user_data = NULL,
    };

    int ret = quic_tunnel_connect(&ctx, &config);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to initiate connection: %d", ret);
        return ret;
    }

    ret = quic_tunnel_run(&ctx);
    ESP_LOGI(TAG, "Packet loop exited: %d", ret);

    quic_tunnel_free(&ctx);
    return 0;
}

/* ── Full tunnel mode ──────────────────────────────────────────────── */

typedef struct {
    /* Phase 4: Control stream */
    bool registered;
    bool registration_sent;
    uint64_t control_stream_id;
    size_t ctrl_parsed_offset; /* bytes consumed from control stream recv_buf */

    /* Phase 1: Credentials (pointers to static/env data) */
    cf_tunnel_auth_t auth;
    uint8_t tunnel_id_bytes[16];
    uint8_t tunnel_secret[64];
    size_t tunnel_secret_len;
    char account_tag[128];
    cf_conn_options_t conn_options;

    /* Phase 6: Origin URL */
    const char *origin_url;
} tunnel_state_t;

static void try_handle_data_stream(quic_tunnel_ctx_t *ctx,
                                   uint64_t stream_id,
                                   tunnel_state_t *state);

/*
 * Try to parse Cap'n Proto RPC messages from the control stream's recv_buf.
 * The control stream stays open (no FIN), so we parse messages incrementally
 * as data arrives. We track how many bytes we've consumed in ctrl_parsed_offset.
 *
 * Expected messages:
 *   1. Return for Bootstrap (questionId=0) — we skip this
 *   2. Return for Call (questionId=1)     — this has the registration result
 */
static void try_parse_control_messages(quic_tunnel_ctx_t *ctx,
                                       tunnel_state_t *state)
{
    stream_ctx_t *sc = quic_tunnel_find_stream(ctx, state->control_stream_id);
    if (!sc || !sc->recv_buf) return;

    while (state->ctrl_parsed_offset < sc->recv_len) {
        const uint8_t *buf = sc->recv_buf + state->ctrl_parsed_offset;
        size_t remaining = sc->recv_len - state->ctrl_parsed_offset;

        /* Check if we have a complete capnp message */
        size_t msg_size = capnp_wire_message_size(buf, remaining);
        if (msg_size == 0) {
            /* Not enough data yet */
            break;
        }

        ESP_LOGD(TAG, "Control stream: parsing message at offset %zu (%zu bytes)",
                 state->ctrl_parsed_offset, msg_size);

        /* Try to decode as registration response */
        cf_registration_result_t result = {0};
        int ret = control_stream_decode_response(buf, msg_size, &result);

        if (ret == 0 && result.success) {
            state->registered = true;
            ESP_LOGI(TAG, "=== REGISTRATION SUCCESS ===");
            ESP_LOGI(TAG, "  Connection UUID: %s", result.uuid);
            ESP_LOGI(TAG, "  Location: %s", result.location);
            ESP_LOGI(TAG, "  Remote managed: %s",
                     result.tunnel_is_remote ? "yes" : "no");
            ESP_LOGI(TAG, "Tunnel is ready, waiting for requests...");
        } else if (ret == 0 && result.error[0]) {
            /* Got a response but it's an error */
            ESP_LOGE(TAG, "=== REGISTRATION FAILED ===");
            ESP_LOGE(TAG, "  Error: %s", result.error);
            ESP_LOGE(TAG, "  Retry: %s (after %" PRId64 " ns)",
                     result.should_retry ? "yes" : "no",
                     result.retry_after_ns);
            quic_tunnel_close(ctx);
        } else if (ret != 0) {
            /* Not a Return message (could be Bootstrap response) - skip it */
            ESP_LOGI(TAG, "Control stream: skipping non-Return message at offset %zu",
                     state->ctrl_parsed_offset);
        }

        state->ctrl_parsed_offset += msg_size;
    }
}

static int full_tunnel_event_cb(quic_tunnel_ctx_t *ctx, qt_event_t event,
                                uint64_t stream_id, const uint8_t *data, size_t len,
                                void *user_data)
{
    tunnel_state_t *state = (tunnel_state_t *)user_data;

    switch (event) {
    case QT_EVENT_CONNECTED: {
        ESP_LOGI(TAG, "Connected to edge, opening control stream...");

        /* Open bidi control stream (first client-initiated stream = 0) */
        state->control_stream_id = quic_tunnel_open_stream(ctx, true);
        if (state->control_stream_id == UINT64_MAX) {
            ESP_LOGE(TAG, "Failed to open control stream");
            quic_tunnel_close(ctx);
            return 0;
        }
        ESP_LOGI(TAG, "Control stream opened: %" PRIu64, state->control_stream_id);

        /* Phase 4: Encode and send RegisterConnection RPC */
        uint8_t reg_buf[4096];
        size_t reg_len = 0;

        int ret = control_stream_encode_register(
            &state->auth,
            state->tunnel_id_bytes, 16,
            0, /* connIndex = 0 */
            &state->conn_options,
            reg_buf, sizeof(reg_buf), &reg_len);

        if (ret != 0) {
            ESP_LOGE(TAG, "Failed to encode RegisterConnection");
            quic_tunnel_close(ctx);
            return 0;
        }

        ESP_LOGI(TAG, "Sending RegisterConnection (%zu bytes) on stream %" PRIu64,
                 reg_len, state->control_stream_id);

        ret = quic_tunnel_send(ctx, state->control_stream_id,
                               reg_buf, reg_len, false);
        if (ret != 0) {
            ESP_LOGE(TAG, "Failed to send RegisterConnection");
            quic_tunnel_close(ctx);
            return 0;
        }
        state->registration_sent = true;
        return 0;
    }

    case QT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "Disconnected from edge");
        return 0;

    case QT_EVENT_STREAM_OPENED_REMOTE:
        ESP_LOGI(TAG, "Edge opened data stream %" PRIu64, stream_id);
        return 0;

    case QT_EVENT_STREAM_DATA:
        if (stream_id == state->control_stream_id) {
            ESP_LOGI(TAG, "Control stream data: %zu new bytes", len);
            /* Try to parse complete messages from accumulated buffer */
            try_parse_control_messages(ctx, state);
        } else {
            /* Phase 5+6: Try to handle data stream as soon as we have a
             * complete ConnectRequest. Don't wait for FIN — the edge keeps
             * the stream open bidirectionally. */
            try_handle_data_stream(ctx, stream_id, state);
        }
        return 0;

    case QT_EVENT_STREAM_FIN:
        if (stream_id == state->control_stream_id) {
            ESP_LOGI(TAG, "Control stream FIN (unexpected), parsing remaining...");
            try_parse_control_messages(ctx, state);
        } else {
            /* Data stream FIN: try to handle if not yet done */
            try_handle_data_stream(ctx, stream_id, state);
        }
        return 0;

    default:
        return 0;
    }
}

/*
 * Try to process a data stream from the edge.
 *
 * Called on every QT_EVENT_STREAM_DATA and QT_EVENT_STREAM_FIN.
 * The edge does NOT send FIN after the ConnectRequest for bidirectional
 * streams, so we process as soon as we have a complete message.
 *
 * The accumulated buffer contains:
 *   [6-byte signature][2-byte version][Cap'n Proto ConnectRequest][HTTP body...]
 *
 * We parse the ConnectRequest, proxy to the local origin, build a
 * ConnectResponse, and send it back on the same stream with FIN.
 */
static void try_handle_data_stream(quic_tunnel_ctx_t *ctx,
                                   uint64_t stream_id,
                                   tunnel_state_t *state)
{
    (void)state;

    stream_ctx_t *sc = quic_tunnel_find_stream(ctx, stream_id);
    if (!sc || sc->request_handled) {
        return; /* Already processed or no context */
    }

    /* Check if we have enough data for the preamble + capnp message */
    size_t req_hdr_size = data_stream_request_size(sc->recv_buf, sc->recv_len);
    if (req_hdr_size == 0) {
        return; /* Not enough data yet */
    }

    /* Mark as handled so we don't process the same stream twice */
    sc->request_handled = true;

    ESP_LOGI(TAG, "Processing data stream %" PRIu64 " (%zu bytes received, hdr=%zu)",
             stream_id, sc->recv_len, req_hdr_size);

    /* Parse ConnectRequest from the accumulated buffer */
    cf_connect_request_t req = {0};
    int ret = data_stream_parse_request(sc->recv_buf, sc->recv_len, &req);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to parse ConnectRequest on stream %" PRIu64, stream_id);
        for (size_t i = 0; i < sc->recv_len && i < 32; i++) {
            printf("%02x ", sc->recv_buf[i]);
        }
        if (sc->recv_len > 0) printf("\n");
        return;
    }

    const char *method = data_stream_get_method(&req);
    const char *host = data_stream_get_host(&req);
    ESP_LOGI(TAG, "  Request: %s %s (host=%s, type=%d, %zu metadata)",
             method ? method : "?",
             req.dest,
             host ? host : "?",
             (int)req.type,
             req.metadata_count);

    /* Body starts after the preamble + capnp message */
    const uint8_t *body = NULL;
    size_t body_len = 0;
    if (req_hdr_size < sc->recv_len) {
        body = sc->recv_buf + req_hdr_size;
        body_len = sc->recv_len - req_hdr_size;
        ESP_LOGI(TAG, "  Request body: %zu bytes", body_len);
    }

    /* Phase 6: Proxy to origin */
    cf_http_response_t http_resp = {0};
    ret = http_proxy_forward(&req, body, body_len, &http_resp);
    if (ret != 0) {
        ESP_LOGE(TAG, "HTTP proxy forward failed");
        http_resp.status_code = 502;
    }

    ESP_LOGI(TAG, "  Origin response: %d (%zu bytes body, %zu headers)",
             http_resp.status_code, http_resp.body_len, http_resp.header_count);

    /* Phase 5: Build ConnectResponse with HTTP metadata */
    cf_connect_response_t connect_resp = {0};
    data_stream_build_http_metadata(http_resp.status_code,
                                    http_resp.headers,
                                    http_resp.header_count,
                                    &connect_resp);

    /* Encode the ConnectResponse wire message */
    uint8_t resp_buf[4096];
    size_t resp_len = 0;
    ret = data_stream_build_response(&connect_resp, resp_buf,
                                     sizeof(resp_buf), &resp_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to build ConnectResponse");
        http_proxy_free_response(&http_resp);
        return;
    }

    /* Send ConnectResponse header */
    ESP_LOGI(TAG, "  Sending ConnectResponse: %zu bytes", resp_len);
    ret = quic_tunnel_send(ctx, stream_id, resp_buf, resp_len, false);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to send ConnectResponse header");
        http_proxy_free_response(&http_resp);
        return;
    }

    /* Send response body and FIN */
    if (http_resp.body && http_resp.body_len > 0) {
        ESP_LOGI(TAG, "  Sending response body: %zu bytes + FIN", http_resp.body_len);
        ret = quic_tunnel_send(ctx, stream_id,
                               http_resp.body, http_resp.body_len, true);
    } else {
        ESP_LOGI(TAG, "  Sending FIN (no body)");
        ret = quic_tunnel_send(ctx, stream_id, NULL, 0, true);
    }

    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to send response body/FIN");
    }

    http_proxy_free_response(&http_resp);
}

static int full_tunnel(const char *edge_server, uint16_t port)
{
    ESP_LOGI(TAG, "=== Full Tunnel: %s:%u ===", edge_server, port);

    /* Read credentials from environment variables */
    const char *tunnel_id_str = getenv("CF_TUNNEL_ID");
    const char *account_tag = getenv("CF_ACCOUNT_TAG");
    const char *secret_b64 = getenv("CF_TUNNEL_SECRET");
    const char *origin_url = getenv("CF_ORIGIN_URL");

    if (!tunnel_id_str || !account_tag || !secret_b64) {
        ESP_LOGE(TAG, "Missing required environment variables:");
        ESP_LOGE(TAG, "  CF_TUNNEL_ID=%s", tunnel_id_str ? tunnel_id_str : "(unset)");
        ESP_LOGE(TAG, "  CF_ACCOUNT_TAG=%s", account_tag ? account_tag : "(unset)");
        ESP_LOGE(TAG, "  CF_TUNNEL_SECRET=%s", secret_b64 ? "(set)" : "(unset)");
        return -1;
    }
    if (!origin_url || !origin_url[0]) {
        origin_url = "http://localhost:8080";
    }

    /* Initialize state */
    tunnel_state_t state = {0};
    state.origin_url = origin_url;

    /* Parse tunnel UUID */
    if (parse_uuid(tunnel_id_str, state.tunnel_id_bytes) != 0) {
        ESP_LOGE(TAG, "Failed to parse CF_TUNNEL_ID: %s", tunnel_id_str);
        return -1;
    }
    ESP_LOGI(TAG, "Tunnel ID: %s", tunnel_id_str);

    /* Copy account tag */
    snprintf(state.account_tag, sizeof(state.account_tag), "%s", account_tag);
    ESP_LOGI(TAG, "Account tag: %s", state.account_tag);

    /* Base64 decode tunnel secret */
    if (base64_decode(secret_b64, state.tunnel_secret,
                      sizeof(state.tunnel_secret),
                      &state.tunnel_secret_len) != 0) {
        ESP_LOGE(TAG, "Failed to decode CF_TUNNEL_SECRET");
        return -1;
    }
    ESP_LOGI(TAG, "Tunnel secret: %zu bytes", state.tunnel_secret_len);

    /* Set up auth and options */
    state.auth.account_tag = state.account_tag;
    state.auth.tunnel_secret = state.tunnel_secret;
    state.auth.tunnel_secret_len = state.tunnel_secret_len;

    /* Generate a client ID (UUID v4) using ESP-IDF's HW RNG */
    static uint8_t client_uuid[16];
    esp_fill_random(client_uuid, sizeof(client_uuid));
    client_uuid[6] = (client_uuid[6] & 0x0F) | 0x40; /* version 4 */
    client_uuid[8] = (client_uuid[8] & 0x3F) | 0x80; /* variant 1 */

    state.conn_options.client_id = client_uuid;
    state.conn_options.version = "cpp-cloudflared/0.1.0";
    state.conn_options.arch = "linux_amd64";
    state.conn_options.replace_existing = false;
    state.conn_options.compression_quality = 0;
    state.conn_options.num_previous_attempts = 0;

    /* Phase 6: Initialize HTTP proxy */
    ESP_LOGI(TAG, "Origin: %s", origin_url);
    http_proxy_config_t proxy_cfg = {
        .origin_url = origin_url,
        .connect_timeout_ms = 5000,
        .read_timeout_ms = 30000,
    };
    if (http_proxy_init(&proxy_cfg) != 0) {
        ESP_LOGE(TAG, "Failed to initialize HTTP proxy");
        return -1;
    }

    /* Phase 3: Connect QUIC */
    quic_tunnel_ctx_t ctx = {0};
    quic_tunnel_config_t config = {
        .edge_server = edge_server,
        .edge_port = port,
        .event_cb = full_tunnel_event_cb,
        .user_data = &state,
    };

    int ret = quic_tunnel_connect(&ctx, &config);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to initiate connection: %d", ret);
        http_proxy_cleanup();
        return ret;
    }

    /* Run the packet loop (blocks until disconnect) */
    ret = quic_tunnel_run(&ctx);
    ESP_LOGI(TAG, "Tunnel exited: %d", ret);

    quic_tunnel_free(&ctx);
    http_proxy_cleanup();
    return 0;
}

/* ── Entry point ───────────────────────────────────────────────────── */

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    const char *edge = CF_EDGE_SRV_HOST;
    uint16_t port = CF_EDGE_PORT;

    const char *mode_env = getenv("CF_MODE");
    const char *edge_env = getenv("CF_EDGE");
    const char *port_env = getenv("CF_PORT");

    if (edge_env && edge_env[0]) {
        edge = edge_env;
    }
    if (port_env && port_env[0]) {
        port = (uint16_t)atoi(port_env);
    }

    ESP_LOGI(TAG, "Cloudflare Tunnel starting (edge=%s, port=%u)", edge, port);

    if (mode_env && strcmp(mode_env, "full") == 0) {
        full_tunnel(edge, port);
    } else {
        phase3_test(edge, port);
    }

    ESP_LOGI(TAG, "Done.");
}

#ifdef CONFIG_IDF_TARGET_LINUX
int main(void)
{
    app_main();
    return 0;
}
#endif
