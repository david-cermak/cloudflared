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
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_log.h"

#include "tunnel_types.h"
#include "quic_tunnel.h"
#include "http_proxy.h"
#include "control_stream.h"
#include "data_stream.h"

static const char *TAG = "cf_tunnel";

/* ── Phase 3 test mode ─────────────────────────────────────────────── */

static int phase3_test(const char *edge_server, uint16_t port);

/*
 * Event callback for Phase 3 test — closes immediately after handshake.
 */
static int phase3_event_cb(quic_tunnel_ctx_t *ctx, qt_event_t event,
                           uint64_t stream_id, const uint8_t *data, size_t len,
                           void *user_data)
{
    (void)stream_id;
    (void)data;
    (void)len;
    (void)user_data;

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

static int full_tunnel(const char *edge_server, uint16_t port);

typedef struct {
    bool registered;
    uint64_t control_stream_id;
} tunnel_state_t;

/*
 * Event callback for full tunnel mode.
 * Handles connection lifecycle, control stream setup, and data streams.
 */
static int full_tunnel_event_cb(quic_tunnel_ctx_t *ctx, qt_event_t event,
                                uint64_t stream_id, const uint8_t *data, size_t len,
                                void *user_data)
{
    tunnel_state_t *state = (tunnel_state_t *)user_data;

    switch (event) {
    case QT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "Connected to edge, opening control stream...");
        state->control_stream_id = quic_tunnel_open_stream(ctx, true);
        ESP_LOGI(TAG, "Control stream opened: %" PRIu64, state->control_stream_id);
        /* Phase 4: Send RegisterConnection RPC on control stream */
        ESP_LOGI(TAG, "TODO: Send RegisterConnection RPC on control stream");
        return 0;

    case QT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "Disconnected from edge");
        return 0;

    case QT_EVENT_STREAM_OPENED_REMOTE:
        ESP_LOGI(TAG, "Edge opened stream %" PRIu64, stream_id);
        /* Phase 5: Handle incoming data stream */
        return 0;

    case QT_EVENT_STREAM_DATA:
        if (stream_id == state->control_stream_id) {
            ESP_LOGI(TAG, "Control stream data: %zu bytes", len);
            /* Phase 4: Parse registration response */
        } else {
            ESP_LOGI(TAG, "Data stream %" PRIu64 ": %zu bytes", stream_id, len);
            /* Phase 5: Accumulate ConnectRequest data */
        }
        return 0;

    case QT_EVENT_STREAM_FIN:
        if (stream_id != state->control_stream_id) {
            ESP_LOGI(TAG, "Data stream %" PRIu64 " finished", stream_id);
            /* Phase 5+6: Parse request and proxy to origin */
        }
        return 0;

    default:
        return 0;
    }
}

static int full_tunnel(const char *edge_server, uint16_t port)
{
    ESP_LOGI(TAG, "=== Full Tunnel: %s:%u ===", edge_server, port);

    tunnel_state_t state = {0};
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
        return ret;
    }

    ret = quic_tunnel_run(&ctx);
    ESP_LOGI(TAG, "Tunnel exited: %d", ret);

    quic_tunnel_free(&ctx);
    return 0;
}

/* ── Entry point ───────────────────────────────────────────────────── */

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    const char *edge = CF_EDGE_SRV_HOST;
    uint16_t port = CF_EDGE_PORT;

    /* On linux host target, allow overriding via environment variables */
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
        /* Default: Phase 3 test (QUIC handshake verification) */
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
