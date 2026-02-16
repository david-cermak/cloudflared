/*
 * Phase 3: QUIC tunnel connection to Cloudflare edge via picoquic.
 *
 * Establishes a QUIC connection using the "argotunnel" ALPN to a
 * Cloudflare edge server, manages bidirectional streams, and dispatches
 * events to the application layer.
 */

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include <picoquic.h>
#include <picoquic_utils.h>
#include <picoquic_packet_loop.h>
#include <picoquic_internal.h>
#include <picosocks.h>
#include "picoquic_bbr.h"

#include "esp_log.h"
#include "tunnel_types.h"
#include "quic_tunnel.h"

static const char *TAG = "quic_tunnel";

/* ── Internal helpers ──────────────────────────────────────────────── */

/*
 * Allocate and insert a new stream context into the linked list.
 */
static stream_ctx_t *stream_ctx_create(quic_tunnel_ctx_t *ctx,
                                       uint64_t stream_id, bool is_control)
{
    stream_ctx_t *sc = calloc(1, sizeof(stream_ctx_t));
    if (sc == NULL) {
        ESP_LOGE(TAG, "Failed to allocate stream context for %" PRIu64, stream_id);
        return NULL;
    }
    sc->stream_id = stream_id;
    sc->is_control = is_control;
    sc->next = ctx->streams;
    ctx->streams = sc;
    ESP_LOGI(TAG, "Created stream context: id=%" PRIu64 " control=%d", stream_id, is_control);
    return sc;
}

/*
 * Remove and free a stream context from the linked list.
 */
static void stream_ctx_destroy(quic_tunnel_ctx_t *ctx, uint64_t stream_id)
{
    stream_ctx_t **pp = &ctx->streams;
    while (*pp) {
        if ((*pp)->stream_id == stream_id) {
            stream_ctx_t *sc = *pp;
            *pp = sc->next;
            free(sc->send_buf);
            free(sc->recv_buf);
            free(sc);
            ESP_LOGI(TAG, "Destroyed stream context: id=%" PRIu64, stream_id);
            return;
        }
        pp = &(*pp)->next;
    }
}

/*
 * Append data to the receive buffer, growing it as needed.
 */
static int recv_buf_append(stream_ctx_t *sc, const uint8_t *data, size_t len)
{
    if (len == 0) {
        return 0;
    }
    size_t needed = sc->recv_len + len;
    if (needed > sc->recv_cap) {
        size_t new_cap = sc->recv_cap ? sc->recv_cap * 2 : 4096;
        while (new_cap < needed) {
            new_cap *= 2;
        }
        uint8_t *tmp = realloc(sc->recv_buf, new_cap);
        if (tmp == NULL) {
            ESP_LOGE(TAG, "recv_buf realloc failed (need %zu)", new_cap);
            return -1;
        }
        sc->recv_buf = tmp;
        sc->recv_cap = new_cap;
    }
    memcpy(sc->recv_buf + sc->recv_len, data, len);
    sc->recv_len += len;
    return 0;
}

/* ── picoquic stream callback ──────────────────────────────────────── */

/*
 * Main picoquic callback, invoked for all connection and stream events.
 *
 * Parameters follow the picoquic_stream_data_cb_fn signature:
 *   cnx         - the QUIC connection
 *   stream_id   - stream affected (0 for connection-level events)
 *   bytes       - data pointer (or opaque context for prepare_to_send)
 *   length      - data length (or max sendable for prepare_to_send)
 *   fin_or_event- the event type
 *   callback_ctx- our quic_tunnel_ctx_t
 *   stream_ctx  - per-stream context (may be NULL for new streams)
 */
static int tunnel_picoquic_callback(picoquic_cnx_t *cnx,
                                    uint64_t stream_id,
                                    uint8_t *bytes, size_t length,
                                    picoquic_call_back_event_t fin_or_event,
                                    void *callback_ctx, void *v_stream_ctx)
{
    quic_tunnel_ctx_t *ctx = (quic_tunnel_ctx_t *)callback_ctx;
    stream_ctx_t *sc = (stream_ctx_t *)v_stream_ctx;

    if (ctx == NULL) {
        return PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }

    switch (fin_or_event) {

    /* ── Connection established ────────────────────────────────── */
    case picoquic_callback_almost_ready:
        ESP_LOGI(TAG, "Connection almost ready");
        /* Fall through to ready handling */
        return 0;

    case picoquic_callback_ready:
        ESP_LOGI(TAG, "Connection ready — QUIC handshake completed");
        ctx->connected = true;
        if (ctx->event_cb) {
            ctx->event_cb(ctx, QT_EVENT_CONNECTED, 0, NULL, 0, ctx->user_data);
        }
        return 0;

    /* ── Connection closed ─────────────────────────────────────── */
    case picoquic_callback_close:
        ESP_LOGW(TAG, "Connection closed by transport");
        ctx->disconnected = true;
        if (ctx->event_cb) {
            ctx->event_cb(ctx, QT_EVENT_DISCONNECTED, 0, NULL, 0, ctx->user_data);
        }
        return 0;

    case picoquic_callback_application_close:
        ESP_LOGW(TAG, "Connection closed by application (peer)");
        ctx->disconnected = true;
        if (ctx->event_cb) {
            ctx->event_cb(ctx, QT_EVENT_DISCONNECTED, 0, NULL, 0, ctx->user_data);
        }
        return 0;

    case picoquic_callback_stateless_reset:
        ESP_LOGW(TAG, "Stateless reset received");
        ctx->disconnected = true;
        if (ctx->event_cb) {
            ctx->event_cb(ctx, QT_EVENT_DISCONNECTED, 0, NULL, 0, ctx->user_data);
        }
        return 0;

    /* ── Stream data received ──────────────────────────────────── */
    case picoquic_callback_stream_data: {
        bool is_new = (sc == NULL);
        if (is_new) {
            /* Remote-initiated stream — create context */
            sc = stream_ctx_create(ctx, stream_id, false);
            if (sc == NULL) {
                return PICOQUIC_ERROR_MEMORY;
            }
            picoquic_set_app_stream_ctx(cnx, stream_id, sc);
            ESP_LOGI(TAG, "Remote opened stream %" PRIu64, stream_id);
            if (ctx->event_cb) {
                ctx->event_cb(ctx, QT_EVENT_STREAM_OPENED_REMOTE, stream_id,
                              NULL, 0, ctx->user_data);
            }
        }

        if (length > 0) {
            if (recv_buf_append(sc, bytes, length) != 0) {
                return PICOQUIC_ERROR_MEMORY;
            }
            ESP_LOGI(TAG, "Stream %" PRIu64 " recv %zu bytes (total %zu)",
                     stream_id, length, sc->recv_len);
            if (ctx->event_cb) {
                ctx->event_cb(ctx, QT_EVENT_STREAM_DATA, stream_id,
                              bytes, length, ctx->user_data);
            }
        }
        return 0;
    }

    /* ── Stream FIN received ───────────────────────────────────── */
    case picoquic_callback_stream_fin: {
        bool is_new = (sc == NULL);
        if (is_new) {
            sc = stream_ctx_create(ctx, stream_id, false);
            if (sc == NULL) {
                return PICOQUIC_ERROR_MEMORY;
            }
            picoquic_set_app_stream_ctx(cnx, stream_id, sc);
            if (ctx->event_cb) {
                ctx->event_cb(ctx, QT_EVENT_STREAM_OPENED_REMOTE, stream_id,
                              NULL, 0, ctx->user_data);
            }
        }
        /* Append any trailing data delivered with FIN */
        if (length > 0) {
            if (recv_buf_append(sc, bytes, length) != 0) {
                return PICOQUIC_ERROR_MEMORY;
            }
            if (ctx->event_cb) {
                ctx->event_cb(ctx, QT_EVENT_STREAM_DATA, stream_id,
                              bytes, length, ctx->user_data);
            }
        }
        sc->recv_fin = true;
        ESP_LOGI(TAG, "Stream %" PRIu64 " FIN (total recv %zu bytes)",
                 stream_id, sc->recv_len);
        if (ctx->event_cb) {
            ctx->event_cb(ctx, QT_EVENT_STREAM_FIN, stream_id,
                          sc->recv_buf, sc->recv_len, ctx->user_data);
        }
        return 0;
    }

    /* ── Prepare to send (picoquic asks us for data) ───────────── */
    case picoquic_callback_prepare_to_send: {
        if (sc == NULL) {
            return 0;
        }
        size_t available = sc->send_len - sc->send_offset;
        if (available == 0 && !sc->send_fin) {
            return 0;
        }
        size_t to_send = (available < length) ? available : length;
        int is_fin = (sc->send_fin && (sc->send_offset + to_send >= sc->send_len)) ? 1 : 0;
        int is_still_active = (!is_fin && (sc->send_offset + to_send < sc->send_len)) ? 1 : 0;

        uint8_t *buf = picoquic_provide_stream_data_buffer(bytes, to_send,
                                                           is_fin, is_still_active);
        if (buf == NULL) {
            ESP_LOGE(TAG, "picoquic_provide_stream_data_buffer returned NULL");
            return PICOQUIC_ERROR_UNEXPECTED_ERROR;
        }
        if (to_send > 0) {
            memcpy(buf, sc->send_buf + sc->send_offset, to_send);
            sc->send_offset += to_send;
        }
        ESP_LOGI(TAG, "Stream %" PRIu64 " sent %zu bytes (fin=%d, still_active=%d)",
                 sc->stream_id, to_send, is_fin, is_still_active);

        /* Free send buffer once fully consumed */
        if (sc->send_offset >= sc->send_len) {
            free(sc->send_buf);
            sc->send_buf = NULL;
            sc->send_len = 0;
            sc->send_offset = 0;
            if (is_fin) {
                sc->send_fin = false;
            }
        }
        return 0;
    }

    /* ── Stream reset / stop sending ───────────────────────────── */
    case picoquic_callback_stream_reset:
        ESP_LOGW(TAG, "Stream %" PRIu64 " reset by peer", stream_id);
        if (sc != NULL) {
            picoquic_reset_stream_ctx(cnx, stream_id);
            stream_ctx_destroy(ctx, stream_id);
        }
        return 0;

    case picoquic_callback_stop_sending:
        ESP_LOGW(TAG, "Stop sending on stream %" PRIu64, stream_id);
        if (sc != NULL) {
            picoquic_reset_stream(cnx, stream_id, 0);
        }
        return 0;

    /* ── Ignored events ────────────────────────────────────────── */
    case picoquic_callback_stream_gap:
        ESP_LOGW(TAG, "Stream gap on %" PRIu64, stream_id);
        return 0;

    case picoquic_callback_datagram:
        ESP_LOGD(TAG, "Datagram received (%zu bytes)", length);
        return 0;

    case picoquic_callback_version_negotiation:
        ESP_LOGI(TAG, "Version negotiation requested");
        return 0;

    case picoquic_callback_request_alpn_list:
        ESP_LOGD(TAG, "ALPN list requested");
        return 0;

    default:
        ESP_LOGD(TAG, "Unhandled callback event: %d", (int)fin_or_event);
        return 0;
    }
}

/* ── Packet loop callback ──────────────────────────────────────────── */

/*
 * Called by picoquic_packet_loop at various stages.
 * We use it to detect when the connection has been closed and
 * to terminate the loop.
 */
static int tunnel_loop_cb(picoquic_quic_t *quic,
                          picoquic_packet_loop_cb_enum cb_mode,
                          void *callback_ctx, void *callback_argv)
{
    quic_tunnel_ctx_t *ctx = (quic_tunnel_ctx_t *)callback_ctx;

    switch (cb_mode) {
    case picoquic_packet_loop_ready:
        ESP_LOGI(TAG, "Packet loop ready, waiting for handshake...");
        return 0;

    case picoquic_packet_loop_after_receive:
        if (ctx->disconnected) {
            ESP_LOGI(TAG, "Disconnected — terminating packet loop");
            return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
        }
        return 0;

    case picoquic_packet_loop_after_send:
        if (ctx->disconnected) {
            ESP_LOGI(TAG, "Disconnected — terminating packet loop (after send)");
            return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
        }
        return 0;

    default:
        return 0;
    }
}

/* ── Public API ────────────────────────────────────────────────────── */

int quic_tunnel_connect(quic_tunnel_ctx_t *ctx, const quic_tunnel_config_t *config)
{
    int ret = 0;
    int is_name = 0;

    if (ctx == NULL || config == NULL || config->edge_server == NULL) {
        ESP_LOGE(TAG, "Invalid arguments to quic_tunnel_connect");
        return -1;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->event_cb = config->event_cb;
    ctx->user_data = config->user_data;

    /* Resolve edge server address */
    ESP_LOGI(TAG, "Resolving edge server: %s:%u", config->edge_server, config->edge_port);
    ret = picoquic_get_server_address(config->edge_server, (int)config->edge_port,
                                      &ctx->server_addr, &is_name);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to resolve server address: %s (ret=%d)",
                 config->edge_server, ret);
        return -1;
    }
    ESP_LOGI(TAG, "Resolved %s (is_name=%d)", config->edge_server, is_name);

    /* Create picoquic context (client mode — no cert/key needed) */
    uint64_t current_time = picoquic_current_time();
    ESP_LOGI(TAG, "Creating QUIC context (time=%" PRIu64 ")", current_time);

    ctx->quic = picoquic_create(
        1,          /* max_nb_connections */
        NULL,       /* cert_file_name (client — not needed) */
        NULL,       /* key_file_name */
        NULL,       /* cert_root_file_name (use system roots) */
        CF_EDGE_ALPN,
        NULL,       /* default_callback_fn (set per-cnx below) */
        NULL,       /* default_callback_ctx */
        NULL,       /* cnx_id_callback */
        NULL,       /* cnx_id_callback_data */
        NULL,       /* reset_seed */
        current_time,
        NULL,       /* p_simulated_time (wall clock) */
        NULL,       /* ticket_file_name */
        NULL,       /* ticket_encryption_key */
        0           /* ticket_encryption_key_length */
    );
    if (ctx->quic == NULL) {
        ESP_LOGE(TAG, "picoquic_create failed");
        return -1;
    }

    /* Set BBR congestion control (matches cloudflared Go) */
    picoquic_set_default_congestion_algorithm(ctx->quic, picoquic_bbr_algorithm);
    ESP_LOGI(TAG, "Congestion control: BBR");

    /* Create QUIC connection */
    ESP_LOGI(TAG, "Creating connection to %s (SNI=%s, ALPN=%s)",
             config->edge_server, CF_EDGE_SNI, CF_EDGE_ALPN);

    ctx->cnx = picoquic_create_cnx(
        ctx->quic,
        picoquic_null_connection_id,    /* initial local CID */
        picoquic_null_connection_id,    /* remote CID */
        (const struct sockaddr *)&ctx->server_addr,
        current_time,
        0,              /* preferred_version (0 = default) */
        CF_EDGE_SNI,    /* TLS SNI */
        CF_EDGE_ALPN,   /* QUIC ALPN */
        1               /* client_mode */
    );
    if (ctx->cnx == NULL) {
        ESP_LOGE(TAG, "picoquic_create_cnx failed");
        picoquic_free(ctx->quic);
        ctx->quic = NULL;
        return -1;
    }

    /* Set per-connection callback */
    picoquic_set_callback(ctx->cnx, tunnel_picoquic_callback, ctx);

    /* Initiate TLS handshake */
    ret = picoquic_start_client_cnx(ctx->cnx);
    if (ret != 0) {
        ESP_LOGE(TAG, "picoquic_start_client_cnx failed: %d", ret);
        picoquic_free(ctx->quic);
        ctx->quic = NULL;
        ctx->cnx = NULL;
        return -1;
    }

    ESP_LOGI(TAG, "QUIC handshake initiated");
    return 0;
}

int quic_tunnel_run(quic_tunnel_ctx_t *ctx)
{
    if (ctx == NULL || ctx->quic == NULL) {
        ESP_LOGE(TAG, "Invalid context for quic_tunnel_run");
        return -1;
    }

    ESP_LOGI(TAG, "Starting packet loop (af=%d)...", ctx->server_addr.ss_family);

    int ret = picoquic_packet_loop(
        ctx->quic,
        0,                          /* local_port (0 = ephemeral) */
        ctx->server_addr.ss_family, /* local_af */
        0,                          /* dest_if */
        0,                          /* socket_buffer_size (0 = default) */
        0,                          /* do_not_use_gso */
        tunnel_loop_cb,
        ctx
    );

    if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP || ret == 0) {
        ESP_LOGI(TAG, "Packet loop terminated normally");
        return 0;
    }

    ESP_LOGE(TAG, "Packet loop exited with error: %d", ret);
    return ret;
}

uint64_t quic_tunnel_open_stream(quic_tunnel_ctx_t *ctx, bool is_control)
{
    if (ctx == NULL || ctx->cnx == NULL) {
        ESP_LOGE(TAG, "Cannot open stream: no connection");
        return UINT64_MAX;
    }

    /* Bidirectional stream (is_unidir = 0) */
    uint64_t stream_id = picoquic_get_next_local_stream_id(ctx->cnx, 0);

    stream_ctx_t *sc = stream_ctx_create(ctx, stream_id, is_control);
    if (sc == NULL) {
        return UINT64_MAX;
    }

    /* Register the stream context and mark it active so picoquic knows about it */
    int ret = picoquic_mark_active_stream(ctx->cnx, stream_id, 1, sc);
    if (ret != 0) {
        ESP_LOGE(TAG, "picoquic_mark_active_stream failed: %d", ret);
        stream_ctx_destroy(ctx, stream_id);
        return UINT64_MAX;
    }

    ESP_LOGI(TAG, "Opened stream %" PRIu64 " (control=%d)", stream_id, is_control);
    return stream_id;
}

int quic_tunnel_send(quic_tunnel_ctx_t *ctx, uint64_t stream_id,
                     const uint8_t *data, size_t len, bool fin)
{
    if (ctx == NULL || ctx->cnx == NULL) {
        ESP_LOGE(TAG, "Cannot send: no connection");
        return -1;
    }

    stream_ctx_t *sc = quic_tunnel_find_stream(ctx, stream_id);
    if (sc == NULL) {
        ESP_LOGE(TAG, "Cannot send: stream %" PRIu64 " not found", stream_id);
        return -1;
    }

    if (len > 0 && data != NULL) {
        /* Grow send buffer to accommodate new data */
        size_t needed = sc->send_len + len;
        uint8_t *tmp = realloc(sc->send_buf, needed);
        if (tmp == NULL) {
            ESP_LOGE(TAG, "send_buf realloc failed (need %zu)", needed);
            return -1;
        }
        memcpy(tmp + sc->send_len, data, len);
        sc->send_buf = tmp;
        sc->send_len = needed;
    }

    if (fin) {
        sc->send_fin = true;
    }

    /* Tell picoquic we have data ready */
    int ret = picoquic_mark_active_stream(ctx->cnx, stream_id, 1, sc);
    if (ret != 0) {
        ESP_LOGE(TAG, "picoquic_mark_active_stream failed: %d", ret);
        return -1;
    }

    ESP_LOGD(TAG, "Queued %zu bytes on stream %" PRIu64 " (fin=%d, total=%zu)",
             len, stream_id, fin, sc->send_len);
    return 0;
}

void quic_tunnel_close(quic_tunnel_ctx_t *ctx)
{
    if (ctx == NULL || ctx->cnx == NULL) {
        return;
    }

    ESP_LOGI(TAG, "Closing QUIC connection gracefully");
    picoquic_close(ctx->cnx, 0);
    /* The actual disconnect will be handled by the callback and loop termination */
}

void quic_tunnel_free(quic_tunnel_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    /* Free all stream contexts */
    stream_ctx_t *sc = ctx->streams;
    while (sc) {
        stream_ctx_t *next = sc->next;
        free(sc->send_buf);
        free(sc->recv_buf);
        free(sc);
        sc = next;
    }
    ctx->streams = NULL;

    /* Free picoquic context (also frees all connections) */
    if (ctx->quic) {
        picoquic_free(ctx->quic);
        ctx->quic = NULL;
        ctx->cnx = NULL;
    }

    ESP_LOGI(TAG, "Tunnel resources freed");
}

stream_ctx_t *quic_tunnel_find_stream(quic_tunnel_ctx_t *ctx, uint64_t stream_id)
{
    if (ctx == NULL) {
        return NULL;
    }
    stream_ctx_t *sc = ctx->streams;
    while (sc) {
        if (sc->stream_id == stream_id) {
            return sc;
        }
        sc = sc->next;
    }
    return NULL;
}
