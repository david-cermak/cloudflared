#pragma once
/*
 * Phase 3: QUIC tunnel connection to Cloudflare edge via picoquic.
 *
 * Manages the lifecycle of a single QUIC connection to a Cloudflare
 * edge server, including stream multiplexing and event dispatch.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <picoquic.h>

/* Forward declare */
typedef struct quic_tunnel_ctx quic_tunnel_ctx_t;

/* Stream context for managing per-stream state */
typedef struct stream_ctx {
    uint64_t stream_id;
    bool is_control;
    /* Send buffer */
    uint8_t *send_buf;
    size_t send_len;
    size_t send_offset;
    bool send_fin;
    /* Receive buffer */
    uint8_t *recv_buf;
    size_t recv_len;
    size_t recv_cap;
    bool recv_fin;
    bool request_handled; /* App flag: data stream request already processed */
    struct stream_ctx *next;
} stream_ctx_t;

/* Tunnel event types */
typedef enum {
    QT_EVENT_CONNECTED,
    QT_EVENT_DISCONNECTED,
    QT_EVENT_STREAM_DATA,
    QT_EVENT_STREAM_FIN,
    QT_EVENT_STREAM_OPENED_REMOTE,
} qt_event_t;

/* Event callback */
typedef int (*qt_event_cb_t)(quic_tunnel_ctx_t *ctx, qt_event_t event,
                             uint64_t stream_id, const uint8_t *data, size_t len,
                             void *user_data);

/* Configuration */
typedef struct {
    const char *edge_server;   /* Hostname or IP */
    uint16_t edge_port;
    qt_event_cb_t event_cb;
    void *user_data;
} quic_tunnel_config_t;

/* Main tunnel context */
struct quic_tunnel_ctx {
    picoquic_quic_t *quic;
    picoquic_cnx_t *cnx;
    struct sockaddr_storage server_addr;
    bool connected;
    bool disconnected;
    qt_event_cb_t event_cb;
    void *user_data;
    stream_ctx_t *streams;  /* Linked list of active streams */
};

/* Connect to Cloudflare edge (creates QUIC context + connection, starts handshake) */
int quic_tunnel_connect(quic_tunnel_ctx_t *ctx, const quic_tunnel_config_t *config);

/* Run the blocking packet loop (returns when disconnected or error) */
int quic_tunnel_run(quic_tunnel_ctx_t *ctx);

/* Open a new client-initiated bidirectional stream, returns stream_id */
uint64_t quic_tunnel_open_stream(quic_tunnel_ctx_t *ctx, bool is_control);

/* Queue data for sending on a stream */
int quic_tunnel_send(quic_tunnel_ctx_t *ctx, uint64_t stream_id,
                     const uint8_t *data, size_t len, bool fin);

/* Close the QUIC connection gracefully */
void quic_tunnel_close(quic_tunnel_ctx_t *ctx);

/* Free all resources */
void quic_tunnel_free(quic_tunnel_ctx_t *ctx);

/* Find stream context by ID */
stream_ctx_t *quic_tunnel_find_stream(quic_tunnel_ctx_t *ctx, uint64_t stream_id);
