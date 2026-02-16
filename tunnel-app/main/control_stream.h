#pragma once
/*
 * Phase 4: Register tunnel via control stream.
 *
 * This encodes Cap'n Proto RPC messages for the RegisterConnection call.
 *
 * The control stream is the first bidirectional stream opened after QUIC
 * handshake.  The Go implementation uses full Cap'n Proto RPC (Bootstrap +
 * Call).  We implement a minimal hand-written encoder for exactly those
 * two messages, and a decoder for the Return message.
 *
 * Protocol sequence:
 *   1. Client sends Bootstrap message  (get server's root interface)
 *   2. Client sends Call message        (invoke RegisterConnection)
 *   3. Server sends Return message      (ConnectionResponse)
 */

#include "tunnel_types.h"

/* Encode the full registration request sequence (Bootstrap + Call).
 *
 * Writes two consecutive Cap'n Proto RPC messages into buf:
 *   [Bootstrap message][Call message]
 *
 * Returns 0 on success, -1 on error.  Sets *out_len to total bytes written. */
int control_stream_encode_register(
    const cf_tunnel_auth_t *auth,
    const uint8_t *tunnel_id, size_t tunnel_id_len,
    uint8_t conn_index,
    const cf_conn_options_t *options,
    uint8_t *buf, size_t buf_cap, size_t *out_len);

/* Decode a registration response from control stream data.
 *
 * Expects a Cap'n Proto RPC Return message containing a ConnectionResponse.
 *
 * Returns 0 on success, -1 on error. */
int control_stream_decode_response(
    const uint8_t *data, size_t len,
    cf_registration_result_t *result);
