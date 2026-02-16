#pragma once
/*
 * Phase 5: Data stream handling.
 *
 * Data streams carry HTTP requests from Cloudflare edge to this tunnel client.
 * Each data stream is a server-initiated bidirectional QUIC stream.
 *
 * Wire protocol:
 *   Request  (edge → client):  6-byte signature + "01" + Cap'n Proto ConnectRequest
 *   Response (client → edge):  6-byte signature + "01" + Cap'n Proto ConnectResponse
 *
 * After the request/response handshake, the stream becomes a raw byte pipe
 * for proxied HTTP body data.
 */

#include "tunnel_types.h"

/* Parse a data stream's initial bytes into a ConnectRequest.
 * The input must include the full preamble (signature + version + capnp).
 * Returns 0 on success, -1 on error. */
int data_stream_parse_request(const uint8_t *data, size_t len,
                              cf_connect_request_t *req);

/* Build a data stream response from a ConnectResponse.
 * Writes signature + version + capnp into buf.
 * Returns 0 on success, -1 on error.  Sets *out_len to bytes written. */
int data_stream_build_response(const cf_connect_response_t *resp,
                               uint8_t *buf, size_t buf_cap,
                               size_t *out_len);

/* Extract HTTP method from ConnectRequest metadata.
 * Returns pointer to the value string, or NULL if not found.
 * The returned pointer is into req->metadata and valid while req lives. */
const char *data_stream_get_method(const cf_connect_request_t *req);

/* Extract HTTP host from ConnectRequest metadata.
 * Returns pointer to the value string, or NULL if not found. */
const char *data_stream_get_host(const cf_connect_request_t *req);

/* Build response metadata for an HTTP response.
 * Populates resp with status code and headers as metadata entries.
 * Returns 0 on success, -1 on overflow. */
int data_stream_build_http_metadata(int status_code,
                                    const cf_metadata_t *headers,
                                    size_t header_count,
                                    cf_connect_response_t *resp);
