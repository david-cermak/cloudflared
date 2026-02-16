/*
 * Phase 5: Data stream parsing and building.
 *
 * Handles the data stream protocol between Cloudflare edge and this client:
 *   - Parse incoming ConnectRequest (signature + version + Cap'n Proto)
 *   - Build outgoing ConnectResponse (signature + version + Cap'n Proto)
 *   - Extract HTTP metadata from ConnectRequest
 *   - Build HTTP response metadata for ConnectResponse
 */

#include "data_stream.h"
#include "capnp_minimal.h"

#include <string.h>
#include <stdio.h>
#include <esp_log.h>

static const char *TAG = "data_stream";

/* Preamble: 6-byte signature + 2-byte version ("01") */
#define PREAMBLE_LEN (6 + 2)

/* ────────────────────────────────────────────────────────────────
 *  Parse incoming ConnectRequest
 * ──────────────────────────────────────────────────────────────── */

int data_stream_parse_request(const uint8_t *data, size_t len,
                              cf_connect_request_t *req)
{
    if (len < PREAMBLE_LEN) {
        ESP_LOGE(TAG, "data too short for preamble: %zu bytes", len);
        return -1;
    }

    /* Verify 6-byte signature */
    if (memcmp(data, CF_DATA_STREAM_SIGNATURE, 6) != 0) {
        ESP_LOGE(TAG, "invalid data stream signature: "
                 "%02x %02x %02x %02x %02x %02x",
                 data[0], data[1], data[2], data[3], data[4], data[5]);
        return -1;
    }

    /* Verify 2-byte version "01" */
    if (data[6] != '0' || data[7] != '1') {
        ESP_LOGE(TAG, "unsupported data stream version: %c%c", data[6], data[7]);
        return -1;
    }

    ESP_LOGD(TAG, "parsing ConnectRequest: %zu bytes after preamble",
             len - PREAMBLE_LEN);

    /* Decode Cap'n Proto ConnectRequest from remaining bytes */
    return capnp_decode_connect_request(data + PREAMBLE_LEN,
                                        len - PREAMBLE_LEN, req);
}

/* ────────────────────────────────────────────────────────────────
 *  Build outgoing ConnectResponse
 * ──────────────────────────────────────────────────────────────── */

int data_stream_build_response(const cf_connect_response_t *resp,
                               uint8_t *buf, size_t buf_cap,
                               size_t *out_len)
{
    /* capnp_encode_connect_response already writes the preamble */
    return capnp_encode_connect_response(resp, buf, buf_cap, out_len);
}

/* ────────────────────────────────────────────────────────────────
 *  Metadata helpers
 * ──────────────────────────────────────────────────────────────── */

/* Search metadata for a key (case-sensitive match). */
static const char *find_metadata(const cf_connect_request_t *req, const char *key)
{
    for (size_t i = 0; i < req->metadata_count; i++) {
        if (strcmp(req->metadata[i].key, key) == 0) {
            return req->metadata[i].val;
        }
    }
    return NULL;
}

const char *data_stream_get_method(const cf_connect_request_t *req)
{
    return find_metadata(req, "HttpMethod");
}

const char *data_stream_get_host(const cf_connect_request_t *req)
{
    return find_metadata(req, "HttpHost");
}

/* ────────────────────────────────────────────────────────────────
 *  Build HTTP response metadata
 *
 *  The Go implementation sends metadata entries like:
 *    "HttpStatus"        = "200"
 *    "HttpHeader:X-Name" = "value"
 * ──────────────────────────────────────────────────────────────── */

int data_stream_build_http_metadata(int status_code,
                                    const cf_metadata_t *headers,
                                    size_t header_count,
                                    cf_connect_response_t *resp)
{
    memset(resp, 0, sizeof(*resp));

    size_t idx = 0;

    /* HttpStatus metadata entry */
    if (idx >= CF_MAX_METADATA) {
        ESP_LOGE(TAG, "metadata overflow adding HttpStatus");
        return -1;
    }
    snprintf(resp->metadata[idx].key, sizeof(resp->metadata[idx].key), "HttpStatus");
    snprintf(resp->metadata[idx].val, sizeof(resp->metadata[idx].val), "%d", status_code);
    idx++;

    /* Copy response headers as "HttpHeader:<Name>" entries */
    for (size_t i = 0; i < header_count; i++) {
        if (idx >= CF_MAX_METADATA) {
            ESP_LOGW(TAG, "metadata overflow at header %zu/%zu", i, header_count);
            break;
        }

        /* Truncation is safe here - snprintf guarantees NUL-termination */
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wformat-truncation"
        snprintf(resp->metadata[idx].key, sizeof(resp->metadata[idx].key),
                 "HttpHeader:%s", headers[i].key);
        #pragma GCC diagnostic pop

        size_t val_len = strlen(headers[i].val);
        size_t copy_len = val_len < sizeof(resp->metadata[idx].val) - 1
                              ? val_len : sizeof(resp->metadata[idx].val) - 1;
        memcpy(resp->metadata[idx].val, headers[i].val, copy_len);
        resp->metadata[idx].val[copy_len] = '\0';

        idx++;
    }

    resp->metadata_count = idx;
    /* No error string for successful responses */
    resp->error[0] = '\0';

    ESP_LOGD(TAG, "built HTTP metadata: status=%d, %zu entries total",
             status_code, idx);
    return 0;
}
