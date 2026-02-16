#pragma once
/*
 * Phase 4/5: Minimal Cap'n Proto encoder/decoder.
 *
 * This is NOT a general-purpose Cap'n Proto library. It encodes and decodes
 * exactly the messages needed by the Cloudflare tunnel protocol:
 *   - ConnectRequest  (decode, from edge)
 *   - ConnectResponse (encode, to edge)
 *
 * Single-segment messages only. No inter-segment pointers, no capabilities.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "tunnel_types.h"

/* ── Cap'n Proto message builder (single-segment, pre-allocated) ── */

typedef struct {
    uint8_t *buf;   /* Working buffer (segment data, no header) */
    size_t   cap;   /* Buffer capacity in bytes */
    size_t   pos;   /* Current write position in bytes */
} capnp_builder_t;

/* Initialise a builder over a caller-supplied buffer. */
void capnp_builder_init(capnp_builder_t *b, uint8_t *buf, size_t cap);

/* Allocate `words` 8-byte words, returns byte offset into buf, or -1 on overflow. */
int capnp_alloc(capnp_builder_t *b, size_t words);

/* Write a struct pointer at `ptr_offset` pointing to struct at `struct_offset`.
 * data_words / ptr_count describe the target struct's shape. */
void capnp_write_struct_ptr(uint8_t *buf, size_t ptr_offset,
                            size_t struct_offset,
                            uint16_t data_words, uint16_t ptr_count);

/* Write a list pointer at `ptr_offset`.
 * elem_size: 0=void, 1=bit, 2=byte, 3=two-byte, 4=four-byte,
 *            5=eight-byte, 6=pointer, 7=composite. */
void capnp_write_list_ptr(uint8_t *buf, size_t ptr_offset,
                          size_t list_offset,
                          uint8_t elem_size, uint32_t count);

/* Write a text string (byte list with NUL terminator).
 * Returns 0 on success, -1 on overflow. */
int capnp_write_text(capnp_builder_t *b, size_t ptr_offset, const char *text);

/* Write raw data (byte list, no NUL).
 * Returns 0 on success, -1 on overflow. */
int capnp_write_data(capnp_builder_t *b, size_t ptr_offset,
                     const uint8_t *data, size_t len);

/* Finalise builder into wire-format message (segment table + data).
 * Returns total bytes written to `out`, or 0 on overflow. */
size_t capnp_finalize(const capnp_builder_t *b, uint8_t *out, size_t out_cap);

/* ── Cap'n Proto message reader (single-segment) ─────────────── */

typedef struct {
    const uint8_t *seg;     /* Pointer to first segment data */
    size_t         seg_len; /* Segment length in bytes */
} capnp_reader_t;

/* Parse message wire format, point reader at first segment.
 * Returns 0 on success, -1 on error. */
int capnp_read_message(const uint8_t *data, size_t len, capnp_reader_t *r);

/* Read a struct pointer at `ptr_offset`.
 * Fills struct_offset (absolute byte offset), data_words, ptr_count.
 * Returns 0 on success, -1 on error (null/invalid pointer). */
int capnp_read_struct_ptr(const capnp_reader_t *r, size_t ptr_offset,
                          size_t *struct_offset,
                          uint16_t *data_words, uint16_t *ptr_count);

/* Read text from a list pointer.  Returns pointer into segment buffer.
 * Sets *out_len to string length (excluding NUL). */
const char *capnp_read_text(const capnp_reader_t *r, size_t ptr_offset,
                            size_t *out_len);

/* Read data from a list pointer.  Returns pointer into segment buffer.
 * Sets *out_len to data length. */
const uint8_t *capnp_read_data(const capnp_reader_t *r, size_t ptr_offset,
                               size_t *out_len);

/* Read uint16 from struct data section at byte_offset relative to struct_data_offset. */
uint16_t capnp_read_uint16(const capnp_reader_t *r,
                           size_t struct_data_offset, size_t byte_offset);

/* Read uint8 from struct data section. */
uint8_t capnp_read_uint8(const capnp_reader_t *r,
                         size_t struct_data_offset, size_t byte_offset);

/* Read bool from struct data section (bit `bit` within byte at byte_offset). */
bool capnp_read_bool(const capnp_reader_t *r,
                     size_t struct_data_offset, size_t byte_offset, int bit);

/* Calculate the total wire size of a single-segment capnp message from raw bytes.
 * Returns 0 if the data is too short or malformed.
 * Useful for determining where the capnp message ends in a stream buffer. */
size_t capnp_wire_message_size(const uint8_t *data, size_t len);

/* ── High-level: Data stream protocol ─────────────────────────── */

/* Decode a ConnectRequest from raw Cap'n Proto bytes
 * (after the 6-byte signature + 2-byte version have been stripped). */
int capnp_decode_connect_request(const uint8_t *data, size_t len,
                                 cf_connect_request_t *req);

/* Encode a ConnectResponse to wire format (signature + version + capnp).
 * Sets *out_len to the total bytes written.
 * Returns 0 on success, -1 on error. */
int capnp_encode_connect_response(const cf_connect_response_t *resp,
                                  uint8_t *buf, size_t buf_cap,
                                  size_t *out_len);
