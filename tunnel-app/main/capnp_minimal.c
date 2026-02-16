/*
 * Phase 4/5: Minimal Cap'n Proto encoder/decoder.
 *
 * Implements exactly the encoding/decoding needed for Cloudflare tunnel
 * protocol messages (ConnectRequest, ConnectResponse, Metadata).
 *
 * Cap'n Proto wire format reference:
 *   https://capnproto.org/encoding.html
 *
 * All multi-byte integers are little-endian.
 */

#include "capnp_minimal.h"

#include <string.h>
#include <stdio.h>
#include <esp_log.h>

static const char *TAG = "capnp";

/* ────────────────────────────────────────────────────────────────
 *  Helpers
 * ──────────────────────────────────────────────────────────────── */

/* Align a byte count up to the next 8-byte boundary. */
static inline size_t align8(size_t n)
{
    return (n + 7) & ~(size_t)7;
}

static inline uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void write_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
}

static inline void write_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void write_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (i * 8));
    }
}

/* ────────────────────────────────────────────────────────────────
 *  Builder
 * ──────────────────────────────────────────────────────────────── */

void capnp_builder_init(capnp_builder_t *b, uint8_t *buf, size_t cap)
{
    b->buf = buf;
    b->cap = cap;
    b->pos = 0;
    memset(buf, 0, cap);
}

int capnp_alloc(capnp_builder_t *b, size_t words)
{
    size_t aligned = align8(b->pos);
    size_t need = aligned + words * 8;
    if (need > b->cap) {
        ESP_LOGE(TAG, "alloc overflow: need %zu, cap %zu", need, b->cap);
        return -1;
    }
    /* Zero any padding gap between pos and aligned */
    if (aligned > b->pos) {
        memset(b->buf + b->pos, 0, aligned - b->pos);
    }
    int offset = (int)aligned;
    b->pos = need;
    return offset;
}

void capnp_write_struct_ptr(uint8_t *buf, size_t ptr_offset,
                            size_t struct_offset,
                            uint16_t data_words, uint16_t ptr_count)
{
    /*
     * Struct pointer (64 bits):
     *   bits [0..1]   = 0 (struct)
     *   bits [2..31]  = offset in words from end of pointer to start of struct (signed)
     *   bits [32..47] = data section size in words
     *   bits [48..63] = pointer section size in words
     */
    int32_t off_words = (int32_t)((struct_offset - ptr_offset - 8) / 8);

    uint32_t lo = ((uint32_t)(off_words << 2)) | 0x00; /* type = 0 */
    uint32_t hi = (uint32_t)data_words | ((uint32_t)ptr_count << 16);

    write_le32(buf + ptr_offset, lo);
    write_le32(buf + ptr_offset + 4, hi);
}

void capnp_write_list_ptr(uint8_t *buf, size_t ptr_offset,
                          size_t list_offset,
                          uint8_t elem_size, uint32_t count)
{
    /*
     * List pointer (64 bits):
     *   bits [0..1]   = 1 (list)
     *   bits [2..31]  = offset in words from end of pointer to start of list (signed)
     *   bits [32..34] = element size tag
     *   bits [35..63] = element count (or total words for composite)
     */
    int32_t off_words = (int32_t)((list_offset - ptr_offset - 8) / 8);

    uint32_t lo = ((uint32_t)(off_words << 2)) | 0x01; /* type = 1 */
    uint32_t hi = (uint32_t)elem_size | (count << 3);

    write_le32(buf + ptr_offset, lo);
    write_le32(buf + ptr_offset + 4, hi);
}

int capnp_write_text(capnp_builder_t *b, size_t ptr_offset, const char *text)
{
    if (!text || !text[0]) {
        /* Null pointer (all zeros) — already zeroed by init */
        memset(b->buf + ptr_offset, 0, 8);
        return 0;
    }
    size_t slen = strlen(text);
    size_t byte_count = slen + 1; /* include NUL */
    size_t words = (byte_count + 7) / 8;

    int data_off = capnp_alloc(b, words);
    if (data_off < 0) return -1;

    memcpy(b->buf + data_off, text, slen);
    b->buf[data_off + slen] = '\0'; /* NUL terminator */

    /* Text = byte list (elem_size=2) with count including NUL */
    capnp_write_list_ptr(b->buf, ptr_offset, (size_t)data_off, 2, (uint32_t)byte_count);
    return 0;
}

int capnp_write_data(capnp_builder_t *b, size_t ptr_offset,
                     const uint8_t *data, size_t len)
{
    if (!data || len == 0) {
        memset(b->buf + ptr_offset, 0, 8);
        return 0;
    }
    size_t words = (len + 7) / 8;

    int data_off = capnp_alloc(b, words);
    if (data_off < 0) return -1;

    memcpy(b->buf + data_off, data, len);

    /* Data = byte list (elem_size=2) without NUL */
    capnp_write_list_ptr(b->buf, ptr_offset, (size_t)data_off, 2, (uint32_t)len);
    return 0;
}

size_t capnp_finalize(const capnp_builder_t *b, uint8_t *out, size_t out_cap)
{
    /*
     * Wire format:
     *   uint32  segment_count - 1   (= 0 for single segment)
     *   uint32  segment_0_size      (in words)
     *   [padding to 8-byte boundary — already satisfied for 1 segment: 4+4=8]
     *   byte[]  segment_0_data
     */
    size_t seg_words = align8(b->pos) / 8;
    size_t seg_bytes = seg_words * 8;
    size_t header_bytes = 8; /* 4 (count-1) + 4 (size) = 8 */
    size_t total = header_bytes + seg_bytes;

    if (total > out_cap) {
        ESP_LOGE(TAG, "finalize overflow: need %zu, cap %zu", total, out_cap);
        return 0;
    }

    memset(out, 0, total);
    write_le32(out, 0);                    /* segment_count - 1 */
    write_le32(out + 4, (uint32_t)seg_words); /* segment 0 size in words */
    memcpy(out + header_bytes, b->buf, b->pos);

    return total;
}

/* ────────────────────────────────────────────────────────────────
 *  Reader
 * ──────────────────────────────────────────────────────────────── */

int capnp_read_message(const uint8_t *data, size_t len, capnp_reader_t *r)
{
    if (len < 8) {
        ESP_LOGE(TAG, "message too short: %zu bytes", len);
        return -1;
    }

    uint32_t num_segs_minus1 = read_le32(data);
    if (num_segs_minus1 != 0) {
        /* We only support single-segment messages */
        ESP_LOGE(TAG, "multi-segment messages not supported (got %u+1 segments)",
                 num_segs_minus1);
        return -1;
    }

    uint32_t seg0_words = read_le32(data + 4);
    size_t seg0_bytes = (size_t)seg0_words * 8;

    /* Header is 8 bytes (4 for count-1, 4 for seg0 size).
     * For an odd number of segment-size entries we'd need 4 bytes padding,
     * but for single-segment it's already aligned. */
    size_t header_size = 8;

    if (header_size + seg0_bytes > len) {
        ESP_LOGE(TAG, "segment overflows message: header %zu + seg %zu > %zu",
                 header_size, seg0_bytes, len);
        return -1;
    }

    r->seg = data + header_size;
    r->seg_len = seg0_bytes;
    return 0;
}

int capnp_read_struct_ptr(const capnp_reader_t *r, size_t ptr_offset,
                          size_t *struct_offset,
                          uint16_t *data_words, uint16_t *ptr_count)
{
    if (ptr_offset + 8 > r->seg_len) {
        ESP_LOGE(TAG, "struct ptr out of bounds at %zu", ptr_offset);
        return -1;
    }

    uint32_t lo = read_le32(r->seg + ptr_offset);
    uint32_t hi = read_le32(r->seg + ptr_offset + 4);

    /* Check for null pointer */
    if (lo == 0 && hi == 0) {
        return -1;
    }

    /* Check type bits [0..1] == 0 (struct) */
    if ((lo & 3) != 0) {
        ESP_LOGE(TAG, "expected struct pointer, got type %u at offset %zu",
                 lo & 3, ptr_offset);
        return -1;
    }

    /* Offset in words (signed 30-bit field at bits [2..31]) */
    int32_t off_words = (int32_t)lo >> 2;

    *data_words = (uint16_t)(hi & 0xFFFF);
    *ptr_count  = (uint16_t)(hi >> 16);

    /* Absolute byte offset = ptr_offset + 8 (past this pointer) + off_words * 8 */
    *struct_offset = ptr_offset + 8 + (size_t)((int64_t)off_words * 8);

    return 0;
}

const char *capnp_read_text(const capnp_reader_t *r, size_t ptr_offset,
                            size_t *out_len)
{
    if (ptr_offset + 8 > r->seg_len) return NULL;

    uint32_t lo = read_le32(r->seg + ptr_offset);
    uint32_t hi = read_le32(r->seg + ptr_offset + 4);

    if (lo == 0 && hi == 0) {
        if (out_len) *out_len = 0;
        return NULL;
    }

    /* Must be list pointer (type = 1) */
    if ((lo & 3) != 1) {
        ESP_LOGE(TAG, "expected list pointer for text at %zu, got type %u",
                 ptr_offset, lo & 3);
        return NULL;
    }

    int32_t off_words = (int32_t)lo >> 2;
    uint8_t elem_sz = hi & 7;
    uint32_t count = hi >> 3;

    if (elem_sz != 2) { /* byte list */
        ESP_LOGE(TAG, "expected byte list (elem_size=2) for text, got %u", elem_sz);
        return NULL;
    }

    size_t data_offset = ptr_offset + 8 + (size_t)((int64_t)off_words * 8);
    if (data_offset + count > r->seg_len) {
        ESP_LOGE(TAG, "text data out of bounds");
        return NULL;
    }

    /* Text includes a NUL terminator in the count */
    if (out_len) {
        *out_len = (count > 0) ? count - 1 : 0;
    }
    return (const char *)(r->seg + data_offset);
}

const uint8_t *capnp_read_data(const capnp_reader_t *r, size_t ptr_offset,
                               size_t *out_len)
{
    if (ptr_offset + 8 > r->seg_len) return NULL;

    uint32_t lo = read_le32(r->seg + ptr_offset);
    uint32_t hi = read_le32(r->seg + ptr_offset + 4);

    if (lo == 0 && hi == 0) {
        if (out_len) *out_len = 0;
        return NULL;
    }

    if ((lo & 3) != 1) {
        ESP_LOGE(TAG, "expected list pointer for data at %zu", ptr_offset);
        return NULL;
    }

    int32_t off_words = (int32_t)lo >> 2;
    uint8_t elem_sz = hi & 7;
    uint32_t count = hi >> 3;

    if (elem_sz != 2) {
        ESP_LOGE(TAG, "expected byte list (elem_size=2) for data, got %u", elem_sz);
        return NULL;
    }

    size_t data_offset = ptr_offset + 8 + (size_t)((int64_t)off_words * 8);
    if (data_offset + count > r->seg_len) {
        ESP_LOGE(TAG, "data out of bounds");
        return NULL;
    }

    if (out_len) *out_len = count;
    return r->seg + data_offset;
}

uint16_t capnp_read_uint16(const capnp_reader_t *r,
                           size_t struct_data_offset, size_t byte_offset)
{
    size_t off = struct_data_offset + byte_offset;
    if (off + 2 > r->seg_len) return 0;
    return read_le16(r->seg + off);
}

uint8_t capnp_read_uint8(const capnp_reader_t *r,
                         size_t struct_data_offset, size_t byte_offset)
{
    size_t off = struct_data_offset + byte_offset;
    if (off + 1 > r->seg_len) return 0;
    return r->seg[off];
}

bool capnp_read_bool(const capnp_reader_t *r,
                     size_t struct_data_offset, size_t byte_offset, int bit)
{
    size_t off = struct_data_offset + byte_offset;
    if (off + 1 > r->seg_len) return false;
    return (r->seg[off] >> bit) & 1;
}

/* ────────────────────────────────────────────────────────────────
 *  Wire message size helper
 * ──────────────────────────────────────────────────────────────── */

size_t capnp_wire_message_size(const uint8_t *data, size_t len)
{
    if (len < 8) return 0;
    uint32_t num_segs_minus1 = read_le32(data);
    if (num_segs_minus1 != 0) return 0; /* single-segment only */
    uint32_t seg0_words = read_le32(data + 4);
    size_t total = 8 + (size_t)seg0_words * 8;
    if (total > len) return 0;
    return total;
}

/* ────────────────────────────────────────────────────────────────
 *  High-level: Decode ConnectRequest
 *
 *  Cap'n Proto schema (from tunnelrpc.capnp):
 *    struct ConnectRequest {
 *        dest     @0 :Text;             # pointer[0]
 *        type     @1 :ConnectionType;   # data[0..2] uint16 enum
 *        metadata @2 :List(Metadata);   # pointer[1]
 *    }
 *    struct Metadata {
 *        key @0 :Text;   # pointer[0]
 *        val @1 :Text;   # pointer[1]
 *    }
 *
 *  ConnectRequest layout: data_words=1, ptr_count=2
 * ──────────────────────────────────────────────────────────────── */

int capnp_decode_connect_request(const uint8_t *data, size_t len,
                                 cf_connect_request_t *req)
{
    capnp_reader_t reader;
    memset(req, 0, sizeof(*req));

    if (capnp_read_message(data, len, &reader) != 0) {
        ESP_LOGE(TAG, "failed to parse ConnectRequest message");
        return -1;
    }

    /* Root struct pointer is at segment offset 0 */
    size_t root_off;
    uint16_t root_dw, root_pc;
    if (capnp_read_struct_ptr(&reader, 0, &root_off, &root_dw, &root_pc) != 0) {
        ESP_LOGE(TAG, "failed to read ConnectRequest root pointer");
        return -1;
    }

    ESP_LOGD(TAG, "ConnectRequest root: off=%zu dw=%u pc=%u", root_off, root_dw, root_pc);

    /* Read type (uint16 enum at data offset 0) */
    if (root_dw >= 1) {
        uint16_t conn_type = capnp_read_uint16(&reader, root_off, 0);
        req->type = (cf_connection_type_t)conn_type;
    }

    /* Pointer section starts after data section */
    size_t ptr_section = root_off + (size_t)root_dw * 8;

    /* pointer[0] = dest (Text) */
    if (root_pc >= 1) {
        size_t dest_len = 0;
        const char *dest = capnp_read_text(&reader, ptr_section + 0, &dest_len);
        if (dest && dest_len > 0) {
            size_t copy_len = dest_len < sizeof(req->dest) - 1 ? dest_len : sizeof(req->dest) - 1;
            memcpy(req->dest, dest, copy_len);
            req->dest[copy_len] = '\0';
        }
        ESP_LOGD(TAG, "ConnectRequest dest: %s", req->dest);
    }

    /* pointer[1] = metadata (List(Metadata)) */
    if (root_pc >= 2) {
        size_t meta_ptr_off = ptr_section + 8;

        if (meta_ptr_off + 8 > reader.seg_len) {
            ESP_LOGW(TAG, "metadata pointer out of bounds");
            return 0;
        }

        uint32_t lo = read_le32(reader.seg + meta_ptr_off);
        uint32_t hi = read_le32(reader.seg + meta_ptr_off + 4);

        if (lo == 0 && hi == 0) {
            /* No metadata */
            return 0;
        }

        if ((lo & 3) != 1) {
            ESP_LOGE(TAG, "metadata: expected list pointer, got type %u", lo & 3);
            return -1;
        }

        int32_t off_words = (int32_t)lo >> 2;
        uint8_t elem_sz = hi & 7;
        uint32_t total_words_or_count = hi >> 3;

        size_t list_data_off = meta_ptr_off + 8 + (size_t)((int64_t)off_words * 8);

        if (elem_sz == 7) {
            /* Composite list: first word is tag word */
            if (list_data_off + 8 > reader.seg_len) {
                ESP_LOGE(TAG, "metadata composite tag out of bounds");
                return -1;
            }

            uint32_t tag_lo = read_le32(reader.seg + list_data_off);
            uint32_t tag_hi = read_le32(reader.seg + list_data_off + 4);

            /* Tag word has struct pointer format: offset=element_count */
            uint32_t elem_count = (uint32_t)((int32_t)tag_lo >> 2);
            uint16_t elem_dw = (uint16_t)(tag_hi & 0xFFFF);
            uint16_t elem_pc = (uint16_t)(tag_hi >> 16);
            size_t elem_stride = ((size_t)elem_dw + (size_t)elem_pc) * 8;

            ESP_LOGD(TAG, "metadata: %u elements, dw=%u pc=%u stride=%zu",
                     elem_count, elem_dw, elem_pc, elem_stride);

            /* Elements start after the tag word */
            size_t elem_base = list_data_off + 8;

            for (uint32_t i = 0; i < elem_count && i < CF_MAX_METADATA; i++) {
                size_t e_off = elem_base + i * elem_stride;
                /* Metadata struct: data_words=0, ptr_count=2
                 * pointer[0] = key (text)
                 * pointer[1] = val (text) */
                size_t e_ptr_section = e_off + (size_t)elem_dw * 8;

                if (e_ptr_section + 16 > reader.seg_len) break;

                size_t key_len = 0, val_len = 0;
                const char *key = capnp_read_text(&reader, e_ptr_section + 0, &key_len);
                const char *val = capnp_read_text(&reader, e_ptr_section + 8, &val_len);

                if (key && key_len > 0) {
                    size_t kl = key_len < sizeof(req->metadata[i].key) - 1
                                    ? key_len : sizeof(req->metadata[i].key) - 1;
                    memcpy(req->metadata[i].key, key, kl);
                    req->metadata[i].key[kl] = '\0';
                }
                if (val && val_len > 0) {
                    size_t vl = val_len < sizeof(req->metadata[i].val) - 1
                                    ? val_len : sizeof(req->metadata[i].val) - 1;
                    memcpy(req->metadata[i].val, val, vl);
                    req->metadata[i].val[vl] = '\0';
                }

                req->metadata_count++;
                ESP_LOGD(TAG, "  meta[%u]: %s = %s",
                         i, req->metadata[i].key, req->metadata[i].val);
            }
        } else {
            ESP_LOGW(TAG, "metadata list has elem_size=%u, expected 7 (composite)",
                     elem_sz);
        }
    }

    return 0;
}

/* ────────────────────────────────────────────────────────────────
 *  High-level: Encode ConnectResponse
 *
 *  Cap'n Proto schema:
 *    struct ConnectResponse {
 *        error    @0 :Text;             # pointer[0]
 *        metadata @1 :List(Metadata);   # pointer[1]
 *    }
 *    struct Metadata {
 *        key @0 :Text;   # pointer[0]
 *        val @1 :Text;   # pointer[1]
 *    }
 *
 *  ConnectResponse layout: data_words=0, ptr_count=2
 * ──────────────────────────────────────────────────────────────── */

int capnp_encode_connect_response(const cf_connect_response_t *resp,
                                  uint8_t *buf, size_t buf_cap,
                                  size_t *out_len)
{
    /* Preamble: signature + version */
    const size_t preamble_len = 6 + 2; /* signature + "01" */
    if (buf_cap < preamble_len + 64) {
        ESP_LOGE(TAG, "buffer too small for ConnectResponse");
        return -1;
    }

    memcpy(buf, CF_DATA_STREAM_SIGNATURE, 6);
    buf[6] = '0';
    buf[7] = '1';

    /* Build Cap'n Proto message */
    uint8_t work[2048];
    capnp_builder_t builder;
    capnp_builder_init(&builder, work, sizeof(work));

    /* Allocate root struct pointer slot (1 word at offset 0) */
    int root_ptr_off = capnp_alloc(&builder, 1);
    if (root_ptr_off < 0) return -1;

    /* Allocate ConnectResponse struct: 0 data words + 2 pointers */
    int struct_off = capnp_alloc(&builder, 0 + 2);
    if (struct_off < 0) return -1;

    /* Write root pointer -> struct */
    capnp_write_struct_ptr(builder.buf, (size_t)root_ptr_off,
                           (size_t)struct_off, 0, 2);

    size_t ptr0_off = (size_t)struct_off + 0;  /* pointer[0] = error */
    size_t ptr1_off = (size_t)struct_off + 8;  /* pointer[1] = metadata */

    /* Write error text at pointer[0] */
    if (resp->error[0] != '\0') {
        if (capnp_write_text(&builder, ptr0_off, resp->error) != 0)
            return -1;
    }

    /* Write metadata list at pointer[1] */
    if (resp->metadata_count > 0) {
        /*
         * Composite list format:
         *   list pointer -> tag_word + N * element_words
         *   tag_word: struct pointer format with offset=N, dw=0, pc=2
         *   elements: each is 0 data words + 2 pointer words
         */
        size_t n = resp->metadata_count;
        uint16_t elem_dw = 0;
        uint16_t elem_pc = 2;
        size_t elem_words = (size_t)elem_dw + (size_t)elem_pc;
        size_t total_list_words = 1 + n * elem_words; /* 1 tag + N elements */

        int list_off = capnp_alloc(&builder, total_list_words);
        if (list_off < 0) return -1;

        /* Write tag word (struct pointer format: offset=element_count) */
        uint32_t tag_lo = (uint32_t)((uint32_t)n << 2) | 0x00; /* type=struct */
        uint32_t tag_hi = (uint32_t)elem_dw | ((uint32_t)elem_pc << 16);
        write_le32(builder.buf + list_off, tag_lo);
        write_le32(builder.buf + list_off + 4, tag_hi);

        /* Write list pointer: elem_size=7 (composite), count=total words including tag */
        capnp_write_list_ptr(builder.buf, ptr1_off,
                             (size_t)list_off, 7, (uint32_t)total_list_words);

        /* Write each Metadata element */
        for (size_t i = 0; i < n; i++) {
            size_t e_off = (size_t)list_off + 8 + i * elem_words * 8;
            /* Element has 0 data words, 2 pointers */
            size_t e_ptr0 = e_off + (size_t)elem_dw * 8; /* key */
            size_t e_ptr1 = e_ptr0 + 8;                   /* val */

            if (capnp_write_text(&builder, e_ptr0, resp->metadata[i].key) != 0)
                return -1;
            if (capnp_write_text(&builder, e_ptr1, resp->metadata[i].val) != 0)
                return -1;
        }
    }

    /* Finalize Cap'n Proto message after the preamble */
    size_t capnp_len = capnp_finalize(&builder,
                                       buf + preamble_len,
                                       buf_cap - preamble_len);
    if (capnp_len == 0) return -1;

    *out_len = preamble_len + capnp_len;
    ESP_LOGD(TAG, "encoded ConnectResponse: %zu bytes total (%zu capnp)",
             *out_len, capnp_len);
    return 0;
}
