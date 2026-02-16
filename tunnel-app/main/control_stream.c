/*
 * Phase 4: Control stream – tunnel registration via Cap'n Proto RPC.
 *
 * Implements the minimal subset of Cap'n Proto RPC needed to register a
 * tunnel connection with Cloudflare edge:
 *   - Bootstrap message (acquire root interface capability)
 *   - Call message      (invoke RegisterConnection, method 0 on
 *                         interface 0xf71695ec7fe85497)
 *   - Return message    (parse ConnectionResponse)
 *
 * The wire format is built by hand using capnp_minimal.h primitives.
 */

#include "control_stream.h"
#include "capnp_minimal.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <esp_log.h>

static const char *TAG = "ctrl_stream";

/* Interface ID for TunnelServer.registerConnection */
static const uint64_t TUNNEL_SERVER_IID = 0xf71695ec7fe85497ULL;

/* ────────────────────────────────────────────────────────────────
 *  Little-endian writers (duplicated here for self-containedness)
 * ──────────────────────────────────────────────────────────────── */

static inline void w_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v); p[1] = (uint8_t)(v >> 8);
}
static inline void w_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v); p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static inline void w_le64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (i * 8));
}
static inline uint16_t r_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static inline uint32_t r_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ────────────────────────────────────────────────────────────────
 *  Encode Bootstrap message
 *
 *  rpc.capnp Message struct: data_words=1, ptr_count=1
 *    data[0..2]  = union discriminant (8 = bootstrap)
 *    pointer[0]  = Bootstrap struct
 *
 *  Bootstrap struct: data_words=1, ptr_count=1
 *    data[0..4]  = questionId (uint32)
 *    pointer[0]  = deprecatedObjectId (null)
 * ──────────────────────────────────────────────────────────────── */

static int encode_bootstrap(uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t work[256];
    capnp_builder_t b;
    capnp_builder_init(&b, work, sizeof(work));

    /* Root pointer slot */
    int rp = capnp_alloc(&b, 1);
    if (rp < 0) return -1;

    /* Message struct: 1 data word + 1 pointer */
    int msg = capnp_alloc(&b, 1 + 1);
    if (msg < 0) return -1;
    capnp_write_struct_ptr(b.buf, (size_t)rp, (size_t)msg, 1, 1);

    /* data[0..2] = 8 (bootstrap discriminant — from Go generated code) */
    w_le16(b.buf + msg, 8);

    /* pointer[0] = Bootstrap struct (data_words=1, ptr_count=1) */
    size_t msg_ptr0 = (size_t)msg + 8; /* after 1 data word */
    int boot = capnp_alloc(&b, 1 + 1);
    if (boot < 0) return -1;
    capnp_write_struct_ptr(b.buf, msg_ptr0, (size_t)boot, 1, 1);

    /* Bootstrap.questionId = 0 (already zero) */
    /* Bootstrap.deprecatedObjectId = null pointer (already zero) */

    *out_len = capnp_finalize(&b, out, out_cap);
    if (*out_len == 0) return -1;

    ESP_LOGD(TAG, "bootstrap message: %zu bytes", *out_len);
    return 0;
}

/* ────────────────────────────────────────────────────────────────
 *  Encode Call message
 *
 *  Message: data[0..2] = 2 (call), pointer[0] = Call struct
 *
 *  Call struct (data_words=3, ptr_count=3):
 *    data[0..4]   = questionId (uint32, = 1)
 *    data[4..6]   = methodId (uint16: 0 = registerConnection)
 *    data[6..8]   = sendResultsTo union discriminant (0 = caller)
 *    data[8..16]  = interfaceId (uint64: 0xf71695ec7fe85497)
 *    pointer[0]   = target (MessageTarget)
 *    pointer[1]   = params (Payload)
 *    pointer[2]   = sendResultsTo.thirdParty (null)
 *
 *  MessageTarget (promisedAnswer for pipelined Bootstrap):
 *    data_words=1, ptr_count=1
 *    data[0..4] = importedCap value (unused when discriminant=1)
 *    data[4..6] = union discriminant (1 = promisedAnswer)
 *    pointer[0] = PromisedAnswer struct
 *
 *  PromisedAnswer: data_words=1, ptr_count=1
 *    data[0..4] = questionId (uint32, = 0, refs Bootstrap)
 *    pointer[0] = transform (null = empty)
 *
 *  Payload: data_words=0, ptr_count=2
 *    pointer[0] = content (AnyPointer = RegisterConnection params)
 *    pointer[1] = capTable (List(CapDescriptor), empty)
 *
 *  RegisterConnection params (data_words=1, ptr_count=3):
 *    data[0] = connIndex (uint8)
 *    pointer[0] = TunnelAuth
 *    pointer[1] = tunnelId (data)
 *    pointer[2] = ConnectionOptions
 * ──────────────────────────────────────────────────────────────── */

static int encode_call(const cf_tunnel_auth_t *auth,
                       const uint8_t *tunnel_id, size_t tunnel_id_len,
                       uint8_t conn_index,
                       const cf_conn_options_t *options,
                       uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t work[4096];
    capnp_builder_t b;
    capnp_builder_init(&b, work, sizeof(work));

    /* ── Root pointer slot ─────────────────────────────────────── */
    int rp = capnp_alloc(&b, 1);
    if (rp < 0) return -1;

    /* ── Message struct: dw=1, pc=1 ───────────────────────────── */
    int msg = capnp_alloc(&b, 1 + 1);
    if (msg < 0) return -1;
    capnp_write_struct_ptr(b.buf, (size_t)rp, (size_t)msg, 1, 1);
    w_le16(b.buf + msg, 2); /* union discriminant = call */

    size_t msg_ptr0 = (size_t)msg + 8;

    /* ── Call struct: dw=3, pc=3 ──────────────────────────────── */
    int call = capnp_alloc(&b, 3 + 3);
    if (call < 0) return -1;
    capnp_write_struct_ptr(b.buf, msg_ptr0, (size_t)call, 3, 3);

    /* Call data section (from Go generated code):
     *   Uint32(0)  = questionId
     *   Uint16(4)  = methodId
     *   Uint16(6)  = sendResultsTo discriminant
     *   Uint64(8)  = interfaceId
     *   Bit(128)   = allowThirdPartyTailCall */
    w_le32(b.buf + call + 0, 1);       /* questionId = 1 */
    w_le16(b.buf + call + 4, 0);       /* methodId = 0 (registerConnection) */
    /* data[6..8] = sendResultsTo discriminant: 0 = caller (already 0) */
    w_le64(b.buf + call + 8, TUNNEL_SERVER_IID); /* interfaceId */

    size_t call_ptrs = (size_t)call + 3 * 8; /* pointer section after 3 data words */

    /* ── Call.target = MessageTarget (promisedAnswer) ─────────── */
    /* MessageTarget: dw=1, pc=1
     *   Uint32(0) = importedCap (unused for promisedAnswer)
     *   Uint16(4) = which discriminant (1 = promisedAnswer)
     *   pointer[0] = PromisedAnswer struct */
    int target = capnp_alloc(&b, 1 + 1);
    if (target < 0) return -1;
    capnp_write_struct_ptr(b.buf, call_ptrs + 0, (size_t)target, 1, 1);
    w_le16(b.buf + target + 4, 1); /* which = promisedAnswer */

    /* PromisedAnswer: dw=1, pc=1
     *   Uint32(0) = questionId (= 0, references Bootstrap question)
     *   pointer[0] = transform (null = empty list) */
    int pa = capnp_alloc(&b, 1 + 1);
    if (pa < 0) return -1;
    capnp_write_struct_ptr(b.buf, (size_t)target + 8, (size_t)pa, 1, 1);
    w_le32(b.buf + pa, 0); /* questionId = 0 (bootstrap question) */
    /* transform pointer[0] = null (already zeroed) */

    /* ── Call.params = Payload: dw=0, pc=2 ────────────────────── */
    int payload = capnp_alloc(&b, 0 + 2);
    if (payload < 0) return -1;
    capnp_write_struct_ptr(b.buf, call_ptrs + 8, (size_t)payload, 0, 2);

    size_t payload_ptr0 = (size_t)payload + 0;  /* content */
    size_t payload_ptr1 = (size_t)payload + 8;  /* capTable */

    /* capTable = empty list (null pointer is fine for empty) */
    /* Leave payload_ptr1 as null (all zeros) */
    (void)payload_ptr1;

    /* ── Payload.content = RegisterConnection params ──────────── */
    /* RegisterConnection params: dw=1, pc=3 */
    int params = capnp_alloc(&b, 1 + 3);
    if (params < 0) return -1;
    capnp_write_struct_ptr(b.buf, payload_ptr0, (size_t)params, 1, 3);

    /* params.connIndex (uint8 at data[0]) */
    b.buf[params] = conn_index;

    size_t params_ptrs = (size_t)params + 1 * 8; /* after 1 data word */

    /* ── params.pointer[0] = TunnelAuth: dw=0, pc=2 ──────────── */
    int ta = capnp_alloc(&b, 0 + 2);
    if (ta < 0) return -1;
    capnp_write_struct_ptr(b.buf, params_ptrs + 0, (size_t)ta, 0, 2);

    /* TunnelAuth.accountTag (text) at pointer[0] */
    if (auth->account_tag) {
        if (capnp_write_text(&b, (size_t)ta + 0, auth->account_tag) != 0)
            return -1;
    }
    /* TunnelAuth.tunnelSecret (data) at pointer[1] */
    if (auth->tunnel_secret && auth->tunnel_secret_len > 0) {
        if (capnp_write_data(&b, (size_t)ta + 8,
                             auth->tunnel_secret, auth->tunnel_secret_len) != 0)
            return -1;
    }

    /* ── params.pointer[1] = tunnelId (data, 16 bytes UUID) ──── */
    if (tunnel_id && tunnel_id_len > 0) {
        if (capnp_write_data(&b, params_ptrs + 8, tunnel_id, tunnel_id_len) != 0)
            return -1;
    }

    /* ── params.pointer[2] = ConnectionOptions: dw=1, pc=2 ───── */
    int co = capnp_alloc(&b, 1 + 2);
    if (co < 0) return -1;
    capnp_write_struct_ptr(b.buf, params_ptrs + 16, (size_t)co, 1, 2);

    if (options) {
        /* data[0] bit 0 = replaceExisting */
        if (options->replace_existing)
            b.buf[co] |= 0x01;
        /* data[1] = compressionQuality */
        b.buf[co + 1] = options->compression_quality;
        /* data[2] = numPreviousAttempts */
        b.buf[co + 2] = options->num_previous_attempts;

        size_t co_ptrs = (size_t)co + 1 * 8;

        /* ── ConnectionOptions.pointer[0] = ClientInfo: dw=0, pc=4 */
        int ci = capnp_alloc(&b, 0 + 4);
        if (ci < 0) return -1;
        capnp_write_struct_ptr(b.buf, co_ptrs + 0, (size_t)ci, 0, 4);

        /* ClientInfo.clientId (data) at pointer[0] */
        if (options->client_id) {
            if (capnp_write_data(&b, (size_t)ci + 0,
                                 options->client_id, 16) != 0)
                return -1;
        }
        /* ClientInfo.features (list of text) at pointer[1] — empty / null */
        /* ClientInfo.version (text) at pointer[2] */
        if (options->version) {
            if (capnp_write_text(&b, (size_t)ci + 16, options->version) != 0)
                return -1;
        }
        /* ClientInfo.arch (text) at pointer[3] */
        if (options->arch) {
            if (capnp_write_text(&b, (size_t)ci + 24, options->arch) != 0)
                return -1;
        }

        /* ConnectionOptions.pointer[1] = originLocalIp (data, null) */
        /* Already zero (null pointer) */
    }

    /* Call.sendResultsTo = null (pointer[2], already zero) */

    /* ── Finalize ─────────────────────────────────────────────── */
    *out_len = capnp_finalize(&b, out, out_cap);
    if (*out_len == 0) return -1;

    ESP_LOGD(TAG, "call message: %zu bytes", *out_len);
    return 0;
}

/* ────────────────────────────────────────────────────────────────
 *  Public: encode registration sequence
 * ──────────────────────────────────────────────────────────────── */

int control_stream_encode_register(
    const cf_tunnel_auth_t *auth,
    const uint8_t *tunnel_id, size_t tunnel_id_len,
    uint8_t conn_index,
    const cf_conn_options_t *options,
    uint8_t *buf, size_t buf_cap, size_t *out_len)
{
    size_t total = 0;

    /* 1. Bootstrap message */
    size_t boot_len = 0;
    if (encode_bootstrap(buf, buf_cap, &boot_len) != 0) {
        ESP_LOGE(TAG, "failed to encode bootstrap message");
        return -1;
    }
    total += boot_len;

    /* 2. Call message */
    size_t call_len = 0;
    if (encode_call(auth, tunnel_id, tunnel_id_len, conn_index, options,
                    buf + total, buf_cap - total, &call_len) != 0) {
        ESP_LOGE(TAG, "failed to encode call message");
        return -1;
    }
    total += call_len;

    *out_len = total;
    ESP_LOGI(TAG, "registration request: %zu bytes (bootstrap=%zu, call=%zu)",
             total, boot_len, call_len);
    return 0;
}

/* ────────────────────────────────────────────────────────────────
 *  Decode registration response
 *
 *  Expected: Cap'n Proto RPC Return message.
 *
 *  Message: data[0..2] union discriminant
 *    3 = "return"
 *    pointer[0] = Return struct
 *
 *  Return struct (data_words=2, ptr_count=1):
 *    data[0..4]  = answerId (uint32)
 *    data[4]     = releaseParamCaps (bool, bit 0)
 *    data[6..8]  = union discriminant
 *                    0 = results, 1 = exception, 2 = canceled, ...
 *    pointer[0]  = union value
 *
 *  For results (discriminant 0):
 *    pointer[0] = Payload (dw=0, pc=2)
 *      pointer[0] = content (AnyPointer)
 *      pointer[1] = capTable (List(CapDescriptor))
 *
 *  For Bootstrap Return, content is a capability pointer (type 3) —
 *  we skip this message since the Call uses pipelining.
 *
 *  For Call Return, content = registerConnection_Results wrapper:
 *    registerConnection_Results (dw=0, pc=1):
 *      pointer[0] = ConnectionResponse
 *
 *  ConnectionResponse (dw=1, pc=1):
 *    data[0..2] = union discriminant
 *      0 = error (pointer[0] = ConnectionError)
 *      1 = connectionDetails (pointer[0] = ConnectionDetails)
 *
 *  ConnectionDetails (dw=1, pc=2):
 *    data[0] bit 0 = tunnelIsRemotelyManaged
 *    pointer[0] = uuid (data, 16 bytes)
 *    pointer[1] = locationName (text)
 *
 *  ConnectionError (dw=2, pc=1):
 *    data[0..8]  = retryAfter (int64)
 *    data[8] bit 0 = shouldRetry (bool, = Bit(64))
 *    pointer[0] = cause (text)
 * ──────────────────────────────────────────────────────────────── */

int control_stream_decode_response(const uint8_t *data, size_t len,
                                   cf_registration_result_t *result)
{
    memset(result, 0, sizeof(*result));

    capnp_reader_t reader;
    if (capnp_read_message(data, len, &reader) != 0) {
        ESP_LOGE(TAG, "failed to parse response message");
        snprintf(result->error, sizeof(result->error), "invalid capnp message");
        return -1;
    }

    /* Root struct pointer at offset 0 */
    size_t root_off;
    uint16_t root_dw, root_pc;
    if (capnp_read_struct_ptr(&reader, 0, &root_off, &root_dw, &root_pc) != 0) {
        ESP_LOGE(TAG, "failed to read root struct pointer");
        snprintf(result->error, sizeof(result->error), "invalid root pointer");
        return -1;
    }

    /* Message union discriminant at data[0..2] */
    uint16_t msg_which = capnp_read_uint16(&reader, root_off, 0);
    ESP_LOGD(TAG, "RPC message type: %u (expected 3=return)", msg_which);

    if (msg_which != 3) {
        ESP_LOGE(TAG, "unexpected RPC message type %u (expected 3=return)", msg_which);
        snprintf(result->error, sizeof(result->error),
                 "unexpected RPC message type %u", msg_which);
        return -1;
    }

    /* pointer[0] = Return struct */
    size_t msg_ptrs = root_off + (size_t)root_dw * 8;
    size_t ret_off;
    uint16_t ret_dw, ret_pc;
    if (capnp_read_struct_ptr(&reader, msg_ptrs + 0, &ret_off, &ret_dw, &ret_pc) != 0) {
        ESP_LOGE(TAG, "failed to read Return struct pointer");
        snprintf(result->error, sizeof(result->error), "invalid Return pointer");
        return -1;
    }

    /* Return.answerId */
    uint32_t answer_id = 0;
    if (ret_dw >= 1) {
        answer_id = r_le32(reader.seg + ret_off);
    }
    ESP_LOGD(TAG, "Return.answerId = %u", answer_id);

    /* Return union discriminant at data[6..8] */
    uint16_t ret_which = 0;
    if (ret_dw >= 1) {
        ret_which = capnp_read_uint16(&reader, ret_off, 6);
    }
    ESP_LOGD(TAG, "Return union discriminant: %u", ret_which);

    size_t ret_ptrs = ret_off + (size_t)ret_dw * 8;

    if (ret_which == 1) {
        /* Exception */
        size_t exc_off;
        uint16_t exc_dw, exc_pc;
        if (capnp_read_struct_ptr(&reader, ret_ptrs + 0,
                                  &exc_off, &exc_dw, &exc_pc) == 0) {
            /* Exception.reason (text) at pointer[0] */
            size_t exc_ptrs_off = exc_off + (size_t)exc_dw * 8;
            if (exc_pc >= 1) {
                size_t reason_len = 0;
                const char *reason = capnp_read_text(&reader, exc_ptrs_off, &reason_len);
                if (reason && reason_len > 0) {
                    size_t clen = reason_len < sizeof(result->error) - 1
                                      ? reason_len : sizeof(result->error) - 1;
                    memcpy(result->error, reason, clen);
                    result->error[clen] = '\0';
                }
            }
        }
        ESP_LOGE(TAG, "registration exception: %s", result->error);
        result->should_retry = true;
        return 0;
    }

    if (ret_which == 2) {
        /* Canceled */
        snprintf(result->error, sizeof(result->error), "registration canceled");
        ESP_LOGE(TAG, "registration canceled");
        return 0;
    }

    if (ret_which != 0) {
        snprintf(result->error, sizeof(result->error),
                 "unknown Return type %u", ret_which);
        ESP_LOGE(TAG, "unknown Return discriminant %u", ret_which);
        return -1;
    }

    /* ret_which == 0: results */
    /* pointer[0] = Payload (dw=0, pc=2) */
    size_t payload_off;
    uint16_t payload_dw, payload_pc;
    if (capnp_read_struct_ptr(&reader, ret_ptrs + 0,
                              &payload_off, &payload_dw, &payload_pc) != 0) {
        ESP_LOGE(TAG, "failed to read Payload struct");
        snprintf(result->error, sizeof(result->error), "invalid Payload");
        return -1;
    }

    /*
     * Payload.content (pointer[0]) = registerConnection_Results wrapper.
     * Results wrapper: dw=0, pc=1, with pointer[0] = ConnectionResponse.
     * We must dereference this wrapper to reach the actual ConnectionResponse.
     */
    size_t payload_ptrs = payload_off + (size_t)payload_dw * 8;

    /* Read the Results wrapper struct */
    size_t results_off;
    uint16_t results_dw, results_pc;
    if (capnp_read_struct_ptr(&reader, payload_ptrs + 0,
                              &results_off, &results_dw, &results_pc) != 0) {
        ESP_LOGE(TAG, "failed to read Results wrapper struct");
        snprintf(result->error, sizeof(result->error), "invalid Results wrapper");
        return -1;
    }
    ESP_LOGD(TAG, "Results wrapper: off=%zu dw=%u pc=%u",
             results_off, results_dw, results_pc);

    /* Navigate to ConnectionResponse at Results.pointer[0] */
    size_t results_ptrs = results_off + (size_t)results_dw * 8;
    size_t connresp_off;
    uint16_t connresp_dw, connresp_pc;
    if (results_pc < 1 ||
        capnp_read_struct_ptr(&reader, results_ptrs + 0,
                              &connresp_off, &connresp_dw, &connresp_pc) != 0) {
        ESP_LOGE(TAG, "failed to read ConnectionResponse struct");
        snprintf(result->error, sizeof(result->error), "invalid ConnectionResponse");
        return -1;
    }

    /* ConnectionResponse union discriminant at data[0..2] */
    uint16_t cr_which = capnp_read_uint16(&reader, connresp_off, 0);
    size_t cr_ptrs = connresp_off + (size_t)connresp_dw * 8;

    ESP_LOGD(TAG, "ConnectionResponse union: %u", cr_which);

    if (cr_which == 0) {
        /* Error case: pointer[0] = ConnectionError (dw=2, pc=1)
         *   Uint64(0)    = retryAfter (int64)
         *   Bit(64)      = shouldRetry (byte 8, bit 0)
         *   Ptr(0)       = cause (text)
         */
        size_t err_struct_off;
        uint16_t err_dw, err_pc;
        if (connresp_pc >= 1 &&
            capnp_read_struct_ptr(&reader, cr_ptrs + 0,
                                  &err_struct_off, &err_dw, &err_pc) == 0) {
            /* Try to read retryAfterNs from data section */
            if (err_dw >= 1) {
                uint32_t lo = r_le32(reader.seg + err_struct_off);
                uint32_t hi = r_le32(reader.seg + err_struct_off + 4);
                result->retry_after_ns = (int64_t)((uint64_t)lo | ((uint64_t)hi << 32));
            }
            if (err_dw >= 2) {
                /* data[8] bit 0 might be shouldRetry — read defensively */
                result->should_retry = capnp_read_bool(&reader, err_struct_off, 8, 0);
            }
            /* pointer[0] = error text */
            size_t err_ptrs = err_struct_off + (size_t)err_dw * 8;
            if (err_pc >= 1) {
                size_t err_len = 0;
                const char *err_text = capnp_read_text(&reader, err_ptrs, &err_len);
                if (err_text && err_len > 0) {
                    size_t clen = err_len < sizeof(result->error) - 1
                                      ? err_len : sizeof(result->error) - 1;
                    memcpy(result->error, err_text, clen);
                    result->error[clen] = '\0';
                }
            }
            ESP_LOGE(TAG, "registration error: %s (retry_ns=%" PRId64 " retry=%d)",
                     result->error, result->retry_after_ns, result->should_retry);
        } else {
            snprintf(result->error, sizeof(result->error),
                     "registration error (could not parse details)");
        }
        return 0;
    }

    if (cr_which == 1) {
        /* connectionDetails: pointer[0] = ConnectionDetails struct */
        size_t details_off;
        uint16_t details_dw, details_pc;
        if (capnp_read_struct_ptr(&reader, cr_ptrs + 0,
                                  &details_off, &details_dw, &details_pc) != 0) {
            ESP_LOGE(TAG, "failed to read ConnectionDetails");
            snprintf(result->error, sizeof(result->error),
                     "invalid ConnectionDetails");
            return -1;
        }

        /* data[0] bit 0 = tunnelIsRemotelyManaged */
        if (details_dw >= 1) {
            result->tunnel_is_remote = capnp_read_bool(&reader, details_off, 0, 0);
        }

        size_t details_ptrs = details_off + (size_t)details_dw * 8;

        /* pointer[0] = uuid (data, 16 bytes) */
        if (details_pc >= 1) {
            size_t uuid_len = 0;
            const uint8_t *uuid_data = capnp_read_data(&reader, details_ptrs + 0,
                                                        &uuid_len);
            if (uuid_data && uuid_len >= 16) {
                /* Format as hex string */
                snprintf(result->uuid, sizeof(result->uuid),
                         "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
                         "%02x%02x-%02x%02x%02x%02x%02x%02x",
                         uuid_data[0],  uuid_data[1],  uuid_data[2],  uuid_data[3],
                         uuid_data[4],  uuid_data[5],  uuid_data[6],  uuid_data[7],
                         uuid_data[8],  uuid_data[9],  uuid_data[10], uuid_data[11],
                         uuid_data[12], uuid_data[13], uuid_data[14], uuid_data[15]);
            } else if (uuid_data && uuid_len > 0) {
                /* Unexpected length, hex dump what we got */
                size_t hex_len = uuid_len * 2;
                if (hex_len > sizeof(result->uuid) - 1)
                    hex_len = sizeof(result->uuid) - 1;
                for (size_t i = 0; i < uuid_len && i * 2 + 1 < sizeof(result->uuid); i++) {
                    snprintf(result->uuid + i * 2, 3, "%02x", uuid_data[i]);
                }
            }
        }

        /* pointer[1] = locationName (text) */
        if (details_pc >= 2) {
            size_t loc_len = 0;
            const char *loc = capnp_read_text(&reader, details_ptrs + 8, &loc_len);
            if (loc && loc_len > 0) {
                size_t clen = loc_len < sizeof(result->location) - 1
                                  ? loc_len : sizeof(result->location) - 1;
                memcpy(result->location, loc, clen);
                result->location[clen] = '\0';
            }
        }

        result->success = true;
        ESP_LOGI(TAG, "registered: uuid=%s location=%s remote=%d",
                 result->uuid, result->location, result->tunnel_is_remote);
        return 0;
    }

    /* Unknown ConnectionResponse variant */
    snprintf(result->error, sizeof(result->error),
             "unknown ConnectionResponse type %u", cr_which);
    ESP_LOGE(TAG, "unknown ConnectionResponse discriminant %u", cr_which);
    return -1;
}
