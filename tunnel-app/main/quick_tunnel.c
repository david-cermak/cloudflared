/*
 * Quick Tunnel provisioning — self-service tunnel creation via
 * https://api.trycloudflare.com/tunnel
 *
 * Uses esp_http_client for the HTTPS POST and cJSON for parsing the
 * JSON response.  Certificate verification is skipped so no CA bundle
 * is needed (requires CONFIG_ESP_TLS_INSECURE=y +
 * CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY=y in sdkconfig).
 */

#include "quick_tunnel.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_http_client.h"
#include "cJSON.h"

static const char *TAG = "quick_tunnel";

#define API_URL  "https://api.trycloudflare.com/tunnel"
#define MAX_RESP 4096

/* ── Minimal base64 decoder ──────────────────────────────────────── */

static const uint8_t b64_lut[256] = {
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

static int b64_decode(const char *in, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t ilen = strlen(in), i = 0, o = 0;
    while (i < ilen) {
        while (i < ilen && (in[i] == '\n' || in[i] == '\r' || in[i] == ' ')) i++;
        if (i >= ilen) break;
        uint32_t s[4] = {0};
        int pad = 0;
        for (int j = 0; j < 4 && i < ilen; j++, i++) {
            if (in[i] == '=') { pad++; s[j] = 0; }
            else s[j] = b64_lut[(uint8_t)in[i]];
        }
        uint32_t t = (s[0] << 18) | (s[1] << 12) | (s[2] << 6) | s[3];
        if (o < cap) out[o++] = (uint8_t)(t >> 16);
        if (pad < 2 && o < cap) out[o++] = (uint8_t)(t >> 8);
        if (pad < 1 && o < cap) out[o++] = (uint8_t)(t);
    }
    *out_len = o;
    return 0;
}

/* ── HTTP response accumulator ───────────────────────────────────── */

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} resp_buf_t;

static esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    resp_buf_t *rb = (resp_buf_t *)evt->user_data;
    if (!rb) return ESP_OK;

    switch (evt->event_id) {
    case HTTP_EVENT_ON_DATA:
        if (rb->len + (size_t)evt->data_len < rb->cap) {
            memcpy(rb->buf + rb->len, evt->data, evt->data_len);
            rb->len += evt->data_len;
            rb->buf[rb->len] = '\0';
        }
        break;
    default:
        break;
    }
    return ESP_OK;
}

/* ── Parse the JSON response from the API ────────────────────────── */

static int parse_response(const char *json_str, quick_tunnel_result_t *r)
{
    cJSON *root = cJSON_Parse(json_str);
    if (!root) {
        ESP_LOGE(TAG, "JSON parse error");
        return -1;
    }

    cJSON *success = cJSON_GetObjectItem(root, "success");
    if (!cJSON_IsTrue(success)) {
        cJSON *errors = cJSON_GetObjectItem(root, "errors");
        if (cJSON_IsArray(errors) && cJSON_GetArraySize(errors) > 0) {
            cJSON *e0 = cJSON_GetArrayItem(errors, 0);
            cJSON *msg = cJSON_GetObjectItem(e0, "message");
            if (cJSON_IsString(msg)) {
                ESP_LOGE(TAG, "API error: %s", msg->valuestring);
            }
        }
        cJSON_Delete(root);
        return -1;
    }

    cJSON *result = cJSON_GetObjectItem(root, "result");
    if (!result) {
        ESP_LOGE(TAG, "missing 'result' in response");
        cJSON_Delete(root);
        return -1;
    }

    cJSON *jid   = cJSON_GetObjectItem(result, "id");
    cJSON *jacct = cJSON_GetObjectItem(result, "account_tag");
    cJSON *jhost = cJSON_GetObjectItem(result, "hostname");
    cJSON *jsec  = cJSON_GetObjectItem(result, "secret");

    if (!cJSON_IsString(jid) || !cJSON_IsString(jacct) || !cJSON_IsString(jhost)) {
        ESP_LOGE(TAG, "missing required string fields in result");
        cJSON_Delete(root);
        return -1;
    }

    snprintf(r->id,          sizeof(r->id),          "%s", jid->valuestring);
    snprintf(r->account_tag, sizeof(r->account_tag),  "%s", jacct->valuestring);
    snprintf(r->hostname,    sizeof(r->hostname),     "%s", jhost->valuestring);

    /* Secret: base64 string or JSON array of byte values */
    if (cJSON_IsString(jsec)) {
        b64_decode(jsec->valuestring, r->secret, sizeof(r->secret), &r->secret_len);
    } else if (cJSON_IsArray(jsec)) {
        int n = cJSON_GetArraySize(jsec);
        if ((size_t)n > sizeof(r->secret)) n = (int)sizeof(r->secret);
        for (int i = 0; i < n; i++) {
            cJSON *b = cJSON_GetArrayItem(jsec, i);
            r->secret[i] = (uint8_t)(cJSON_IsNumber(b) ? b->valueint : 0);
        }
        r->secret_len = (size_t)n;
    } else {
        ESP_LOGE(TAG, "unexpected type for 'secret'");
        cJSON_Delete(root);
        return -1;
    }

    r->ok = true;
    cJSON_Delete(root);
    return 0;
}

/* ── Public API ──────────────────────────────────────────────────── */

int quick_tunnel_provision(quick_tunnel_result_t *result)
{
    memset(result, 0, sizeof(*result));

    char *resp_data = calloc(1, MAX_RESP);
    if (!resp_data) {
        ESP_LOGE(TAG, "malloc failed");
        return -1;
    }

    resp_buf_t rb = { .buf = resp_data, .len = 0, .cap = MAX_RESP - 1 };

    esp_http_client_config_t config = {
        .url = API_URL,
        .method = HTTP_METHOD_POST,
        .event_handler = http_event_handler,
        .user_data = &rb,
        .timeout_ms = 15000,
        .skip_cert_common_name_check = true,
    };

    ESP_LOGI(TAG, "Requesting quick tunnel from %s ...", API_URL);

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "esp_http_client_init failed");
        free(resp_data);
        return -1;
    }

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "User-Agent", "cpp-cloudflared/0.1.0");

    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP request failed: %s", esp_err_to_name(err));
        free(resp_data);
        return -1;
    }

    ESP_LOGI(TAG, "API response: HTTP %d (%zu bytes)", status, rb.len);

    if (status != 200) {
        ESP_LOGE(TAG, "API returned HTTP %d: %.*s", status, (int)rb.len, resp_data);
        free(resp_data);
        return -1;
    }

    int ret = parse_response(resp_data, result);
    free(resp_data);

    if (ret == 0 && result->ok) {
        ESP_LOGI(TAG, "Quick tunnel provisioned:");
        ESP_LOGI(TAG, "  ID:       %s", result->id);
        ESP_LOGI(TAG, "  Hostname: %s", result->hostname);
        ESP_LOGI(TAG, "  Account:  %s", result->account_tag);
        ESP_LOGI(TAG, "  Secret:   %zu bytes", result->secret_len);
    }

    return ret;
}
