/*
 * Phase 6: HTTP Proxy – forward incoming requests to a local origin server.
 *
 * This implementation uses POSIX sockets and targets the Linux host build.
 * An ESP32 build would replace socket calls with esp_http_client.
 */

#include "http_proxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "esp_log.h"

static const char *TAG = "http_proxy";

/* Maximum response body we are willing to buffer (1 MB). */
#define MAX_RESPONSE_BODY  (1024 * 1024)

/* Initial receive buffer size for the HTTP response. */
#define RECV_BUF_INIT      4096

/* ── Internal state ──────────────────────────────────────────────── */

typedef struct {
    char host[256];
    uint16_t port;
    char path_prefix[256];
    int connect_timeout_ms;
    int read_timeout_ms;
    bool initialised;
} proxy_state_t;

static proxy_state_t s_state;

/* ── Helpers (forward declarations) ──────────────────────────────── */

static int  parse_origin_url(const char *url, char *host, size_t host_sz,
                             uint16_t *port, char *path, size_t path_sz);
static int  connect_to_origin(const char *host, uint16_t port, int timeout_ms);
static int  send_all(int fd, const void *buf, size_t len, int timeout_ms);
static int  send_http_request(int fd, const char *method, const char *path,
                              const char *host, const cf_metadata_t *headers,
                              size_t header_count, const uint8_t *body,
                              size_t body_len, int timeout_ms);
static int  read_http_response(int fd, cf_http_response_t *resp, int timeout_ms);
static const char *extract_metadata_value(const cf_metadata_t *md, size_t count,
                                          const char *key);
static void set_bad_gateway(cf_http_response_t *resp, const char *reason);

/* ── Public API ──────────────────────────────────────────────────── */

int http_proxy_init(const http_proxy_config_t *config)
{
    if (!config || !config->origin_url) {
        ESP_LOGE(TAG, "init: NULL config or origin_url");
        return -1;
    }

    memset(&s_state, 0, sizeof(s_state));

    if (parse_origin_url(config->origin_url,
                         s_state.host, sizeof(s_state.host),
                         &s_state.port,
                         s_state.path_prefix, sizeof(s_state.path_prefix)) != 0) {
        ESP_LOGE(TAG, "init: failed to parse origin URL: %s", config->origin_url);
        return -1;
    }

    s_state.connect_timeout_ms = config->connect_timeout_ms > 0
                                 ? config->connect_timeout_ms : 5000;
    s_state.read_timeout_ms    = config->read_timeout_ms > 0
                                 ? config->read_timeout_ms : 30000;
    s_state.initialised = true;

    ESP_LOGI(TAG, "init: origin=%s:%u prefix=\"%s\" "
             "connect_timeout=%dms read_timeout=%dms",
             s_state.host, s_state.port, s_state.path_prefix,
             s_state.connect_timeout_ms, s_state.read_timeout_ms);
    return 0;
}

int http_proxy_forward(const cf_connect_request_t *req,
                       const uint8_t *body, size_t body_len,
                       cf_http_response_t *resp)
{
    if (!s_state.initialised) {
        ESP_LOGE(TAG, "forward: proxy not initialised");
        return -1;
    }
    if (!req || !resp) {
        ESP_LOGE(TAG, "forward: NULL req or resp");
        return -1;
    }

    memset(resp, 0, sizeof(*resp));

    /* ── 1. Extract metadata fields ───────────────────────────────── */
    const char *method = extract_metadata_value(
        req->metadata, req->metadata_count, "HttpMethod");
    if (!method) {
        method = "GET";
    }

    /* Build the request path from dest + optional path prefix. */
    char path[1024];
    const char *dest = req->dest;
    if (dest[0] == '\0') {
        dest = "/";
    }
    if (s_state.path_prefix[0] != '\0'
        && strcmp(s_state.path_prefix, "/") != 0) {
        snprintf(path, sizeof(path), "%s%s", s_state.path_prefix, dest);
    } else {
        snprintf(path, sizeof(path), "%s", dest);
    }

    /* Collect forwarded headers (metadata keys starting with "HttpHeader:"). */
    cf_metadata_t fwd_headers[CF_MAX_METADATA];
    size_t fwd_count = 0;
    for (size_t i = 0; i < req->metadata_count && fwd_count < CF_MAX_METADATA; i++) {
        if (strncmp(req->metadata[i].key, "HttpHeader:", 11) == 0) {
            snprintf(fwd_headers[fwd_count].key,
                     sizeof(fwd_headers[fwd_count].key),
                     "%s", req->metadata[i].key + 11);
            snprintf(fwd_headers[fwd_count].val,
                     sizeof(fwd_headers[fwd_count].val),
                     "%s", req->metadata[i].val);
            fwd_count++;
        }
    }

    ESP_LOGI(TAG, "forward: %s %s (%zu headers, %zu body bytes)",
             method, path, fwd_count, body_len);

    /* ── 2. Connect to origin ─────────────────────────────────────── */
    int fd = connect_to_origin(s_state.host, s_state.port,
                               s_state.connect_timeout_ms);
    if (fd < 0) {
        ESP_LOGE(TAG, "forward: connection to origin failed");
        set_bad_gateway(resp, "connection to origin failed");
        return 0; /* resp populated with 502 */
    }

    /* ── 3. Send HTTP request ─────────────────────────────────────── */
    if (send_http_request(fd, method, path, s_state.host,
                          fwd_headers, fwd_count,
                          body, body_len,
                          s_state.read_timeout_ms) != 0) {
        ESP_LOGE(TAG, "forward: failed to send request to origin");
        close(fd);
        set_bad_gateway(resp, "failed to send request to origin");
        return 0;
    }

    /* ── 4. Read HTTP response ────────────────────────────────────── */
    if (read_http_response(fd, resp, s_state.read_timeout_ms) != 0) {
        ESP_LOGE(TAG, "forward: failed to read response from origin");
        close(fd);
        set_bad_gateway(resp, "failed to read response from origin");
        return 0;
    }

    close(fd);

    ESP_LOGI(TAG, "forward: origin responded %d (%zu body bytes)",
             resp->status_code, resp->body_len);
    return 0;
}

void http_proxy_free_response(cf_http_response_t *resp)
{
    if (resp && resp->body) {
        free(resp->body);
        resp->body = NULL;
        resp->body_len = 0;
    }
}

void http_proxy_cleanup(void)
{
    ESP_LOGI(TAG, "cleanup");
    s_state.initialised = false;
}

/* ── URL parsing ─────────────────────────────────────────────────── */

static int parse_origin_url(const char *url, char *host, size_t host_sz,
                            uint16_t *port, char *path, size_t path_sz)
{
    /* Expect "http://host[:port][/path]". */
    const char *p = url;
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    } else if (strncmp(p, "https://", 8) == 0) {
        ESP_LOGW(TAG, "parse_origin_url: HTTPS origins not yet supported, "
                 "treating as plain HTTP");
        p += 8;
    } else {
        ESP_LOGE(TAG, "parse_origin_url: unsupported scheme in '%s'", url);
        return -1;
    }

    /* Find host end: colon (port), slash (path), or end of string. */
    const char *host_start = p;
    const char *colon = NULL;
    const char *slash = NULL;
    while (*p) {
        if (*p == ':' && !colon) colon = p;
        if (*p == '/') { slash = p; break; }
        p++;
    }

    /* Extract host. */
    size_t hlen = (colon ? (size_t)(colon - host_start)
                         : (slash ? (size_t)(slash - host_start)
                                  : strlen(host_start)));
    if (hlen == 0 || hlen >= host_sz) {
        ESP_LOGE(TAG, "parse_origin_url: host too long or empty");
        return -1;
    }
    memcpy(host, host_start, hlen);
    host[hlen] = '\0';

    /* Extract port. */
    if (colon) {
        long pval = strtol(colon + 1, NULL, 10);
        if (pval <= 0 || pval > 65535) {
            ESP_LOGE(TAG, "parse_origin_url: bad port in '%s'", url);
            return -1;
        }
        *port = (uint16_t)pval;
    } else {
        *port = 80;
    }

    /* Extract path prefix. */
    if (slash) {
        snprintf(path, path_sz, "%s", slash);
        /* Remove trailing slash for cleaner concatenation (keep root "/"). */
        size_t plen = strlen(path);
        if (plen > 1 && path[plen - 1] == '/') {
            path[plen - 1] = '\0';
        }
    } else {
        path[0] = '\0';
    }

    return 0;
}

/* ── TCP connection with timeout ─────────────────────────────────── */

static int connect_to_origin(const char *host, uint16_t port, int timeout_ms)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0 || !res) {
        ESP_LOGE(TAG, "connect: getaddrinfo(%s:%s) failed: %s",
                 host, port_str, gai_strerror(rc));
        return -1;
    }

    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) {
        ESP_LOGE(TAG, "connect: socket() failed: %s", strerror(errno));
        freeaddrinfo(res);
        return -1;
    }

    /* Set non-blocking for connect timeout. */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        ESP_LOGE(TAG, "connect: fcntl failed: %s", strerror(errno));
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    rc = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (rc < 0 && errno != EINPROGRESS) {
        ESP_LOGE(TAG, "connect: connect() failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (rc < 0) {
        /* Wait for connection with timeout. */
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);

        struct timeval tv;
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        rc = select(fd + 1, NULL, &wset, NULL, &tv);
        if (rc <= 0) {
            ESP_LOGE(TAG, "connect: %s",
                     rc == 0 ? "timed out" : strerror(errno));
            close(fd);
            return -1;
        }

        /* Check for connection error. */
        int so_err = 0;
        socklen_t so_len = sizeof(so_err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len);
        if (so_err != 0) {
            ESP_LOGE(TAG, "connect: async connect error: %s",
                     strerror(so_err));
            close(fd);
            return -1;
        }
    }

    /* Restore blocking mode for subsequent I/O (select used for timeouts). */
    fcntl(fd, F_SETFL, flags);

    ESP_LOGI(TAG, "connect: connected to %s:%u", host, port);
    return fd;
}

/* ── Reliable send with timeout ──────────────────────────────────── */

static int send_all(int fd, const void *buf, size_t len, int timeout_ms)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);

        struct timeval tv;
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int rc = select(fd + 1, NULL, &wset, NULL, &tv);
        if (rc <= 0) {
            ESP_LOGE(TAG, "send_all: %s",
                     rc == 0 ? "timed out" : strerror(errno));
            return -1;
        }

        ssize_t n = send(fd, p, remaining, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            ESP_LOGE(TAG, "send_all: send() failed: %s", strerror(errno));
            return -1;
        }
        p += n;
        remaining -= (size_t)n;
    }
    return 0;
}

/* ── Build and send the HTTP/1.1 request ─────────────────────────── */

static int send_http_request(int fd, const char *method, const char *path,
                             const char *host, const cf_metadata_t *headers,
                             size_t header_count, const uint8_t *body,
                             size_t body_len, int timeout_ms)
{
    /*
     * Estimate buffer size:
     *   request-line  ~method(16) + path(1024) + " HTTP/1.1\r\n"(11) = ~1051
     *   Host header   ~"Host: " + host(256) + "\r\n"                  = ~264
     *   Per header    ~key(128) + ": " + val(512) + "\r\n"            = ~644
     *   C-L header    ~"Content-Length: <20>\r\n"                      = ~40
     *   Blank line    "\r\n"                                           = 2
     *   Body          body_len
     */
    size_t est = 1400 + header_count * 650 + body_len;
    char *buf = malloc(est);
    if (!buf) {
        ESP_LOGE(TAG, "send_http_request: malloc(%zu) failed", est);
        return -1;
    }

    int off = 0;
    /* Request line. */
    off += snprintf(buf + off, est - (size_t)off,
                    "%s %s HTTP/1.1\r\n", method, path);

    /* Host header (use origin host, not the one from the edge). */
    off += snprintf(buf + off, est - (size_t)off,
                    "Host: %s\r\n", host);

    /* Connection: close so the origin will close after responding. */
    off += snprintf(buf + off, est - (size_t)off,
                    "Connection: close\r\n");

    /* Forwarded headers. */
    for (size_t i = 0; i < header_count; i++) {
        /* Skip Host (we already set it) and Connection. */
        if (strcasecmp(headers[i].key, "Host") == 0) continue;
        if (strcasecmp(headers[i].key, "Connection") == 0) continue;
        off += snprintf(buf + off, est - (size_t)off,
                        "%s: %s\r\n", headers[i].key, headers[i].val);
    }

    /* Content-Length if body present. */
    if (body && body_len > 0) {
        off += snprintf(buf + off, est - (size_t)off,
                        "Content-Length: %zu\r\n", body_len);
    }

    /* End of headers. */
    off += snprintf(buf + off, est - (size_t)off, "\r\n");

    /* Send headers. */
    if (send_all(fd, buf, (size_t)off, timeout_ms) != 0) {
        free(buf);
        return -1;
    }

    /* Send body. */
    if (body && body_len > 0) {
        if (send_all(fd, body, body_len, timeout_ms) != 0) {
            free(buf);
            return -1;
        }
    }

    free(buf);
    return 0;
}

/* ── Read and parse the HTTP/1.1 response ────────────────────────── */

/* Read data into a growable buffer until we hit the header terminator or EOF. */
static int recv_with_timeout(int fd, uint8_t *buf, size_t buf_sz,
                             size_t *out_len, int timeout_ms)
{
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(fd, &rset);

    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int rc = select(fd + 1, &rset, NULL, NULL, &tv);
    if (rc < 0) {
        ESP_LOGE(TAG, "recv: select() error: %s", strerror(errno));
        return -1;
    }
    if (rc == 0) {
        ESP_LOGE(TAG, "recv: timed out");
        return -1;
    }

    ssize_t n = recv(fd, buf, buf_sz, 0);
    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN) {
            *out_len = 0;
            return 0;
        }
        ESP_LOGE(TAG, "recv: recv() error: %s", strerror(errno));
        return -1;
    }
    *out_len = (size_t)n;
    return 0;
}

/* Parse a single header line "Key: Value" into a cf_metadata_t entry. */
static int parse_header_line(const char *line, size_t len,
                             cf_metadata_t *out)
{
    const char *colon = memchr(line, ':', len);
    if (!colon) return -1;

    size_t klen = (size_t)(colon - line);
    if (klen == 0 || klen >= sizeof(out->key)) return -1;
    memcpy(out->key, line, klen);
    out->key[klen] = '\0';

    /* Skip colon and optional whitespace. */
    const char *vstart = colon + 1;
    size_t remaining = len - klen - 1;
    while (remaining > 0 && *vstart == ' ') { vstart++; remaining--; }

    if (remaining >= sizeof(out->val)) remaining = sizeof(out->val) - 1;
    memcpy(out->val, vstart, remaining);
    out->val[remaining] = '\0';

    return 0;
}

static int read_http_response(int fd, cf_http_response_t *resp, int timeout_ms)
{
    /* Accumulate raw response data. */
    size_t buf_cap = RECV_BUF_INIT;
    uint8_t *buf = malloc(buf_cap);
    if (!buf) {
        ESP_LOGE(TAG, "read_response: malloc failed");
        return -1;
    }
    size_t buf_len = 0;

    /* Read until we have the full header section (terminated by \r\n\r\n). */
    char *header_end = NULL;
    while (!header_end) {
        if (buf_len + 1 >= buf_cap) {
            size_t new_cap = buf_cap * 2;
            if (new_cap > MAX_RESPONSE_BODY + 8192) {
                ESP_LOGE(TAG, "read_response: headers too large");
                free(buf);
                return -1;
            }
            uint8_t *tmp = realloc(buf, new_cap);
            if (!tmp) {
                ESP_LOGE(TAG, "read_response: realloc failed");
                free(buf);
                return -1;
            }
            buf = tmp;
            buf_cap = new_cap;
        }

        size_t n = 0;
        if (recv_with_timeout(fd, buf + buf_len,
                              buf_cap - buf_len - 1, &n, timeout_ms) != 0) {
            free(buf);
            return -1;
        }
        if (n == 0) {
            /* Connection closed before headers complete. */
            ESP_LOGE(TAG, "read_response: connection closed in headers");
            free(buf);
            return -1;
        }
        buf_len += n;
        buf[buf_len] = '\0';

        header_end = strstr((char *)buf, "\r\n\r\n");
    }

    /* ── Parse status line ────────────────────────────────────────── */
    char *status_line_end = strstr((char *)buf, "\r\n");
    if (!status_line_end) {
        ESP_LOGE(TAG, "read_response: no status line");
        free(buf);
        return -1;
    }

    /* "HTTP/1.x STATUS REASON" */
    int status_code = 0;
    if (sscanf((char *)buf, "HTTP/%*d.%*d %d", &status_code) != 1) {
        ESP_LOGE(TAG, "read_response: failed to parse status code");
        free(buf);
        return -1;
    }
    resp->status_code = status_code;

    /* ── Parse response headers ───────────────────────────────────── */
    resp->header_count = 0;
    char *line = status_line_end + 2; /* skip first \r\n */
    while (line < header_end) {
        char *next = strstr(line, "\r\n");
        if (!next || next == line) break;
        size_t line_len = (size_t)(next - line);

        if (resp->header_count < CF_MAX_METADATA) {
            parse_header_line(line, line_len,
                              &resp->headers[resp->header_count]);
            resp->header_count++;
        }
        line = next + 2;
    }

    /* ── Determine body length ────────────────────────────────────── */
    size_t content_length = 0;
    bool have_content_length = false;
    for (size_t i = 0; i < resp->header_count; i++) {
        if (strcasecmp(resp->headers[i].key, "Content-Length") == 0) {
            content_length = (size_t)strtoul(resp->headers[i].val, NULL, 10);
            have_content_length = true;
            break;
        }
    }

    /* Body starts right after "\r\n\r\n". */
    size_t header_section_len = (size_t)(header_end - (char *)buf) + 4;
    size_t body_already = buf_len - header_section_len;

    if (have_content_length) {
        if (content_length > MAX_RESPONSE_BODY) {
            ESP_LOGE(TAG, "read_response: Content-Length %zu exceeds limit",
                     content_length);
            free(buf);
            return -1;
        }

        /* Read remaining body bytes. */
        while (body_already < content_length) {
            if (buf_len + 1 >= buf_cap) {
                size_t new_cap = buf_cap * 2;
                if (new_cap > MAX_RESPONSE_BODY + header_section_len + 64) {
                    new_cap = content_length + header_section_len + 64;
                }
                uint8_t *tmp = realloc(buf, new_cap);
                if (!tmp) {
                    ESP_LOGE(TAG, "read_response: realloc failed for body");
                    free(buf);
                    return -1;
                }
                buf = tmp;
                buf_cap = new_cap;
            }

            size_t n = 0;
            if (recv_with_timeout(fd, buf + buf_len,
                                  buf_cap - buf_len, &n, timeout_ms) != 0) {
                free(buf);
                return -1;
            }
            if (n == 0) break; /* connection closed */
            buf_len += n;
            body_already = buf_len - header_section_len;
        }

        resp->body_len = content_length;
    } else {
        /* No Content-Length: read until connection close. */
        for (;;) {
            if (buf_len + 1 >= buf_cap) {
                size_t new_cap = buf_cap * 2;
                if (new_cap > MAX_RESPONSE_BODY + header_section_len + 64) {
                    ESP_LOGE(TAG, "read_response: body too large (no C-L)");
                    free(buf);
                    return -1;
                }
                uint8_t *tmp = realloc(buf, new_cap);
                if (!tmp) {
                    ESP_LOGE(TAG, "read_response: realloc failed");
                    free(buf);
                    return -1;
                }
                buf = tmp;
                buf_cap = new_cap;
            }

            size_t n = 0;
            if (recv_with_timeout(fd, buf + buf_len,
                                  buf_cap - buf_len, &n, timeout_ms) != 0) {
                /* Treat timeout as end-of-body when we already have data. */
                if (body_already > 0) break;
                free(buf);
                return -1;
            }
            if (n == 0) break;
            buf_len += n;
            body_already = buf_len - header_section_len;
        }

        resp->body_len = body_already;
    }

    /* Copy body into its own allocation so the caller can free it. */
    if (resp->body_len > 0) {
        resp->body = malloc(resp->body_len);
        if (!resp->body) {
            ESP_LOGE(TAG, "read_response: malloc for body failed");
            free(buf);
            return -1;
        }
        memcpy(resp->body, buf + header_section_len, resp->body_len);
    } else {
        resp->body = NULL;
    }

    free(buf);
    return 0;
}

/* ── Metadata helpers ────────────────────────────────────────────── */

static const char *extract_metadata_value(const cf_metadata_t *md, size_t count,
                                          const char *key)
{
    for (size_t i = 0; i < count; i++) {
        if (strcmp(md[i].key, key) == 0) {
            return md[i].val;
        }
    }
    return NULL;
}

/* ── Error helpers ───────────────────────────────────────────────── */

static void set_bad_gateway(cf_http_response_t *resp, const char *reason)
{
    resp->status_code = 502;
    resp->header_count = 1;
    snprintf(resp->headers[0].key, sizeof(resp->headers[0].key),
             "Content-Type");
    snprintf(resp->headers[0].val, sizeof(resp->headers[0].val),
             "text/plain");

    const char *prefix = "502 Bad Gateway: ";
    size_t plen = strlen(prefix);
    size_t rlen = strlen(reason);
    size_t total = plen + rlen;

    resp->body = malloc(total + 1);
    if (resp->body) {
        memcpy(resp->body, prefix, plen);
        memcpy(resp->body + plen, reason, rlen);
        resp->body[total] = '\0';
        resp->body_len = total;
    } else {
        resp->body_len = 0;
    }
}
