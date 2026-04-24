// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file nxhttp.h
 * @brief NxHTTP - Lightweight HTTP client for Zepra
 * 
 * Replaces libcurl with a minimal, high-performance HTTP client.
 * 
 * Features:
 * - HTTP/1.1 with keep-alive
 * - Chunked transfer encoding
 * - Cookie jar
 * - Redirect following
 * - Timeout support
 */

#ifndef NXHTTP_H
#define NXHTTP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Configuration Flags
// ============================================================================

// HTTP/2 is DISABLED by default for security
// Enable only after thorough testing
#ifndef NXHTTP_ENABLE_HTTP2
#define NXHTTP_ENABLE_HTTP2 0
#endif

// Strict IDN mode: reject ambiguous domains (recommended)
#ifndef NXHTTP_STRICT_IDN
#define NXHTTP_STRICT_IDN 1
#endif

// ============================================================================
// Error Codes
// ============================================================================

typedef enum {
    NX_HTTP_OK = 0,
    NX_HTTP_ERROR = -1,
    NX_HTTP_ERROR_NOMEM = -2,
    NX_HTTP_ERROR_INVALID_URL = -3,
    NX_HTTP_ERROR_DNS = -4,
    NX_HTTP_ERROR_CONNECT = -5,
    NX_HTTP_ERROR_TIMEOUT = -6,
    NX_HTTP_ERROR_SSL = -7,
    NX_HTTP_ERROR_SEND = -8,
    NX_HTTP_ERROR_RECV = -9,
    NX_HTTP_ERROR_PARSE = -10,
    NX_HTTP_ERROR_TOO_MANY_REDIRECTS = -11,
    
    // Fallback-related errors (strict mode)
    NX_HTTP_ERROR_HTTP2_FAILED = -20,       // HTTP/2 failed, use HTTP/1.1
    NX_HTTP_ERROR_IDN_INVALID = -21,        // Invalid IDN, REJECT (no guess)
    NX_HTTP_ERROR_IDN_MIXED_SCRIPT = -22,   // Mixed script domain
    NX_HTTP_ERROR_IDN_INVALID_UTF8 = -23,   // Invalid UTF-8 sequence
    NX_HTTP_ERROR_HTTP2_DISABLED = -24      // HTTP/2 not enabled
} NxHttpError;

const char* nx_http_error_string(NxHttpError err);

// ============================================================================
// URL Parsing
// ============================================================================

typedef struct {
    char* scheme;      // "http" or "https"
    char* host;
    int port;          // 80, 443, or custom
    char* path;        // "/" if empty
    char* query;       // After '?'
    char* fragment;    // After '#'
    char* userinfo;    // "user:pass" before '@'
} NxUrl;

NxUrl* nx_url_parse(const char* url);
void nx_url_free(NxUrl* url);
char* nx_url_to_string(const NxUrl* url);
bool nx_url_is_https(const NxUrl* url);

// URL encoding/decoding (RFC 3986 compliant)
char* nx_url_encode(const char* str);
char* nx_url_decode(const char* str);

// Base URL resolution (resolves relative URLs against a base)
NxUrl* nx_url_resolve(const NxUrl* base, const char* reference);

// Query parameter parsing
typedef struct {
    char** keys;
    char** values;
    size_t count;
} NxUrlParams;

NxUrlParams* nx_url_parse_query(const char* query);
void nx_url_params_free(NxUrlParams* params);
const char* nx_url_params_get(const NxUrlParams* params, const char* key);

// ============================================================================
// URL Scheme Classification (Security-Critical)
// ============================================================================

typedef enum {
    NX_SCHEME_UNKNOWN = 0,
    NX_SCHEME_HTTP,       // Needs DNS, network access
    NX_SCHEME_HTTPS,      // Needs DNS + TLS
    NX_SCHEME_FILE,       // Local filesystem, NO DNS, NO network
    NX_SCHEME_DATA,       // Inline data (data:text/html,...), NO network
    NX_SCHEME_BLOB,       // Memory blob, NO network
    NX_SCHEME_ABOUT,      // Browser internal (about:blank)
    NX_SCHEME_ZEPRA       // Browser extensions (zepra://settings)
} NxUrlScheme;

// Get scheme type from URL
NxUrlScheme nx_url_get_scheme_type(const NxUrl* url);

// Check if URL needs DNS resolution
// Returns: true for http/https, false for file/data/about/zepra
bool nx_url_needs_dns(const NxUrl* url);

// Check if URL is local (no network access allowed)
// Returns: true for file/data/blob/about/zepra
bool nx_url_is_local(const NxUrl* url);

// ============================================================================
// File Origin & Security (Quarantine System)
// ============================================================================

typedef enum {
    NX_FILE_ORIGIN_LOCAL = 0,    // file:// - already on device
    NX_FILE_ORIGIN_HTTPS,        // Downloaded via HTTPS
    NX_FILE_ORIGIN_HTTP,         // Downloaded via HTTP (UNSAFE!)
    NX_FILE_ORIGIN_UNKNOWN       // Origin not tracked
} NxFileOrigin;

typedef struct {
    NxFileOrigin origin;         // Where file came from
    char* source_url;            // Full source URL
    char* source_domain;         // Just the domain
    int64_t download_time;       // Unix timestamp
    bool is_quarantined;         // Needs user verification
    bool user_verified;          // User clicked "keep anyway"
    char sha256[65];             // File hash (64 chars + null)
} NxFileSecurityInfo;

// Get security info from file (reads extended attributes)
NxFileSecurityInfo* nx_file_get_security_info(const char* path);
void nx_file_security_info_free(NxFileSecurityInfo* info);

// Set quarantine on downloaded file
bool nx_file_set_quarantine(const char* path, const NxFileSecurityInfo* info);

// Remove quarantine (after user verification)
bool nx_file_remove_quarantine(const char* path);

// Check if file is quarantined (quick check)
bool nx_file_is_quarantined(const char* path);

// ============================================================================
// Executable Detection (NEVER auto-open)
// ============================================================================

typedef enum {
    NX_FILE_TYPE_SAFE = 0,       // Text, images, etc - can render
    NX_FILE_TYPE_EXECUTABLE,     // .exe, .sh, .elf - NEVER auto-run
    NX_FILE_TYPE_SCRIPT,         // .js, .py, .bat - NEVER auto-run
    NX_FILE_TYPE_ARCHIVE,        // .zip, .tar - save only
    NX_FILE_TYPE_UNKNOWN         // Unknown binary - save only
} NxFileType;

// Detect file type from path/extension
NxFileType nx_file_detect_type(const char* path);

// Check if file type should NEVER be auto-opened
// Returns: true for executables, scripts, archives, unknown binaries
bool nx_file_is_dangerous(const char* path);

// ============================================================================
// Local File Sandbox Flags
// ============================================================================

// Security flags for rendering local (file://) content
// These MUST be enforced when loading file:// URLs
typedef enum {
    NX_SANDBOX_NONE = 0,
    NX_SANDBOX_DISABLE_NETWORK    = (1 << 0),  // Block fetch(), XHR
    NX_SANDBOX_DISABLE_WEBSOCKET  = (1 << 1),  // Block WebSocket
    NX_SANDBOX_DISABLE_WORKER     = (1 << 2),  // Block Service Workers
    NX_SANDBOX_DISABLE_PLUGINS    = (1 << 3),  // Block plugins
    NX_SANDBOX_DISABLE_SCRIPTS    = (1 << 4),  // Block all JS (optional)
    
    // Combined: for file:// content
    NX_SANDBOX_LOCAL_FILE = (
        NX_SANDBOX_DISABLE_NETWORK |
        NX_SANDBOX_DISABLE_WEBSOCKET |
        NX_SANDBOX_DISABLE_WORKER
    )
} NxSandboxFlags;

// Get sandbox flags for URL scheme
NxSandboxFlags nx_url_get_sandbox_flags(const NxUrl* url);


// ============================================================================
// Headers
// ============================================================================

typedef struct NxHttpHeaders NxHttpHeaders;

NxHttpHeaders* nx_http_headers_create(void);
void nx_http_headers_free(NxHttpHeaders* headers);
void nx_http_headers_set(NxHttpHeaders* headers, const char* name, const char* value);
void nx_http_headers_add(NxHttpHeaders* headers, const char* name, const char* value);
const char* nx_http_headers_get(const NxHttpHeaders* headers, const char* name);
void nx_http_headers_remove(NxHttpHeaders* headers, const char* name);
size_t nx_http_headers_count(const NxHttpHeaders* headers);
bool nx_http_headers_get_at(const NxHttpHeaders* headers, size_t index, 
                            const char** name, const char** value);

// ============================================================================
// Request
// ============================================================================

typedef enum {
    NX_HTTP_GET,
    NX_HTTP_POST,
    NX_HTTP_PUT,
    NX_HTTP_DELETE,
    NX_HTTP_PATCH,
    NX_HTTP_HEAD,
    NX_HTTP_OPTIONS
} NxHttpMethod;

typedef struct NxHttpRequest NxHttpRequest;

NxHttpRequest* nx_http_request_create(NxHttpMethod method, const char* url);
void nx_http_request_free(NxHttpRequest* req);
void nx_http_request_set_header(NxHttpRequest* req, const char* name, const char* value);
void nx_http_request_set_body(NxHttpRequest* req, const void* data, size_t len);
void nx_http_request_set_body_string(NxHttpRequest* req, const char* body);
void nx_http_request_set_timeout(NxHttpRequest* req, int timeout_ms);
void nx_http_request_set_follow_redirects(NxHttpRequest* req, bool follow, int max_redirects);

// ============================================================================
// Response
// ============================================================================

typedef struct NxHttpResponse NxHttpResponse;

int nx_http_response_status(const NxHttpResponse* res);
const char* nx_http_response_status_text(const NxHttpResponse* res);
const char* nx_http_response_header(const NxHttpResponse* res, const char* name);
const NxHttpHeaders* nx_http_response_headers(const NxHttpResponse* res);
const uint8_t* nx_http_response_body(const NxHttpResponse* res);
size_t nx_http_response_body_len(const NxHttpResponse* res);
const char* nx_http_response_body_string(const NxHttpResponse* res);
void nx_http_response_free(NxHttpResponse* res);

// ============================================================================
// Client
// ============================================================================

typedef struct NxHttpClient NxHttpClient;

typedef struct {
    int connect_timeout_ms;    // Default: 30000
    int read_timeout_ms;       // Default: 30000
    bool follow_redirects;     // Default: true
    int max_redirects;         // Default: 10
    bool verify_ssl;           // Default: true (for HTTPS)
    const char* user_agent;    // Default: "NxHTTP/1.0"
} NxHttpClientConfig;

NxHttpClient* nx_http_client_create(const NxHttpClientConfig* config);
void nx_http_client_free(NxHttpClient* client);

// Synchronous request
NxHttpResponse* nx_http_client_send(NxHttpClient* client, NxHttpRequest* req, NxHttpError* error);

// Convenience methods
NxHttpResponse* nx_http_get(const char* url, NxHttpError* error);
NxHttpResponse* nx_http_post(const char* url, const char* body, 
                             const char* content_type, NxHttpError* error);

// ============================================================================
// Cookie Jar
// ============================================================================

typedef struct NxHttpCookieJar NxHttpCookieJar;

NxHttpCookieJar* nx_http_cookie_jar_create(void);
void nx_http_cookie_jar_free(NxHttpCookieJar* jar);
void nx_http_cookie_jar_set(NxHttpCookieJar* jar, const char* domain, 
                            const char* name, const char* value);
const char* nx_http_cookie_jar_get(const NxHttpCookieJar* jar, const char* domain, 
                                   const char* name);
void nx_http_client_set_cookie_jar(NxHttpClient* client, NxHttpCookieJar* jar);

// ============================================================================
// Connection Pool (HTTP keep-alive connection reuse)
// ============================================================================

typedef struct NxConnectionPool NxConnectionPool;

NxConnectionPool* nx_conn_pool_create(int max_per_host, int max_total, int idle_timeout_ms);
void nx_conn_pool_free(NxConnectionPool* pool);
void nx_conn_pool_cleanup(NxConnectionPool* pool);
int nx_conn_pool_active_count(NxConnectionPool* pool);
int nx_conn_pool_reuse_count(NxConnectionPool* pool);

// ============================================================================
// Response Cache (LRU with Cache-Control support)
// ============================================================================

typedef struct NxHttpCache NxHttpCache;

typedef enum {
    NX_CACHE_MISS = 0,
    NX_CACHE_HIT = 1,
    NX_CACHE_STALE = 2,
    NX_CACHE_NEEDS_REVALIDATION = 3
} NxCacheStatus;

typedef struct {
    NxCacheStatus status;
    NxHttpResponse* response;  // Valid if HIT
    const char* etag;          // For revalidation
    const char* last_modified; // For revalidation
} NxCacheResult;

NxHttpCache* nx_http_cache_create(const char* cache_dir, size_t max_memory_bytes);
void nx_http_cache_free(NxHttpCache* cache);
bool nx_http_cache_put(NxHttpCache* cache, const char* url, const NxHttpResponse* response);
NxCacheResult nx_http_cache_get(NxHttpCache* cache, const char* url);
void nx_http_cache_invalidate(NxHttpCache* cache, const char* url);
void nx_http_cache_clear(NxHttpCache* cache);
size_t nx_http_cache_size(NxHttpCache* cache);
size_t nx_http_cache_count(NxHttpCache* cache);
const uint8_t* nx_http_cache_get_body(NxHttpCache* cache, const char* url, size_t* out_len);
const char* nx_http_cache_get_content_type(NxHttpCache* cache, const char* url);

// ============================================================================
// IDN / Punycode (Internationalized Domain Names)
// ============================================================================

// Convert Unicode domain to ASCII (Punycode)
// Returns allocated string, caller must free()
char* nx_idn_to_ascii(const char* unicode_domain);

// Convert ASCII domain (Punycode) to Unicode
// Returns allocated string, caller must free()
char* nx_idn_to_unicode(const char* ascii_domain);

// Validate domain name structure
bool nx_idn_is_valid(const char* domain);

// ============================================================================
// HTTP/2 Protocol
// ============================================================================

typedef struct NxHttp2Session NxHttp2Session;

// Session management
NxHttp2Session* nx_http2_session_create(void);
void nx_http2_session_free(NxHttp2Session* session);

// Connection setup
bool nx_http2_send_preface(NxHttp2Session* session, uint8_t* out_buf, size_t* out_len);

// Stream management
uint32_t nx_http2_create_stream(NxHttp2Session* session);

// HPACK header encoding/decoding
bool nx_http2_encode_headers(NxHttp2Session* session, uint32_t stream_id,
                              const char** names, const char** values, size_t count,
                              uint8_t* out_buf, size_t* out_len);
bool nx_http2_decode_headers(NxHttp2Session* session, const uint8_t* data, size_t len,
                              char*** out_names, char*** out_values, size_t* out_count);

// Frame parsing
bool nx_http2_parse_frame(const uint8_t* data, size_t len,
                           uint8_t* out_type, uint8_t* out_flags,
                           uint32_t* out_stream_id, size_t* out_payload_len);

// Error handling
const char* nx_http2_error_string(uint32_t error_code);

#ifdef __cplusplus
}
#endif

// ============================================================================
// C++ Wrapper
// ============================================================================

#ifdef __cplusplus
#include <string>
#include <map>
#include <memory>
#include <stdexcept>
#include <functional>

namespace nx {

class HttpException : public std::runtime_error {
public:
    explicit HttpException(const std::string& msg, NxHttpError code = NX_HTTP_ERROR)
        : std::runtime_error(msg), code_(code) {}
    NxHttpError code() const { return code_; }
private:
    NxHttpError code_;
};

class HttpResponse {
public:
    HttpResponse(NxHttpResponse* res) : res_(res) {}
    ~HttpResponse() { if (res_) nx_http_response_free(res_); }
    
    HttpResponse(HttpResponse&& other) noexcept : res_(other.res_) { other.res_ = nullptr; }
    HttpResponse& operator=(HttpResponse&& other) noexcept {
        if (res_) nx_http_response_free(res_);
        res_ = other.res_;
        other.res_ = nullptr;
        return *this;
    }
    
    HttpResponse(const HttpResponse&) = delete;
    HttpResponse& operator=(const HttpResponse&) = delete;
    
    int status() const { return nx_http_response_status(res_); }
    std::string statusText() const { return nx_http_response_status_text(res_); }
    std::string header(const std::string& name) const {
        const char* val = nx_http_response_header(res_, name.c_str());
        return val ? val : "";
    }
    std::string body() const { return nx_http_response_body_string(res_); }
    size_t bodyLength() const { return nx_http_response_body_len(res_); }
    bool ok() const { return status() >= 200 && status() < 300; }
    
private:
    NxHttpResponse* res_;
};

class HttpClient {
public:
    HttpClient() : client_(nx_http_client_create(nullptr)) {
        if (!client_) throw HttpException("Failed to create HTTP client");
    }
    ~HttpClient() { if (client_) nx_http_client_free(client_); }
    
    HttpResponse get(const std::string& url) {
        NxHttpError err;
        NxHttpRequest* req = nx_http_request_create(NX_HTTP_GET, url.c_str());
        NxHttpResponse* res = nx_http_client_send(client_, req, &err);
        nx_http_request_free(req);
        if (!res) throw HttpException(nx_http_error_string(err), err);
        return HttpResponse(res);
    }
    
    HttpResponse post(const std::string& url, const std::string& body, 
                      const std::string& contentType = "application/json") {
        NxHttpError err;
        NxHttpRequest* req = nx_http_request_create(NX_HTTP_POST, url.c_str());
        nx_http_request_set_header(req, "Content-Type", contentType.c_str());
        nx_http_request_set_body_string(req, body.c_str());
        NxHttpResponse* res = nx_http_client_send(client_, req, &err);
        nx_http_request_free(req);
        if (!res) throw HttpException(nx_http_error_string(err), err);
        return HttpResponse(res);
    }
    
private:
    NxHttpClient* client_;
};

// Convenience functions
inline HttpResponse httpGet(const std::string& url) {
    HttpClient client;
    return client.get(url);
}

inline HttpResponse httpPost(const std::string& url, const std::string& body,
                             const std::string& contentType = "application/json") {
    HttpClient client;
    return client.post(url, body, contentType);
}

} // namespace nx

#endif // __cplusplus

#endif // NXHTTP_H
