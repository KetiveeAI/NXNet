// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file url.cpp
 * @brief URL parsing implementation
 */

#include "nxhttp.h"
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <string>
#include <vector>

extern "C" {

NxUrl* nx_url_parse(const char* url) {
    if (!url) return nullptr;
    
    NxUrl* u = static_cast<NxUrl*>(calloc(1, sizeof(NxUrl)));
    if (!u) return nullptr;
    
    const char* p = url;
    const char* end = url + strlen(url);
    
    // Parse scheme
    const char* scheme_end = strstr(p, "://");
    if (scheme_end) {
        size_t len = scheme_end - p;
        u->scheme = static_cast<char*>(malloc(len + 1));
        memcpy(u->scheme, p, len);
        u->scheme[len] = '\0';
        // Convert to lowercase
        for (char* c = u->scheme; *c; c++) *c = tolower(*c);
        p = scheme_end + 3;
    } else {
        u->scheme = strdup("http");
    }
    
    // Default port
    if (strcmp(u->scheme, "https") == 0) {
        u->port = 443;
    } else {
        u->port = 80;
    }
    
    // Parse userinfo (user:pass@)
    const char* at = strchr(p, '@');
    const char* slash = strchr(p, '/');
    if (at && (!slash || at < slash)) {
        size_t len = at - p;
        u->userinfo = static_cast<char*>(malloc(len + 1));
        memcpy(u->userinfo, p, len);
        u->userinfo[len] = '\0';
        p = at + 1;
    }
    
    // Parse host:port
    const char* host_end = p;
    while (host_end < end && *host_end != '/' && *host_end != '?' && *host_end != '#') {
        host_end++;
    }
    
    // Check for port
    const char* colon = nullptr;
    // Handle IPv6 addresses [::1]:port
    if (*p == '[') {
        const char* bracket = strchr(p, ']');
        if (bracket && bracket < host_end) {
            colon = strchr(bracket, ':');
        }
    } else {
        // Find last colon (for IPv4 or hostname)
        for (const char* c = host_end - 1; c >= p; c--) {
            if (*c == ':') {
                colon = c;
                break;
            }
        }
    }
    
    if (colon && colon < host_end) {
        size_t host_len = colon - p;
        u->host = static_cast<char*>(malloc(host_len + 1));
        memcpy(u->host, p, host_len);
        u->host[host_len] = '\0';
        u->port = atoi(colon + 1);
    } else {
        size_t host_len = host_end - p;
        u->host = static_cast<char*>(malloc(host_len + 1));
        memcpy(u->host, p, host_len);
        u->host[host_len] = '\0';
    }
    
    p = host_end;
    
    // Parse path
    const char* query_start = strchr(p, '?');
    const char* frag_start = strchr(p, '#');
    const char* path_end = query_start ? query_start : (frag_start ? frag_start : end);
    
    if (path_end > p) {
        size_t len = path_end - p;
        u->path = static_cast<char*>(malloc(len + 1));
        memcpy(u->path, p, len);
        u->path[len] = '\0';
    } else {
        u->path = strdup("/");
    }
    
    // Parse query
    if (query_start) {
        const char* query_end = frag_start ? frag_start : end;
        size_t len = query_end - query_start - 1;
        u->query = static_cast<char*>(malloc(len + 1));
        memcpy(u->query, query_start + 1, len);
        u->query[len] = '\0';
    }
    
    // Parse fragment
    if (frag_start) {
        size_t len = end - frag_start - 1;
        u->fragment = static_cast<char*>(malloc(len + 1));
        memcpy(u->fragment, frag_start + 1, len);
        u->fragment[len] = '\0';
    }
    
    return u;
}

void nx_url_free(NxUrl* url) {
    if (url) {
        free(url->scheme);
        free(url->host);
        free(url->path);
        free(url->query);
        free(url->fragment);
        free(url->userinfo);
        free(url);
    }
}

char* nx_url_to_string(const NxUrl* url) {
    if (!url) return nullptr;
    
    std::string result;
    result.reserve(256);
    
    result += url->scheme ? url->scheme : "http";
    result += "://";
    
    if (url->userinfo) {
        result += url->userinfo;
        result += "@";
    }
    
    if (url->host) result += url->host;
    
    // Add port if non-default
    bool default_port = (strcmp(url->scheme, "https") == 0 && url->port == 443) ||
                        (strcmp(url->scheme, "http") == 0 && url->port == 80);
    if (!default_port && url->port > 0) {
        result += ":";
        result += std::to_string(url->port);
    }
    
    result += url->path ? url->path : "/";
    
    if (url->query) {
        result += "?";
        result += url->query;
    }
    
    if (url->fragment) {
        result += "#";
        result += url->fragment;
    }
    
    return strdup(result.c_str());
}

bool nx_url_is_https(const NxUrl* url) {
    return url && url->scheme && strcmp(url->scheme, "https") == 0;
}

// ----------------------------------------------------------------------------
// URL Encoding/Decoding (RFC 3986 compliant, original implementation)
// ----------------------------------------------------------------------------

// Check if character is unreserved (no encoding needed)
static bool is_unreserved_char(unsigned char c) {
    // Alphanumeric
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= 'a' && c <= 'z') return true;
    if (c >= '0' && c <= '9') return true;
    // Special unreserved: - . _ ~
    if (c == '-' || c == '.' || c == '_' || c == '~') return true;
    return false;
}

// Convert hex digit to value
static int hex_digit_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return -1;
}

char* nx_url_encode(const char* input) {
    if (!input) return nullptr;
    
    size_t input_len = strlen(input);
    // Worst case: every char becomes %XX (3x size)
    char* output = static_cast<char*>(malloc(input_len * 3 + 1));
    if (!output) return nullptr;
    
    static const char hex_chars[] = "0123456789ABCDEF";
    char* out = output;
    
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(input); *p; p++) {
        if (is_unreserved_char(*p)) {
            *out++ = *p;
        } else if (*p == ' ') {
            // Spaces can be encoded as + (form encoding) or %20
            *out++ = '%';
            *out++ = '2';
            *out++ = '0';
        } else {
            // Percent-encode
            *out++ = '%';
            *out++ = hex_chars[(*p >> 4) & 0x0F];
            *out++ = hex_chars[*p & 0x0F];
        }
    }
    *out = '\0';
    
    return output;
}

char* nx_url_decode(const char* input) {
    if (!input) return nullptr;
    
    size_t input_len = strlen(input);
    char* output = static_cast<char*>(malloc(input_len + 1));
    if (!output) return nullptr;
    
    char* out = output;
    const char* p = input;
    
    while (*p) {
        if (*p == '%' && p[1] && p[2]) {
            int high = hex_digit_value(p[1]);
            int low = hex_digit_value(p[2]);
            if (high >= 0 && low >= 0) {
                *out++ = static_cast<char>((high << 4) | low);
                p += 3;
                continue;
            }
        } else if (*p == '+') {
            // Plus to space (form encoding)
            *out++ = ' ';
            p++;
            continue;
        }
        *out++ = *p++;
    }
    *out = '\0';
    
    return output;
}

// ----------------------------------------------------------------------------
// Path Normalization (removes . and .. segments)
// ----------------------------------------------------------------------------

static char* normalize_path(const char* path) {
    if (!path || !*path) return strdup("/");
    
    // Split path into segments
    std::string result;
    std::vector<std::string> segments;
    
    const char* p = path;
    bool has_leading_slash = (*p == '/');
    if (has_leading_slash) p++;
    
    while (*p) {
        const char* seg_start = p;
        while (*p && *p != '/') p++;
        
        size_t seg_len = p - seg_start;
        std::string segment(seg_start, seg_len);
        
        if (segment == ".") {
            // Single dot - skip (current directory)
        } else if (segment == "..") {
            // Double dot - go up one level
            if (!segments.empty()) {
                segments.pop_back();
            }
        } else if (seg_len > 0) {
            segments.push_back(segment);
        }
        
        if (*p == '/') p++;
    }
    
    // Rebuild normalized path
    if (has_leading_slash) result = "/";
    for (size_t i = 0; i < segments.size(); i++) {
        if (i > 0) result += "/";
        result += segments[i];
    }
    
    // Preserve trailing slash if original had one
    if (path[strlen(path) - 1] == '/' && !result.empty() && result.back() != '/') {
        result += "/";
    }
    
    if (result.empty()) result = "/";
    
    return strdup(result.c_str());
}

// ----------------------------------------------------------------------------
// Base URL Resolution (RFC 3986 Section 5)
// ----------------------------------------------------------------------------

NxUrl* nx_url_resolve(const NxUrl* base, const char* reference) {
    if (!reference) return nullptr;
    
    // If reference is absolute (has scheme), use it directly
    if (strstr(reference, "://")) {
        return nx_url_parse(reference);
    }
    
    // Need a base URL to resolve relative references
    if (!base) return nullptr;
    
    NxUrl* result = static_cast<NxUrl*>(calloc(1, sizeof(NxUrl)));
    if (!result) return nullptr;
    
    const char* ref = reference;
    
    // Inherit scheme from base
    result->scheme = base->scheme ? strdup(base->scheme) : strdup("http");
    result->port = base->port;
    
    // Check for authority (starts with //)
    if (ref[0] == '/' && ref[1] == '/') {
        // Reference has authority - parse it
        nx_url_free(result);
        std::string full_url = std::string(base->scheme ? base->scheme : "http") + ":" + reference;
        return nx_url_parse(full_url.c_str());
    }
    
    // Inherit authority (host, port, userinfo) from base
    result->host = base->host ? strdup(base->host) : nullptr;
    result->userinfo = base->userinfo ? strdup(base->userinfo) : nullptr;
    
    // Handle path
    if (ref[0] == '/') {
        // Absolute path - use directly
        char* normalized = normalize_path(ref);
        
        // Split path and query
        char* qmark = strchr(normalized, '?');
        char* hash = strchr(normalized, '#');
        
        if (qmark) {
            *qmark = '\0';
            result->path = strdup(normalized);
            if (hash && hash > qmark) {
                *hash = '\0';
                result->query = strdup(qmark + 1);
                result->fragment = strdup(hash + 1);
            } else {
                result->query = strdup(qmark + 1);
            }
        } else if (hash) {
            *hash = '\0';
            result->path = strdup(normalized);
            result->fragment = strdup(hash + 1);
        } else {
            result->path = normalized;
            normalized = nullptr; // Don't free, transferred ownership
        }
        if (normalized) free(normalized);
    } else if (ref[0] == '?' || ref[0] == '#') {
        // Query or fragment only - keep base path
        result->path = base->path ? strdup(base->path) : strdup("/");
        
        if (ref[0] == '?') {
            const char* hash = strchr(ref, '#');
            if (hash) {
                result->query = static_cast<char*>(malloc(hash - ref));
                memcpy(result->query, ref + 1, hash - ref - 1);
                result->query[hash - ref - 1] = '\0';
                result->fragment = strdup(hash + 1);
            } else {
                result->query = strdup(ref + 1);
            }
        } else {
            result->query = base->query ? strdup(base->query) : nullptr;
            result->fragment = strdup(ref + 1);
        }
    } else {
        // Relative path - merge with base
        std::string merged_path;
        
        if (base->path) {
            // Find last slash in base path
            const char* last_slash = strrchr(base->path, '/');
            if (last_slash) {
                merged_path.assign(base->path, last_slash - base->path + 1);
            } else {
                merged_path = "/";
            }
        } else {
            merged_path = "/";
        }
        
        // Handle query/fragment in reference
        const char* qmark = strchr(ref, '?');
        const char* hash = strchr(ref, '#');
        const char* path_end = qmark ? qmark : (hash ? hash : ref + strlen(ref));
        
        merged_path.append(ref, path_end - ref);
        
        char* normalized = normalize_path(merged_path.c_str());
        result->path = normalized;
        
        if (qmark) {
            if (hash && hash > qmark) {
                result->query = static_cast<char*>(malloc(hash - qmark));
                memcpy(result->query, qmark + 1, hash - qmark - 1);
                result->query[hash - qmark - 1] = '\0';
                result->fragment = strdup(hash + 1);
            } else {
                result->query = strdup(qmark + 1);
            }
        } else if (hash) {
            result->fragment = strdup(hash + 1);
        }
    }
    
    return result;
}

// ----------------------------------------------------------------------------
// Query Parameter Parsing
// ----------------------------------------------------------------------------

NxUrlParams* nx_url_parse_query(const char* query) {
    if (!query || !*query) return nullptr;
    
    NxUrlParams* params = static_cast<NxUrlParams*>(calloc(1, sizeof(NxUrlParams)));
    if (!params) return nullptr;
    
    // Count parameters (roughly by counting &)
    size_t capacity = 8;
    params->keys = static_cast<char**>(malloc(capacity * sizeof(char*)));
    params->values = static_cast<char**>(malloc(capacity * sizeof(char*)));
    params->count = 0;
    
    const char* p = query;
    while (*p) {
        // Find key
        const char* key_start = p;
        while (*p && *p != '=' && *p != '&') p++;
        size_t key_len = p - key_start;
        
        // Find value
        const char* value_start = nullptr;
        size_t value_len = 0;
        
        if (*p == '=') {
            p++;
            value_start = p;
            while (*p && *p != '&') p++;
            value_len = p - value_start;
        }
        
        // Grow arrays if needed
        if (params->count >= capacity) {
            capacity *= 2;
            params->keys = static_cast<char**>(realloc(params->keys, capacity * sizeof(char*)));
            params->values = static_cast<char**>(realloc(params->values, capacity * sizeof(char*)));
        }
        
        // Decode and store
        char* key_raw = static_cast<char*>(malloc(key_len + 1));
        memcpy(key_raw, key_start, key_len);
        key_raw[key_len] = '\0';
        params->keys[params->count] = nx_url_decode(key_raw);
        free(key_raw);
        
        if (value_start) {
            char* val_raw = static_cast<char*>(malloc(value_len + 1));
            memcpy(val_raw, value_start, value_len);
            val_raw[value_len] = '\0';
            params->values[params->count] = nx_url_decode(val_raw);
            free(val_raw);
        } else {
            params->values[params->count] = strdup("");
        }
        
        params->count++;
        
        if (*p == '&') p++;
    }
    
    return params;
}

void nx_url_params_free(NxUrlParams* params) {
    if (params) {
        for (size_t i = 0; i < params->count; i++) {
            free(params->keys[i]);
            free(params->values[i]);
        }
        free(params->keys);
        free(params->values);
        free(params);
    }
}

const char* nx_url_params_get(const NxUrlParams* params, const char* key) {
    if (!params || !key) return nullptr;
    
    for (size_t i = 0; i < params->count; i++) {
        if (strcmp(params->keys[i], key) == 0) {
            return params->values[i];
        }
    }
    return nullptr;
}

// ============================================================================
// URL Scheme Classification (Security-Critical)
// ============================================================================

NxUrlScheme nx_url_get_scheme_type(const NxUrl* url) {
    if (!url || !url->scheme) return NX_SCHEME_UNKNOWN;
    
    const char* s = url->scheme;
    
    if (strcmp(s, "http") == 0) return NX_SCHEME_HTTP;
    if (strcmp(s, "https") == 0) return NX_SCHEME_HTTPS;
    if (strcmp(s, "file") == 0) return NX_SCHEME_FILE;
    if (strcmp(s, "data") == 0) return NX_SCHEME_DATA;
    if (strcmp(s, "blob") == 0) return NX_SCHEME_BLOB;
    if (strcmp(s, "about") == 0) return NX_SCHEME_ABOUT;
    if (strcmp(s, "zepra") == 0) return NX_SCHEME_ZEPRA;
    
    return NX_SCHEME_UNKNOWN;
}

bool nx_url_needs_dns(const NxUrl* url) {
    NxUrlScheme scheme = nx_url_get_scheme_type(url);
    
    // ONLY http/https need DNS resolution
    // All other schemes are local or special
    return scheme == NX_SCHEME_HTTP || scheme == NX_SCHEME_HTTPS;
}

bool nx_url_is_local(const NxUrl* url) {
    NxUrlScheme scheme = nx_url_get_scheme_type(url);
    
    // Local schemes: NO network access allowed
    switch (scheme) {
        case NX_SCHEME_FILE:
        case NX_SCHEME_DATA:
        case NX_SCHEME_BLOB:
        case NX_SCHEME_ABOUT:
        case NX_SCHEME_ZEPRA:
            return true;
        default:
            return false;
    }
}

NxSandboxFlags nx_url_get_sandbox_flags(const NxUrl* url) {
    NxUrlScheme scheme = nx_url_get_scheme_type(url);
    
    switch (scheme) {
        case NX_SCHEME_FILE:
            // Local files: DISABLE network access
            // This prevents file:// HTML from loading remote resources
            return NX_SANDBOX_LOCAL_FILE;
            
        case NX_SCHEME_DATA:
        case NX_SCHEME_BLOB:
            // Data URLs: also sandboxed
            return NX_SANDBOX_LOCAL_FILE;
            
        case NX_SCHEME_ABOUT:
        case NX_SCHEME_ZEPRA:
            // Browser internals: allow full access
            return NX_SANDBOX_NONE;
            
        case NX_SCHEME_HTTP:
        case NX_SCHEME_HTTPS:
        default:
            // Web content: normal rules apply
            return NX_SANDBOX_NONE;
    }
}

// ============================================================================
// Executable Detection (NEVER auto-open)
// ============================================================================

// Dangerous extensions that should NEVER be auto-executed
static const char* DANGEROUS_EXTENSIONS[] = {
    // Executables
    ".exe", ".com", ".bat", ".cmd", ".msi", ".scr", ".pif",
    ".sh", ".bash", ".zsh", ".csh", ".ksh",
    ".elf", ".bin", ".run", ".appimage",
    ".app", ".dmg", ".pkg",
    ".deb", ".rpm", ".apk",
    
    // Scripts
    ".js", ".vbs", ".vbe", ".jse", ".ws", ".wsf", ".wsc", ".wsh",
    ".ps1", ".psm1", ".psd1",
    ".py", ".pyw", ".pyc", ".pyo",
    ".rb", ".pl", ".php", ".lua",
    ".jar", ".class",
    
    // Archives (may contain executables)
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".iso", ".img",
    
    // Documents with macros
    ".docm", ".xlsm", ".pptm",
    
    nullptr  // Sentinel
};

// Safe extensions that can be rendered in-browser
static const char* SAFE_EXTENSIONS[] = {
    // Text
    ".txt", ".md", ".rst", ".log", ".csv",
    
    // Web
    ".html", ".htm", ".xhtml", ".xml", ".css",
    
    // Images
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
    
    // Audio/Video (can be played)
    ".mp3", ".wav", ".ogg", ".flac", ".m4a",
    ".mp4", ".webm", ".mkv", ".avi", ".mov",
    
    // Documents (view-only)
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp",
    
    // Fonts
    ".ttf", ".otf", ".woff", ".woff2",
    
    nullptr  // Sentinel
};

// Get file extension (lowercase)
static const char* get_extension(const char* path) {
    if (!path) return nullptr;
    
    const char* dot = strrchr(path, '.');
    if (!dot || dot == path) return nullptr;
    
    // Ignore if there's a path separator after the dot
    if (strchr(dot, '/') || strchr(dot, '\\')) return nullptr;
    
    return dot;
}

NxFileType nx_file_detect_type(const char* path) {
    const char* ext = get_extension(path);
    if (!ext) return NX_FILE_TYPE_UNKNOWN;
    
    // Convert to lowercase for comparison
    char ext_lower[32] = {0};
    size_t len = strlen(ext);
    if (len >= sizeof(ext_lower)) return NX_FILE_TYPE_UNKNOWN;
    
    for (size_t i = 0; i < len; i++) {
        ext_lower[i] = tolower(ext[i]);
    }
    
    // Check safe extensions first
    for (const char** e = SAFE_EXTENSIONS; *e; e++) {
        if (strcmp(ext_lower, *e) == 0) {
            return NX_FILE_TYPE_SAFE;
        }
    }
    
    // Check dangerous extensions
    for (const char** e = DANGEROUS_EXTENSIONS; *e; e++) {
        if (strcmp(ext_lower, *e) == 0) {
            // Further classify
            if (strstr(".exe.com.elf.bin.run.appimage.app.dmg.deb.rpm.apk", ext_lower)) {
                return NX_FILE_TYPE_EXECUTABLE;
            }
            if (strstr(".js.vbs.py.rb.pl.php.ps1.sh.bat.cmd", ext_lower)) {
                return NX_FILE_TYPE_SCRIPT;
            }
            if (strstr(".zip.rar.7z.tar.gz.iso.img", ext_lower)) {
                return NX_FILE_TYPE_ARCHIVE;
            }
            return NX_FILE_TYPE_EXECUTABLE;  // Default to most dangerous
        }
    }
    
    return NX_FILE_TYPE_UNKNOWN;
}

bool nx_file_is_dangerous(const char* path) {
    NxFileType type = nx_file_detect_type(path);
    
    // NEVER auto-open these types
    switch (type) {
        case NX_FILE_TYPE_EXECUTABLE:
        case NX_FILE_TYPE_SCRIPT:
        case NX_FILE_TYPE_ARCHIVE:
        case NX_FILE_TYPE_UNKNOWN:
            return true;
        case NX_FILE_TYPE_SAFE:
        default:
            return false;
    }
}

} // extern "C"

