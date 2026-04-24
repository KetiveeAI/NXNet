// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file headers.cpp
 * @brief HTTP headers implementation
 */

#include "nxhttp.h"
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>

struct NxHttpHeaders {
    std::vector<std::pair<std::string, std::string>> headers;
};

extern "C" {

NxHttpHeaders* nx_http_headers_create() {
    return new NxHttpHeaders();
}

void nx_http_headers_free(NxHttpHeaders* headers) {
    delete headers;
}

static bool headers_name_eq(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        if (tolower(a[i]) != tolower(b[i])) return false;
    }
    return true;
}

void nx_http_headers_set(NxHttpHeaders* headers, const char* name, const char* value) {
    if (!headers || !name) return;
    
    // Replace existing header
    for (auto& h : headers->headers) {
        if (headers_name_eq(h.first, name)) {
            h.second = value ? value : "";
            return;
        }
    }
    
    // Add new header
    headers->headers.emplace_back(name, value ? value : "");
}

void nx_http_headers_add(NxHttpHeaders* headers, const char* name, const char* value) {
    if (!headers || !name) return;
    headers->headers.emplace_back(name, value ? value : "");
}

const char* nx_http_headers_get(const NxHttpHeaders* headers, const char* name) {
    if (!headers || !name) return nullptr;
    
    for (const auto& h : headers->headers) {
        if (headers_name_eq(h.first, name)) {
            return h.second.c_str();
        }
    }
    return nullptr;
}

void nx_http_headers_remove(NxHttpHeaders* headers, const char* name) {
    if (!headers || !name) return;
    
    headers->headers.erase(
        std::remove_if(headers->headers.begin(), headers->headers.end(),
            [name](const auto& h) { return headers_name_eq(h.first, name); }),
        headers->headers.end()
    );
}

size_t nx_http_headers_count(const NxHttpHeaders* headers) {
    return headers ? headers->headers.size() : 0;
}

bool nx_http_headers_get_at(const NxHttpHeaders* headers, size_t index,
                            const char** name, const char** value) {
    if (!headers || index >= headers->headers.size()) return false;
    
    if (name) *name = headers->headers[index].first.c_str();
    if (value) *value = headers->headers[index].second.c_str();
    return true;
}

} // extern "C"
