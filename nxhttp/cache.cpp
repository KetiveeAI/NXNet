// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file cache.cpp
 * @brief HTTP Response Cache
 * 
 * Original implementation for caching HTTP responses.
 * Uses LRU eviction with memory limits and Cache-Control header support.
 */

#include "nxhttp.h"
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <list>
#include <unordered_map>
#include <mutex>
#include <fstream>
#include <iostream>

// ----------------------------------------------------------------------------
// Cache Entry - stored response with metadata
// ----------------------------------------------------------------------------

struct CacheEntry {
    std::string url;
    std::string etag;
    std::string last_modified;
    time_t expires;
    time_t created;
    int max_age_seconds;
    bool must_revalidate;
    std::vector<uint8_t> body;
    std::string content_type;
    int status_code;
};

// ----------------------------------------------------------------------------
// HTTP Cache Implementation (LRU)
// ----------------------------------------------------------------------------

struct NxHttpCache {
    // LRU list: front = most recently used
    std::list<std::string> lru_order;
    
    // URL -> iterator in LRU list for O(1) updates
    std::unordered_map<std::string, std::list<std::string>::iterator> lru_map;
    
    // URL -> cached entry
    std::unordered_map<std::string, CacheEntry*> entries;
    
    std::mutex cache_mutex;
    size_t max_memory_bytes;
    size_t current_memory_bytes;
    std::string cache_dir;          // Disk cache directory (optional)
    bool disk_cache_enabled;
    
    NxHttpCache(size_t max_mem, const char* dir) 
        : max_memory_bytes(max_mem), current_memory_bytes(0),
          disk_cache_enabled(dir != nullptr) {
        if (dir) cache_dir = dir;
    }
    
    ~NxHttpCache() {
        for (auto& pair : entries) {
            delete pair.second;
        }
    }
};

// Calculate memory usage of an entry
static size_t entry_memory_size(const CacheEntry* entry) {
    return sizeof(CacheEntry) 
         + entry->url.size()
         + entry->etag.size()
         + entry->last_modified.size()
         + entry->content_type.size()
         + entry->body.size();
}

// Move entry to front of LRU
static void touch_entry(NxHttpCache* cache, const std::string& url) {
    auto map_it = cache->lru_map.find(url);
    if (map_it != cache->lru_map.end()) {
        cache->lru_order.erase(map_it->second);
        cache->lru_order.push_front(url);
        map_it->second = cache->lru_order.begin();
    }
}

// Evict least recently used entries until under memory limit
static void evict_lru(NxHttpCache* cache) {
    while (cache->current_memory_bytes > cache->max_memory_bytes 
           && !cache->lru_order.empty()) {
        
        std::string& oldest_url = cache->lru_order.back();
        
        auto entry_it = cache->entries.find(oldest_url);
        if (entry_it != cache->entries.end()) {
            cache->current_memory_bytes -= entry_memory_size(entry_it->second);
            delete entry_it->second;
            cache->entries.erase(entry_it);
        }
        
        cache->lru_map.erase(oldest_url);
        cache->lru_order.pop_back();
    }
}

// Parse Cache-Control header
struct CacheDirectives {
    int max_age;
    bool no_cache;
    bool no_store;
    bool must_revalidate;
    bool is_private;
    bool is_public;
};

static CacheDirectives parse_cache_control(const char* header) {
    CacheDirectives dirs = {-1, false, false, false, false, false};
    if (!header) return dirs;
    
    std::string h = header;
    
    // Check for no-cache
    if (h.find("no-cache") != std::string::npos) dirs.no_cache = true;
    
    // Check for no-store
    if (h.find("no-store") != std::string::npos) dirs.no_store = true;
    
    // Check for must-revalidate
    if (h.find("must-revalidate") != std::string::npos) dirs.must_revalidate = true;
    
    // Check for private
    if (h.find("private") != std::string::npos) dirs.is_private = true;
    
    // Check for public
    if (h.find("public") != std::string::npos) dirs.is_public = true;
    
    // Parse max-age
    size_t pos = h.find("max-age=");
    if (pos != std::string::npos) {
        dirs.max_age = atoi(h.c_str() + pos + 8);
    }
    
    return dirs;
}

// Check if entry is still fresh
static bool is_entry_fresh(const CacheEntry* entry) {
    time_t now = time(nullptr);
    
    // Check explicit expiration
    if (entry->expires > 0 && now > entry->expires) {
        return false;
    }
    
    // Check max-age
    if (entry->max_age_seconds > 0) {
        time_t age = now - entry->created;
        if (age > entry->max_age_seconds) {
            return false;
        }
    }
    
    return true;
}

// ----------------------------------------------------------------------------
// Public C API
// ----------------------------------------------------------------------------

extern "C" {

NxHttpCache* nx_http_cache_create(const char* cache_dir, size_t max_memory_bytes) {
    if (max_memory_bytes == 0) max_memory_bytes = 50 * 1024 * 1024;  // 50MB default
    return new NxHttpCache(max_memory_bytes, cache_dir);
}

void nx_http_cache_free(NxHttpCache* cache) {
    delete cache;
}

bool nx_http_cache_put(NxHttpCache* cache, const char* url, 
                       const NxHttpResponse* response) {
    if (!cache || !url || !response) return false;
    
    // Check Cache-Control
    const char* cc = nx_http_response_header(response, "Cache-Control");
    CacheDirectives dirs = parse_cache_control(cc);
    
    // Don't cache no-store responses
    if (dirs.no_store) return false;
    
    // Only cache successful responses
    int status = nx_http_response_status(response);
    if (status < 200 || status >= 400) return false;
    
    std::lock_guard<std::mutex> lock(cache->cache_mutex);
    
    // Remove existing entry if present
    auto existing = cache->entries.find(url);
    if (existing != cache->entries.end()) {
        cache->current_memory_bytes -= entry_memory_size(existing->second);
        cache->lru_map.erase(existing->first);
        for (auto it = cache->lru_order.begin(); it != cache->lru_order.end(); ++it) {
            if (*it == url) {
                cache->lru_order.erase(it);
                break;
            }
        }
        delete existing->second;
        cache->entries.erase(existing);
    }
    
    // Create new entry
    CacheEntry* entry = new CacheEntry();
    entry->url = url;
    entry->status_code = status;
    entry->created = time(nullptr);
    entry->max_age_seconds = dirs.max_age > 0 ? dirs.max_age : 3600;  // 1 hour default
    entry->must_revalidate = dirs.must_revalidate;
    
    // Get ETag
    const char* etag = nx_http_response_header(response, "ETag");
    if (etag) entry->etag = etag;
    
    // Get Last-Modified
    const char* lm = nx_http_response_header(response, "Last-Modified");
    if (lm) entry->last_modified = lm;
    
    // Get Expires
    const char* expires = nx_http_response_header(response, "Expires");
    if (expires) {
        // Simple parse - could be improved
        struct tm tm_exp = {};
        if (strptime(expires, "%a, %d %b %Y %H:%M:%S", &tm_exp)) {
            entry->expires = mktime(&tm_exp);
        }
    }
    
    // Get Content-Type
    const char* ct = nx_http_response_header(response, "Content-Type");
    if (ct) entry->content_type = ct;
    
    // Copy body
    const uint8_t* body = nx_http_response_body(response);
    size_t body_len = nx_http_response_body_len(response);
    if (body && body_len > 0) {
        entry->body.assign(body, body + body_len);
    }
    
    // Check if entry fits in memory
    size_t entry_size = entry_memory_size(entry);
    if (entry_size > cache->max_memory_bytes / 2) {
        // Single entry too large
        delete entry;
        return false;
    }
    
    // Evict if needed
    cache->current_memory_bytes += entry_size;
    while (cache->current_memory_bytes > cache->max_memory_bytes) {
        evict_lru(cache);
    }
    
    // Add to cache
    cache->entries[url] = entry;
    cache->lru_order.push_front(url);
    cache->lru_map[url] = cache->lru_order.begin();
    
    return true;
}

NxCacheResult nx_http_cache_get(NxHttpCache* cache, const char* url) {
    NxCacheResult result = {NX_CACHE_MISS, nullptr, nullptr, nullptr};
    
    if (!cache || !url) return result;
    
    std::lock_guard<std::mutex> lock(cache->cache_mutex);
    
    auto it = cache->entries.find(url);
    if (it == cache->entries.end()) {
        return result;  // Cache miss
    }
    
    CacheEntry* entry = it->second;
    touch_entry(cache, url);
    
    // Check freshness
    if (!is_entry_fresh(entry)) {
        if (entry->must_revalidate || entry->etag.empty()) {
            result.status = NX_CACHE_STALE;
        } else {
            result.status = NX_CACHE_NEEDS_REVALIDATION;
            result.etag = entry->etag.empty() ? nullptr : entry->etag.c_str();
            result.last_modified = entry->last_modified.empty() ? nullptr 
                                 : entry->last_modified.c_str();
        }
    } else {
        result.status = NX_CACHE_HIT;
        // Response is not allocated here - caller should use nx_http_cache_get_body 
        // to retrieve cached body data
        result.response = nullptr;  
    }
    
    return result;
}

void nx_http_cache_invalidate(NxHttpCache* cache, const char* url) {
    if (!cache || !url) return;
    
    std::lock_guard<std::mutex> lock(cache->cache_mutex);
    
    auto it = cache->entries.find(url);
    if (it != cache->entries.end()) {
        cache->current_memory_bytes -= entry_memory_size(it->second);
        cache->lru_map.erase(url);
        for (auto lit = cache->lru_order.begin(); lit != cache->lru_order.end(); ++lit) {
            if (*lit == url) {
                cache->lru_order.erase(lit);
                break;
            }
        }
        delete it->second;
        cache->entries.erase(it);
    }
}

void nx_http_cache_clear(NxHttpCache* cache) {
    if (!cache) return;
    
    std::lock_guard<std::mutex> lock(cache->cache_mutex);
    
    for (auto& pair : cache->entries) {
        delete pair.second;
    }
    cache->entries.clear();
    cache->lru_order.clear();
    cache->lru_map.clear();
    cache->current_memory_bytes = 0;
}

size_t nx_http_cache_size(NxHttpCache* cache) {
    if (!cache) return 0;
    std::lock_guard<std::mutex> lock(cache->cache_mutex);
    return cache->current_memory_bytes;
}

size_t nx_http_cache_count(NxHttpCache* cache) {
    if (!cache) return 0;
    std::lock_guard<std::mutex> lock(cache->cache_mutex);
    return cache->entries.size();
}

const uint8_t* nx_http_cache_get_body(NxHttpCache* cache, const char* url, size_t* out_len) {
    if (!cache || !url) {
        if (out_len) *out_len = 0;
        return nullptr;
    }
    
    std::lock_guard<std::mutex> lock(cache->cache_mutex);
    
    auto it = cache->entries.find(url);
    if (it == cache->entries.end()) {
        if (out_len) *out_len = 0;
        return nullptr;
    }
    
    CacheEntry* entry = it->second;
    touch_entry(cache, url);
    
    if (out_len) *out_len = entry->body.size();
    return entry->body.empty() ? nullptr : entry->body.data();
}

const char* nx_http_cache_get_content_type(NxHttpCache* cache, const char* url) {
    if (!cache || !url) return nullptr;
    
    std::lock_guard<std::mutex> lock(cache->cache_mutex);
    
    auto it = cache->entries.find(url);
    if (it == cache->entries.end()) return nullptr;
    
    return it->second->content_type.empty() ? nullptr : it->second->content_type.c_str();
}

} // extern "C"

