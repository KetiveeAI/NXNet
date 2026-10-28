// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file network_monitor.h
 * @brief Network request/response monitor for ZepraWebView
 *
 * One monitor records the requests of one page (tab). Loader threads record
 * into it while the UI thread reads it, so every method takes the monitor's
 * mutex and readers get a copy of the entries (getEntries) or a callback run
 * under the lock (forEachEntry); no reference into the entry list escapes.
 */

#ifndef NETWORK_MONITOR_H
#define NETWORK_MONITOR_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace zepra {

// ============================================================================
// Network Request/Response Data
// ============================================================================

struct NetworkHeader {
    std::string name;
    std::string value;
};

enum class NetworkResourceType {
    DOCUMENT,
    STYLESHEET,
    SCRIPT,
    IMAGE,
    FONT,
    XHR,
    FETCH,
    WEBSOCKET,
    MEDIA,
    OTHER
};

struct NetworkRequest {
    uint64_t id = 0;
    std::string method;
    std::string url;
    std::string origin;
    std::vector<NetworkHeader> headers;
    std::string body;
    size_t body_size = 0;
    std::chrono::system_clock::time_point start_time;

    /// What asked for the resource (the document parser, a stylesheet link, a
    /// script tag, an image, fetch/XHR). OTHER means "guess from the URL and
    /// the response's Content-Type".
    NetworkResourceType initiator = NetworkResourceType::OTHER;

    // Flags
    bool is_xhr = false;
    bool is_fetch = false;
    bool is_cors = false;
    bool blocked = false;
    std::string blocked_reason;
};

struct NetworkResponse {
    uint64_t request_id = 0;
    int status_code = 0;
    std::string status_text;
    std::vector<NetworkHeader> headers;
    std::string content_type;
    size_t content_length = 0;        // decoded body bytes
    size_t transferred_bytes = 0;     // bytes read off the connection (headers + body); 0 = unknown
    std::chrono::system_clock::time_point end_time;
    double duration_ms = 0;

    // Body (truncated for display)
    std::string body_preview;
    bool body_truncated = false;

    // Security
    bool is_secure = false;           // HTTPS
    std::string security_protocol;    // TLS version
    std::string certificate_issuer;
};

struct NetworkEntry {
    NetworkRequest request;
    NetworkResponse response;
    NetworkResourceType type = NetworkResourceType::OTHER;
    bool completed = false;
    bool failed = false;
    std::string error;
};

// ============================================================================
// Network Monitor
// ============================================================================

class NetworkMonitor {
public:
    using RequestCallback = std::function<void(const NetworkRequest&)>;
    using ResponseCallback = std::function<void(const NetworkEntry&)>;
    using EntryVisitor = std::function<void(const NetworkEntry&)>;

    NetworkMonitor();
    ~NetworkMonitor();

    NetworkMonitor(const NetworkMonitor&) = delete;
    NetworkMonitor& operator=(const NetworkMonitor&) = delete;

    // Enable/disable monitoring
    void setEnabled(bool enabled);
    bool isEnabled() const;

    // Callbacks (run after the lock is released, on the recording thread)
    void setRequestCallback(RequestCallback cb);
    void setResponseCallback(ResponseCallback cb);

    /**
     * @brief Record the start of a request; safe from any thread
     * @return the request id to complete it with, 0 when monitoring is disabled
     */
    uint64_t recordRequest(const NetworkRequest& req);
    void recordResponse(uint64_t request_id, const NetworkResponse& res);
    void recordError(uint64_t request_id, const std::string& error);

    /// A snapshot of the entries, taken under the lock
    std::vector<NetworkEntry> getEntries() const;
    /// Runs `visit` for each entry while holding the lock (don't record from inside)
    void forEachEntry(const EntryVisitor& visit) const;
    std::vector<NetworkEntry> getEntriesForOrigin(const std::string& origin) const;

    // Clear
    void clear();

    // Stats
    size_t getTotalRequests() const;
    size_t getBlockedRequests() const;
    double getTotalTransferSize() const;

    // Filter
    std::vector<NetworkEntry> filterByType(NetworkResourceType type) const;
    std::vector<NetworkEntry> filterByStatus(int min_status, int max_status) const;

    // Export
    std::string exportAsHAR() const;  // HTTP Archive format

private:
    std::vector<NetworkEntry> entries_;
    std::map<uint64_t, size_t> id_to_index_;
    uint64_t next_id_ = 1;
    std::atomic<bool> enabled_{true};
    mutable std::mutex mutex_;

    RequestCallback request_callback_;
    ResponseCallback response_callback_;
};

// Global network monitor instance
NetworkMonitor& getNetworkMonitor();

// ============================================================================
// Helper: Format for display
// ============================================================================

std::string formatHeaders(const std::vector<NetworkHeader>& headers);
std::string formatDuration(double ms);
std::string formatSize(size_t bytes);
NetworkResourceType guessResourceType(const std::string& url, const std::string& content_type);

} // namespace zepra

#endif // NETWORK_MONITOR_H
