// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file http_response_reader.hpp
 * @brief Reads one HTTP/1.x response off a connection and finds where it ends
 *
 * The body length comes from the response itself (RFC 9112 section 6.3):
 * no body for HEAD/1xx/204/304, chunked decoding, Content-Length, or read
 * until the server closes. Reading stops as soon as the body is complete,
 * so the connection can carry the next request.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace Zepra::Networking {

/**
 * @brief Reads up to len bytes into buf
 * @return bytes read (> 0), 0 when the peer closed, -1 on error or timeout
 */
using HttpReadFn = std::function<long(char* buf, size_t len)>;

struct HttpWireResponse {
    int versionMinor = 1;              // HTTP/1.<minor>
    int statusCode = 0;
    std::string statusMessage;
    std::vector<std::pair<std::string, std::string>> headers;  // in arrival order
    std::vector<uint8_t> body;         // chunked framing removed
    bool complete = false;             // body ended where the framing said it would
    bool keepAlive = false;            // connection may carry another request
    size_t bytesReceived = 0;          // raw bytes read off the connection
    std::string error;                 // set when no response head could be read

    /** @brief First header with this name (case-insensitive), or nullptr */
    const std::string* header(const std::string& name) const;
};

/**
 * @brief Reads one response; 1xx interim responses (except 101) are skipped
 * @param headRequest the request was HEAD, so the response has no body
 * @return false when no valid status line and headers arrived (see out.error)
 */
bool readHttpResponse(const HttpReadFn& read, bool headRequest, HttpWireResponse& out);

} // namespace Zepra::Networking
