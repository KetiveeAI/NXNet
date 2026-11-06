/**
 * @file http_response.hpp
 * @brief HTTP response representation
 */

#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <utility>

namespace Zepra::Networking {

using HttpHeaderList = std::vector<std::pair<std::string, std::string>>;

/**
 * @brief Where the time of a request went, in milliseconds. The phases of
 * opening a connection (DNS, connect, TLS) are -1 when a kept-alive
 * connection was reused; TLS is also -1 for plain HTTP.
 */
struct HttpTimings {
    double redirectMs = 0;   ///< earlier hops of a redirect chain
    double dnsMs = -1;
    double connectMs = -1;
    double tlsMs = -1;
    double sendMs = 0;       ///< writing the request
    double waitMs = 0;       ///< request sent until the first response byte
    double receiveMs = 0;    ///< first response byte until the end of the body
};

/**
 * @brief HTTP Response
 */
class HttpResponse {
public:
    HttpResponse() = default;
    
    // Status
    void setStatusCode(int code) { statusCode_ = code; }
    int statusCode() const { return statusCode_; }
    
    void setStatusMessage(const std::string& msg) { statusMessage_ = msg; }
    const std::string& statusMessage() const { return statusMessage_; }
    
    bool isSuccess() const { return statusCode_ >= 200 && statusCode_ < 300; }
    bool isRedirect() const { return statusCode_ >= 300 && statusCode_ < 400; }
    bool isClientError() const { return statusCode_ >= 400 && statusCode_ < 500; }
    bool isServerError() const { return statusCode_ >= 500; }
    bool isError() const { return statusCode_ >= 400; }
    
    // Headers
    void setHeader(const std::string& name, const std::string& value);
    std::string header(const std::string& name) const;
    bool hasHeader(const std::string& name) const;
    const std::unordered_map<std::string, std::string>& headers() const { return headers_; }
    /// The headers as they arrived (order and repeats kept); empty for a response not read off the wire
    void setHeaderList(HttpHeaderList list) { headerList_ = std::move(list); }
    const HttpHeaderList& headerList() const { return headerList_; }

    /// The request line's headers as sent on the final hop (Host, cookies and defaults included)
    void setRequestHeaders(HttpHeaderList list) { requestHeaders_ = std::move(list); }
    const HttpHeaderList& requestHeaders() const { return requestHeaders_; }
    
    // Body
    void setBody(const std::vector<uint8_t>& body) { body_ = body; }
    void setBody(std::vector<uint8_t>&& body) { body_ = std::move(body); }
    void appendBody(const uint8_t* data, size_t size);
    const std::vector<uint8_t>& body() const { return body_; }
    std::string bodyString() const;
    size_t contentLength() const;
    
    // Content type
    std::string contentType() const;
    std::string mimeType() const;
    std::string charset() const;
    
    // Redirects
    std::string location() const;
    
    // Cookies
    std::vector<std::string> setCookieHeaders() const;
    
    // Timing
    void setTimingMs(double ms) { timingMs_ = ms; }
    double timingMs() const { return timingMs_; }
    void setTimings(const HttpTimings& timings) { timings_ = timings; }
    const HttpTimings& timings() const { return timings_; }

    // Bytes read off the connection for this response (status line, headers,
    // body with its transfer framing); 0 when unknown
    void setBytesReceived(size_t bytes) { bytesReceived_ = bytes; }
    size_t bytesReceived() const { return bytesReceived_; }

    // True when the connection carried an earlier request (keep-alive reuse)
    void setConnectionReused(bool reused) { connectionReused_ = reused; }
    bool connectionReused() const { return connectionReused_; }
    
    // Error
    void setError(const std::string& error) { error_ = error; }
    const std::string& error() const { return error_; }
    bool hasError() const { return !error_.empty(); }
    
    // URL (final after redirects)
    void setUrl(const std::string& url) { url_ = url; }
    const std::string& url() const { return url_; }
    
private:
    int statusCode_ = 0;
    std::string statusMessage_;
    std::unordered_map<std::string, std::string> headers_;
    std::vector<uint8_t> body_;
    double timingMs_ = 0;
    HttpTimings timings_;
    HttpHeaderList headerList_;
    HttpHeaderList requestHeaders_;
    size_t bytesReceived_ = 0;
    bool connectionReused_ = false;
    std::string error_;
    std::string url_;
};

} // namespace Zepra::Networking
