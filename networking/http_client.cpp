// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file http_client.cpp
 * @brief HTTP client implementation with socket operations
 *
 * HTTP/1.1 over plain or TLS sockets. Each response is read exactly to the
 * end its headers announce (see http_response_reader.hpp), and connections
 * the server keeps open go back to a per-host pool for the next request.
 */

#include "http_client.hpp"
#include "http_response_reader.hpp"
#include "ssl_context.hpp"
#include "cookie_manager.hpp"
#include "dns_resolver.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
static inline int closeSocket(int s) { return ::closesocket(static_cast<SOCKET>(s)); }
static inline int pollSockets(WSAPOLLFD* fds, ULONG n, int timeoutMs) { return ::WSAPoll(fds, n, timeoutMs); }
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
static inline int closeSocket(int s) { return ::close(s); }
static inline int pollSockets(struct pollfd* fds, nfds_t n, int timeoutMs) { return ::poll(fds, n, timeoutMs); }
#endif

#include <sstream>
#include <chrono>
#include <thread>
#include <atomic>
#include <fstream>
#include <mutex>
#include <algorithm>
#include <iostream>
#include <cstring>

namespace Zepra::Networking {

#ifdef MSG_NOSIGNAL
static constexpr int SEND_FLAGS = MSG_NOSIGNAL;
#else
static constexpr int SEND_FLAGS = 0;
#endif

// =============================================================================
// Connection
// =============================================================================

struct Connection {
    int socket = -1;
    std::unique_ptr<SSLContext::SSLSocket> sslSocket;
    std::string key;  // pool key: scheme, host, port, verification
    std::chrono::steady_clock::time_point lastUsed;
    bool reused = false;

    ~Connection() { close(); }

    // Waits up to timeoutMs for data; >0 bytes, 0 when the peer closed, -1 on error/timeout
    long read(char* buffer, size_t size, int timeoutMs) {
        // Bytes OpenSSL already decrypted are invisible to poll()
        if (!(sslSocket && sslSocket->pending() > 0)) {
            struct pollfd pfd = {};
            pfd.fd = socket;
            pfd.events = POLLIN;
            if (pollSockets(&pfd, 1, timeoutMs) <= 0) return -1;
        }
        if (sslSocket) return sslSocket->read(buffer, size);
        long n = ::recv(socket, buffer, static_cast<int>(size), 0);
        return n < 0 ? -1 : n;
    }

    bool writeAll(const char* data, size_t len) {
        while (len > 0) {
            long n = sslSocket ? sslSocket->write(data, len)
                               : ::send(socket, data, static_cast<int>(len), SEND_FLAGS);
            if (n <= 0) return false;
            data += n;
            len -= static_cast<size_t>(n);
        }
        return true;
    }

    // An idle connection is usable only if the server hasn't closed it or sent anything
    bool isIdleAndOpen() const {
        if (socket < 0) return false;
        if (sslSocket && sslSocket->pending() > 0) return false;
        struct pollfd pfd = {};
        pfd.fd = socket;
        pfd.events = POLLIN;
        int r = pollSockets(&pfd, 1, 0);
        return r == 0;  // readable here means EOF, an error, or stray bytes
    }

    void close() {
        if (sslSocket) {
            sslSocket->close();
            sslSocket.reset();
        }
        if (socket >= 0) {
            closeSocket(socket);
            socket = -1;
        }
    }
};

// =============================================================================
// Connection Pool (idle keep-alive connections, shared by all HttpClients)
// =============================================================================

class ConnectionPool {
public:
    static constexpr size_t MAX_IDLE = 16;
    static constexpr size_t MAX_IDLE_PER_HOST = 6;
    static constexpr int IDLE_TIMEOUT_SEC = 30;

    std::unique_ptr<Connection> take(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        evictExpired();
        // Most recently used first: least likely to have been closed by the server
        for (size_t i = idle_.size(); i-- > 0;) {
            if (idle_[i]->key != key) continue;
            std::unique_ptr<Connection> conn = std::move(idle_[i]);
            idle_.erase(idle_.begin() + static_cast<long>(i));
            if (conn->isIdleAndOpen()) {
                conn->reused = true;
                return conn;
            }
            // Server closed it; drop and keep looking
        }
        return nullptr;
    }

    void put(std::unique_ptr<Connection> conn) {
        std::lock_guard<std::mutex> lock(mutex_);
        evictExpired();
        conn->lastUsed = std::chrono::steady_clock::now();
        size_t sameHost = 0;
        for (const auto& c : idle_) {
            if (c->key == conn->key) sameHost++;
        }
        if (sameHost >= MAX_IDLE_PER_HOST) return;  // conn closes on destruction
        if (idle_.size() >= MAX_IDLE) idle_.erase(idle_.begin());  // oldest
        idle_.push_back(std::move(conn));
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        idle_.clear();
    }

private:
    void evictExpired() {
        auto now = std::chrono::steady_clock::now();
        idle_.erase(std::remove_if(idle_.begin(), idle_.end(),
            [&](const std::unique_ptr<Connection>& c) {
                return now - c->lastUsed > std::chrono::seconds(IDLE_TIMEOUT_SEC);
            }), idle_.end());
    }

    std::mutex mutex_;
    std::vector<std::unique_ptr<Connection>> idle_;
};

static ConnectionPool& getConnectionPool() {
    // Never destroyed: closing TLS connections during static teardown could run
    // after OpenSSL's own atexit cleanup
    static ConnectionPool* pool = new ConnectionPool();
    return *pool;
}

// =============================================================================
// Helpers
// =============================================================================

// "https://host:port" part of a URL
static std::string originOf(const std::string& url) {
    size_t schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) return url;
    size_t end = url.find_first_of("/?#", schemeEnd + 3);
    return end == std::string::npos ? url : url.substr(0, end);
}

// Resolves a Location header against the URL that was requested
static std::string resolveLocation(const HttpRequest& request, const std::string& location) {
    size_t colon = location.find("://");
    if (colon != std::string::npos && location.find_first_of("/?#") > colon) {
        return location;  // absolute
    }
    if (location.rfind("//", 0) == 0) return request.scheme() + ":" + location;
    std::string origin = originOf(request.url());
    if (!location.empty() && location[0] == '/') return origin + location;
    std::string path = request.path();
    return origin + path.substr(0, path.rfind('/') + 1) + location;
}

// =============================================================================
// Internal Implementation
// =============================================================================

class HttpClientImpl {
public:
    HttpClientImpl(HttpClientConfig& config) : config_(config) {}

    HttpResponse send(const HttpRequest& request) {
        return sendFollowingRedirects(request, config_.maxRedirects);
    }

private:
    HttpResponse sendFollowingRedirects(const HttpRequest& request, int redirectsLeft) {
        HttpResponse response;
        auto startTime = std::chrono::steady_clock::now();

        exchange(request, response);

        // Handle cookies
        if (config_.useCookies && !response.hasError()) {
            for (const auto& setCookie : response.setCookieHeaders()) {
                getCookieManager().setCookie(setCookie, request.url());
            }
        }

        // Handle redirects
        if (config_.followRedirects && !response.hasError() && response.isRedirect() &&
            !response.location().empty() && redirectsLeft > 0) {
            std::string target = resolveLocation(request, response.location());
            int code = response.statusCode();
            if ((code == 307 || code == 308) && originOf(target) == originOf(request.url())) {
                // Same method and body; headers only stay within the same origin
                HttpRequest next = request;
                next.setUrl(target);
                return sendFollowingRedirects(next, redirectsLeft - 1);
            }
            HttpRequest next(code == 307 || code == 308 ? request.method() : HttpMethod::GET, target);
            if (code == 307 || code == 308) next.setBody(request.body());
            return sendFollowingRedirects(next, redirectsLeft - 1);
        }

        response.setUrl(request.url());

        auto endTime = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime);
        response.setTimingMs(static_cast<double>(duration.count()));

        return response;
    }

    // One request/response on a pooled or new connection
    void exchange(const HttpRequest& request, HttpResponse& response) {
        std::string host = request.host();
        int port = request.port();
        bool secure = request.isSecure();
        std::string key = (secure ? "https://" : "http://") + host + ":" + std::to_string(port) +
                          (secure && !config_.verifySsl ? "#noverify" : "");
        std::string requestBytes = buildRequest(request, host, port, secure);
        bool headRequest = request.method() == HttpMethod::HEAD;
        int readTimeoutMs = config_.readTimeoutMs > 0 ? config_.readTimeoutMs : 30000;

        // A reused connection may have been closed by the server just as we sent;
        // if nothing came back, the request is retried once on a new connection
        for (int attempt = 0; attempt < 2; ++attempt) {
            std::unique_ptr<Connection> conn;
            if (attempt == 0) conn = getConnectionPool().take(key);
            if (!conn) {
                std::string error;
                conn = openConnection(host, port, secure, error);
                if (!conn) {
                    response.setError(error);
                    return;
                }
                conn->key = key;
            }
            bool reused = conn->reused;

            if (!conn->writeAll(requestBytes.data(), requestBytes.size())) {
                if (reused) continue;
                std::cerr << "[HTTPClient] Send failed!" << std::endl;
                response.setError("Failed to send request");
                return;
            }

            HttpWireResponse wire;
            Connection* c = conn.get();
            bool ok = readHttpResponse(
                [c, readTimeoutMs](char* buf, size_t len) { return c->read(buf, len, readTimeoutMs); },
                headRequest, wire);
            if (!ok) {
                if (reused && wire.bytesReceived == 0) continue;
                response.setError("Invalid response: " + wire.error);
                return;
            }
            if (!wire.complete) {
                std::cerr << "[HTTPClient] Response body ended early (" << wire.body.size()
                          << " bytes): " << request.url() << std::endl;
            }

            fillResponse(wire, response);
            if (wire.keepAlive) getConnectionPool().put(std::move(conn));
            return;
        }
        response.setError("Connection closed by server");
    }

    std::string buildRequest(const HttpRequest& request, const std::string& host, int port, bool secure) {
        std::ostringstream reqStream;
        std::string pathAndQuery = request.path();
        if (pathAndQuery.empty()) pathAndQuery = "/";  // Use / for empty path
        if (!request.query().empty()) {
            pathAndQuery += "?" + request.query();
        }

        reqStream << request.methodString() << " " << pathAndQuery << " HTTP/1.1\r\n";
        reqStream << "Host: " << host;
        if ((secure && port != 443) || (!secure && port != 80)) {
            reqStream << ":" << port;
        }
        reqStream << "\r\n";

        // Add headers
        for (const auto& [name, value] : request.headers()) {
            reqStream << name << ": " << value << "\r\n";
        }

        // Add default headers if not present
        if (!request.hasHeader("User-Agent")) {
            reqStream << "User-Agent: " << config_.userAgent << "\r\n";
        }
        if (!request.hasHeader("Accept")) {
            reqStream << "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
        }
        if (!request.hasHeader("Accept-Language")) {
            reqStream << "Accept-Language: en-US,en;q=0.5\r\n";
        }
        if (!request.hasHeader("Accept-Encoding")) {
            reqStream << "Accept-Encoding: identity\r\n";  // No compression for now
        }
        if (!request.hasHeader("Connection")) {
            reqStream << "Connection: keep-alive\r\n";
        }

        // Add cookies
        if (config_.useCookies) {
            std::string cookies = getCookieManager().getCookiesForUrl(request.url(), secure);
            if (!cookies.empty()) {
                reqStream << "Cookie: " << cookies << "\r\n";
            }
        }

        // Add body
        if (!request.body().empty() && !request.hasHeader("Content-Length")) {
            reqStream << "Content-Length: " << request.body().size() << "\r\n";
        }

        reqStream << "\r\n";

        std::string bytes = reqStream.str();
        bytes.append(request.body().begin(), request.body().end());
        return bytes;
    }

    std::unique_ptr<Connection> openConnection(const std::string& host, int port, bool secure,
                                               std::string& error) {
#if !defined(_WIN32) && !defined(SO_NOSIGPIPE)
        // TLS writes go through OpenSSL's write(), which MSG_NOSIGNAL can't reach:
        // a server closing a kept-alive connection must not kill the process
        static std::once_flag sigpipeOnce;
        std::call_once(sigpipeOnce, [] {
            struct sigaction current = {};
            if (sigaction(SIGPIPE, nullptr, &current) == 0 && current.sa_handler == SIG_DFL) {
                signal(SIGPIPE, SIG_IGN);
            }
        });
#endif

        // Resolve DNS
        DnsResult dns = getDnsResolver().resolve(host);
        if (!dns.success || dns.addresses.empty()) {
            error = "DNS resolution failed: " + dns.error;
            return nullptr;
        }

        // Loop over addresses to connect robustly
        int sock = -1;
        bool connected = false;

        for (const auto& addrStr : dns.addresses) {
            bool isIPv6 = addrStr.find(':') != std::string::npos;
            sock = socket(isIPv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;

            // Set socket options
#ifdef _WIN32
            // Winsock takes the timeout as a DWORD of milliseconds
            DWORD timeout = static_cast<DWORD>(config_.connectTimeoutMs);
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
            struct timeval timeout;
            timeout.tv_sec = config_.connectTimeoutMs / 1000;
            timeout.tv_usec = (config_.connectTimeoutMs % 1000) * 1000;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#endif
#ifdef SO_NOSIGPIPE
            int noSigpipe = 1;
            setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe, sizeof(noSigpipe));
#endif
            // Requests go out in one write; don't hold them back waiting for ACKs
            int noDelay = 1;
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&noDelay), sizeof(noDelay));

            // Connect
            if (isIPv6) {
                struct sockaddr_in6 errAddr;
                memset(&errAddr, 0, sizeof(errAddr));
                errAddr.sin6_family = AF_INET6;
                errAddr.sin6_port = htons(port);
                inet_pton(AF_INET6, addrStr.c_str(), &errAddr.sin6_addr);
                if (connect(sock, (struct sockaddr*)&errAddr, sizeof(errAddr)) == 0) {
                    connected = true; break;
                }
            } else {
                struct sockaddr_in errAddr;
                memset(&errAddr, 0, sizeof(errAddr));
                errAddr.sin_family = AF_INET;
                errAddr.sin_port = htons(port);
                inet_pton(AF_INET, addrStr.c_str(), &errAddr.sin_addr);
                if (connect(sock, (struct sockaddr*)&errAddr, sizeof(errAddr)) == 0) {
                    connected = true; break;
                }
            }
            closeSocket(sock);
            sock = -1;
        }

        if (!connected || sock < 0) {
            error = "Connection failed to all resolved IPs";
            return nullptr;
        }

        auto conn = std::make_unique<Connection>();
        conn->socket = sock;

        // SSL handshake if HTTPS
        if (secure) {
            // Verification is set on this socket only, not on the shared context
            conn->sslSocket = getSSLContext().createSocket(sock, config_.verifySsl);
            if (!conn->sslSocket) {
                error = "Failed to create SSL socket";
                return nullptr;
            }

            if (!conn->sslSocket->connect(host, host + ":" + std::to_string(port))) {
                error = "SSL handshake failed";
                return nullptr;
            }
        }

        return conn;
    }

    void fillResponse(HttpWireResponse& wire, HttpResponse& response) {
        response.setStatusCode(wire.statusCode);
        response.setStatusMessage(wire.statusMessage);

        for (const auto& [name, value] : wire.headers) {
            // Handle multiple Set-Cookie headers
            std::string nameLower = name;
            std::transform(nameLower.begin(), nameLower.end(),
                           nameLower.begin(), ::tolower);

            if (nameLower == "set-cookie" && response.hasHeader("Set-Cookie")) {
                std::string existing = response.header("Set-Cookie");
                response.setHeader(name, existing + "\n" + value);
            } else {
                response.setHeader(name, value);
            }
        }

        response.setBody(std::move(wire.body));
    }

    HttpClientConfig& config_;
};

// =============================================================================
// HttpClient Implementation
// =============================================================================

HttpClient::HttpClient() : impl_(std::make_unique<HttpClientImpl>(config_)) {}

HttpClient::HttpClient(const HttpClientConfig& config)
    : config_(config), impl_(std::make_unique<HttpClientImpl>(config_)) {}

HttpClient::~HttpClient() = default;

HttpResponse HttpClient::send(const HttpRequest& request) {
    return impl_->send(request);
}

std::future<HttpResponse> HttpClient::sendAsync(const HttpRequest& request) {
    return std::async(std::launch::async, [this, request]() {
        return impl_->send(request);
    });
}

HttpResponse HttpClient::get(const std::string& url) {
    HttpRequest request(HttpMethod::GET, url);
    return send(request);
}

HttpResponse HttpClient::post(const std::string& url, const std::string& body,
                               const std::string& contentType) {
    HttpRequest request(HttpMethod::POST, url);
    request.setBody(body);
    request.setContentType(contentType);
    return send(request);
}

bool HttpClient::download(const std::string& url, const std::string& filePath,
                           ProgressCallback progress) {
    HttpRequest request(HttpMethod::GET, url);
    HttpResponse response = send(request);

    if (!response.isSuccess()) {
        return false;
    }

    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    const auto& body = response.body();
    file.write(reinterpret_cast<const char*>(body.data()), body.size());

    if (progress) {
        progress(body.size(), body.size());
    }

    return true;
}

void HttpClient::cancelAll() {
    // TODO: Implement request cancellation
}

void HttpClient::closeIdleConnections() {
    getConnectionPool().clear();
}

} // namespace Zepra::Networking
