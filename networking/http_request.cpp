// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file http_request.cpp
 * @brief HTTP request implementation
 */

#include "http_request.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace Zepra::Networking {

namespace {

// The pieces of an absolute http(s) URL. One parser for every accessor, so host(),
// port() and path() agree on where the authority ends ("/", "?" or "#", RFC 3986).
struct UrlParts {
    std::string scheme = "http";
    std::string host;      // without brackets for an IPv6 literal
    std::string port;      // digits as written; empty if absent
    bool hostBracketed = false;
    std::string path = "/";
    std::string query;     // without the "?"
};

UrlParts splitUrl(const std::string& url) {
    UrlParts parts;
    size_t start = 0;
    size_t schemeEnd = url.find("://");
    if (schemeEnd != std::string::npos) {
        parts.scheme = url.substr(0, schemeEnd);
        start = schemeEnd + 3;
    }

    size_t authorityEnd = url.find_first_of("/?#", start);
    if (authorityEnd == std::string::npos) authorityEnd = url.size();
    std::string authority = url.substr(start, authorityEnd - start);

    // userinfo is never sent in the request line or Host header
    size_t at = authority.rfind('@');
    if (at != std::string::npos) authority.erase(0, at + 1);

    if (!authority.empty() && authority[0] == '[') {
        size_t close = authority.find(']');
        if (close != std::string::npos) {
            parts.host = authority.substr(1, close - 1);
            parts.hostBracketed = true;
            if (close + 1 < authority.size() && authority[close + 1] == ':') {
                parts.port = authority.substr(close + 2);
            }
        } else {
            parts.host = authority;  // malformed; rejected by validate()
        }
    } else {
        size_t colon = authority.rfind(':');
        if (colon != std::string::npos) {
            parts.host = authority.substr(0, colon);
            parts.port = authority.substr(colon + 1);
        } else {
            parts.host = authority;
        }
    }

    // The fragment never leaves the client
    size_t fragment = url.find('#', authorityEnd);
    size_t rest_end = fragment == std::string::npos ? url.size() : fragment;
    size_t queryStart = url.find('?', authorityEnd);
    if (queryStart != std::string::npos && queryStart < rest_end) {
        parts.query = url.substr(queryStart + 1, rest_end - queryStart - 1);
    } else {
        queryStart = rest_end;
    }
    if (authorityEnd < queryStart && url[authorityEnd] == '/') {
        parts.path = url.substr(authorityEnd, queryStart - authorityEnd);
    }
    return parts;
}

// -1 if the text is not a port number in 1..65535
int parsePort(const std::string& text) {
    if (text.empty() || text.size() > 5) return -1;
    int value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') return -1;
        value = value * 10 + (c - '0');
    }
    return (value >= 1 && value <= 65535) ? value : -1;
}

bool hasControlOrSpace(const std::string& s) {
    for (unsigned char c : s) {
        if (c <= 0x20 || c == 0x7f) return true;
    }
    return false;
}

bool hasLineBreakOrNul(const std::string& s) {
    return s.find_first_of(std::string("\r\n\0", 3)) != std::string::npos;
}

bool equalsIgnoreCase(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
}

} // namespace

HttpRequest::HttpRequest(const std::string& url) : url_(url) {}

HttpRequest::HttpRequest(HttpMethod method, const std::string& url)
    : url_(url), method_(method) {}

void HttpRequest::setUrl(const std::string& url) {
    url_ = url;
}

std::string HttpRequest::methodString() const {
    switch (method_) {
        case HttpMethod::GET: return "GET";
        case HttpMethod::POST: return "POST";
        case HttpMethod::PUT: return "PUT";
        case HttpMethod::DELETE: return "DELETE";
        case HttpMethod::PATCH: return "PATCH";
        case HttpMethod::HEAD: return "HEAD";
        case HttpMethod::OPTIONS: return "OPTIONS";
    }
    return "GET";
}

void HttpRequest::setHeader(const std::string& name, const std::string& value) {
    headers_[name] = value;
}

void HttpRequest::addHeader(const std::string& name, const std::string& value) {
    auto it = headers_.find(name);
    if (it != headers_.end()) {
        it->second += ", " + value;
    } else {
        headers_[name] = value;
    }
}

// Header names are case-insensitive (RFC 9110 section 5.1): a page's "content-type"
// must suppress the client's default "Content-Type", not be sent next to it
std::string HttpRequest::header(const std::string& name) const {
    auto it = headers_.find(name);
    if (it != headers_.end()) return it->second;
    for (const auto& [key, value] : headers_) {
        if (equalsIgnoreCase(key, name)) return value;
    }
    return "";
}

bool HttpRequest::hasHeader(const std::string& name) const {
    if (headers_.find(name) != headers_.end()) return true;
    for (const auto& [key, value] : headers_) {
        if (equalsIgnoreCase(key, name)) return true;
    }
    return false;
}

void HttpRequest::setBody(const std::string& body) {
    body_.assign(body.begin(), body.end());
}

void HttpRequest::setBody(const std::vector<uint8_t>& body) {
    body_ = body;
}

std::string HttpRequest::bodyString() const {
    return std::string(body_.begin(), body_.end());
}

void HttpRequest::setContentType(const std::string& type) {
    setHeader("Content-Type", type);
}

std::string HttpRequest::contentType() const {
    return header("Content-Type");
}

std::string HttpRequest::scheme() const {
    return splitUrl(url_).scheme;
}

std::string HttpRequest::host() const {
    return splitUrl(url_).host;
}

int HttpRequest::port() const {
    UrlParts parts = splitUrl(url_);
    int port = parsePort(parts.port);
    if (port > 0) return port;
    return isSecure() ? 443 : 80;
}

std::string HttpRequest::path() const {
    return splitUrl(url_).path;
}

std::string HttpRequest::query() const {
    return splitUrl(url_).query;
}

std::string HttpRequest::hostHeader() const {
    UrlParts parts = splitUrl(url_);
    return parts.hostBracketed ? "[" + parts.host + "]" : parts.host;
}

bool HttpRequest::validate(std::string& error) const {
    UrlParts parts = splitUrl(url_);
    std::string scheme = parts.scheme;
    std::transform(scheme.begin(), scheme.end(), scheme.begin(), ::tolower);
    if (scheme != "http" && scheme != "https") {
        error = "Unsupported URL scheme: " + parts.scheme;
        return false;
    }
    if (parts.host.empty() || hasControlOrSpace(parts.host) ||
        parts.host.find_first_of("[]/?#@") != std::string::npos) {
        error = "Invalid host in URL";
        return false;
    }
    if (!parts.port.empty() && parsePort(parts.port) < 0) {
        error = "Invalid port in URL";
        return false;
    }
    // A space or line break in the request target would split the request line
    if (hasControlOrSpace(parts.path) || hasControlOrSpace(parts.query)) {
        error = "Invalid character in URL path";
        return false;
    }
    for (const auto& [name, value] : headers_) {
        if (name.empty() || hasControlOrSpace(name) || name.find(':') != std::string::npos ||
            hasLineBreakOrNul(value)) {
            error = "Invalid request header: " + name;
            return false;
        }
    }
    return true;
}

bool HttpRequest::isSecure() const {
    std::string s = scheme();
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s == "https";
}

} // namespace Zepra::Networking
