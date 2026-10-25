// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file http_response_reader.cpp
 * @brief HTTP/1.x response framing (Content-Length, chunked, close-delimited)
 */

#include "http_response_reader.hpp"

#include <algorithm>
#include <cctype>

namespace Zepra::Networking {

namespace {

constexpr size_t MAX_LINE = 64 * 1024;          // one header or chunk-size line
constexpr size_t MAX_HEAD = 256 * 1024;         // status line + all headers
constexpr size_t MAX_RESERVE = 16 * 1024 * 1024; // don't trust Content-Length for more
constexpr int MAX_INTERIM = 16;                 // 1xx responses before the real one

bool equalsIgnoreCase(const std::string& a, const char* b) {
    size_t n = std::char_traits<char>::length(b);
    if (a.size() != n) return false;
    for (size_t i = 0; i < n; ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

// True if the comma-separated list contains token (case-insensitive)
bool listHasToken(const std::string& list, const char* token) {
    size_t start = 0;
    while (start <= list.size()) {
        size_t comma = list.find(',', start);
        std::string item = trim(list.substr(start, comma == std::string::npos
                                                   ? std::string::npos : comma - start));
        if (equalsIgnoreCase(item, token)) return true;
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return false;
}

// Buffered reader over HttpReadFn
class WireReader {
public:
    explicit WireReader(const HttpReadFn& read) : read_(read) {}

    size_t bytesReceived() const { return received_; }
    size_t buffered() const { return buf_.size() - pos_; }

    // Next line without its CRLF (a bare LF is accepted); false at EOF or if too long
    bool readLine(std::string& line) {
        size_t searchFrom = pos_;
        for (;;) {
            size_t lf = buf_.find('\n', searchFrom);
            if (lf != std::string::npos) {
                size_t end = (lf > pos_ && buf_[lf - 1] == '\r') ? lf - 1 : lf;
                line.assign(buf_, pos_, end - pos_);
                pos_ = lf + 1;
                return true;
            }
            if (buffered() > MAX_LINE) return false;
            searchFrom = buf_.size();
            size_t before = pos_;
            if (!fill()) return false;
            searchFrom -= before - pos_;  // fill() may compact the buffer
        }
    }

    // Appends exactly n bytes to out; false if the stream ended first
    // (what did arrive is still appended)
    bool readExact(size_t n, std::vector<uint8_t>& out) {
        while (n > 0) {
            if (buffered() == 0 && !fill()) return false;
            size_t take = std::min(n, buffered());
            out.insert(out.end(), buf_.begin() + pos_, buf_.begin() + pos_ + take);
            pos_ += take;
            n -= take;
        }
        return true;
    }

    // Appends everything until the peer closes; false if it ended in an error
    bool readToEnd(std::vector<uint8_t>& out) {
        for (;;) {
            out.insert(out.end(), buf_.begin() + pos_, buf_.end());
            pos_ = buf_.size();
            if (!fill()) return !failed_;
        }
    }

private:
    bool fill() {
        if (pos_ == buf_.size()) {
            buf_.clear();
            pos_ = 0;
        } else if (pos_ > 64 * 1024) {
            buf_.erase(0, pos_);
            pos_ = 0;
        }
        char tmp[16 * 1024];
        long n = read_(tmp, sizeof(tmp));
        if (n > 0) {
            buf_.append(tmp, static_cast<size_t>(n));
            received_ += static_cast<size_t>(n);
            return true;
        }
        if (n < 0) failed_ = true;
        return false;
    }

    const HttpReadFn& read_;
    std::string buf_;
    size_t pos_ = 0;
    size_t received_ = 0;
    bool failed_ = false;
};

// "HTTP/1.1 200 OK"
bool parseStatusLine(const std::string& line, HttpWireResponse& out) {
    if (line.size() < 12 || line.compare(0, 7, "HTTP/1.") != 0) return false;
    if (!std::isdigit(static_cast<unsigned char>(line[7])) || line[8] != ' ') return false;
    if (!std::isdigit(static_cast<unsigned char>(line[9])) ||
        !std::isdigit(static_cast<unsigned char>(line[10])) ||
        !std::isdigit(static_cast<unsigned char>(line[11]))) return false;
    if (line.size() > 12 && line[12] != ' ') return false;
    out.versionMinor = line[7] - '0';
    out.statusCode = (line[9] - '0') * 100 + (line[10] - '0') * 10 + (line[11] - '0');
    out.statusMessage = line.size() > 13 ? line.substr(13) : "";
    return true;
}

bool readHead(WireReader& reader, HttpWireResponse& out) {
    std::string line;
    // Tolerate stray blank lines before the status line (RFC 9112 section 2.2)
    do {
        if (!reader.readLine(line)) {
            out.error = reader.bytesReceived() == 0 ? "Connection closed before response"
                                                    : "Truncated response status line";
            return false;
        }
    } while (line.empty());

    if (!parseStatusLine(line, out)) {
        out.error = "Invalid response status line";
        return false;
    }

    out.headers.clear();
    size_t headSize = line.size();
    for (;;) {
        if (!reader.readLine(line)) {
            out.error = "Truncated response headers";
            return false;
        }
        if (line.empty()) return true;
        headSize += line.size() + 2;
        if (headSize > MAX_HEAD) {
            out.error = "Response headers too large";
            return false;
        }
        if ((line[0] == ' ' || line[0] == '\t') && !out.headers.empty()) {
            // obs-fold: continuation of the previous header value
            out.headers.back().second += " " + trim(line);
            continue;
        }
        size_t colon = line.find(':');
        if (colon == std::string::npos || colon == 0) continue;  // ignore junk lines
        out.headers.emplace_back(trim(line.substr(0, colon)), trim(line.substr(colon + 1)));
    }
}

// Content-Length: one value, or a list of identical values; -1 if invalid
long long parseContentLength(const HttpWireResponse& res, bool& present) {
    long long value = -1;
    present = false;
    for (const auto& [name, raw] : res.headers) {
        if (!equalsIgnoreCase(name, "Content-Length")) continue;
        present = true;
        size_t start = 0;
        while (start <= raw.size()) {
            size_t comma = raw.find(',', start);
            std::string item = trim(raw.substr(start, comma == std::string::npos
                                                      ? std::string::npos : comma - start));
            if (item.empty() || item.size() > 15 ||
                !std::all_of(item.begin(), item.end(),
                             [](unsigned char c) { return std::isdigit(c); })) {
                return -1;
            }
            long long v = std::stoll(item);
            if (value >= 0 && v != value) return -1;
            value = v;
            if (comma == std::string::npos) break;
            start = comma + 1;
        }
    }
    return value;
}

// Chunk-size line: hex digits, optionally followed by ";ext"
bool parseChunkSize(const std::string& line, size_t& size) {
    size = 0;
    size_t i = 0;
    int digits = 0;
    for (; i < line.size(); ++i) {
        char c = line[i];
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else break;
        if (++digits > 15) return false;  // > 1 PB chunk: not real
        size = size * 16 + static_cast<size_t>(v);
    }
    if (digits == 0) return false;
    for (; i < line.size(); ++i) {
        if (line[i] == ';') return true;
        if (line[i] != ' ' && line[i] != '\t') return false;
    }
    return true;
}

// Returns true if the chunked body ended with its zero-size chunk and trailers
bool readChunked(WireReader& reader, std::vector<uint8_t>& body) {
    std::string line;
    for (;;) {
        size_t size = 0;
        if (!reader.readLine(line) || !parseChunkSize(line, size)) return false;
        if (size == 0) break;
        if (!reader.readExact(size, body)) return false;
        if (!reader.readLine(line) || !line.empty()) return false;  // CRLF after data
    }
    // Trailer fields, ended by an empty line
    for (;;) {
        if (!reader.readLine(line)) return false;
        if (line.empty()) return true;
    }
}

} // namespace

const std::string* HttpWireResponse::header(const std::string& name) const {
    for (const auto& h : headers) {
        if (equalsIgnoreCase(h.first, name.c_str())) return &h.second;
    }
    return nullptr;
}

bool readHttpResponse(const HttpReadFn& read, bool headRequest, HttpWireResponse& out) {
    WireReader reader(read);
    out = HttpWireResponse{};

    // Skip interim responses (100 Continue, 103 Early Hints); 101 ends the HTTP exchange
    for (int interim = 0;; ++interim) {
        if (!readHead(reader, out)) {
            out.bytesReceived = reader.bytesReceived();
            return false;
        }
        if (out.statusCode < 100 || out.statusCode >= 200 || out.statusCode == 101) break;
        if (interim >= MAX_INTERIM) {
            out.error = "Too many interim responses";
            out.bytesReceived = reader.bytesReceived();
            return false;
        }
    }

    std::string connection;
    for (const auto& [name, value] : out.headers) {
        if (equalsIgnoreCase(name, "Connection")) connection += value + ",";
    }
    bool persistent = out.versionMinor >= 1 ? !listHasToken(connection, "close")
                                            : listHasToken(connection, "keep-alive");

    const std::string* te = out.header("Transfer-Encoding");
    bool clPresent = false;
    long long contentLength = parseContentLength(out, clPresent);

    bool noBody = headRequest || out.statusCode == 101 || out.statusCode == 204 ||
                  out.statusCode == 304 || out.statusCode < 200;

    if (out.statusCode == 101) {
        persistent = false;  // the connection now speaks another protocol
        out.complete = true;
    } else if (noBody) {
        out.complete = true;
    } else if (te) {
        // Transfer-Encoding wins over Content-Length; chunked must be the final coding
        std::string codings = lower(*te);
        size_t lastComma = codings.rfind(',');
        std::string last = trim(lastComma == std::string::npos ? codings
                                                               : codings.substr(lastComma + 1));
        if (last == "chunked") {
            out.complete = readChunked(reader, out.body);
            if (clPresent) persistent = false;  // ambiguous framing: don't reuse
        } else {
            out.complete = reader.readToEnd(out.body);
            persistent = false;
        }
    } else if (clPresent) {
        if (contentLength < 0) {
            out.error = "Invalid Content-Length";
            out.bytesReceived = reader.bytesReceived();
            return false;
        }
        size_t len = static_cast<size_t>(contentLength);
        out.body.reserve(std::min(len, MAX_RESERVE));
        out.complete = reader.readExact(len, out.body);
    } else {
        // No framing: the body ends when the server closes the connection
        out.complete = reader.readToEnd(out.body);
        persistent = false;
    }

    // Bytes past the end of the response mean we lost track of the framing
    out.keepAlive = persistent && out.complete && reader.buffered() == 0;
    out.bytesReceived = reader.bytesReceived();
    return true;
}

} // namespace Zepra::Networking
