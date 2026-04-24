// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file http2.cpp
 * @brief HTTP/2 Protocol Implementation
 * 
 * Original implementation following RFC 7540 (HTTP/2) and RFC 7541 (HPACK).
 * Provides binary framing, stream multiplexing, and header compression.
 */

#include "nxhttp.h"
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <mutex>

// ----------------------------------------------------------------------------
// HTTP/2 Frame Types (RFC 7540 Section 6)
// ----------------------------------------------------------------------------

enum H2FrameType : uint8_t {
    H2_FRAME_DATA          = 0x0,
    H2_FRAME_HEADERS       = 0x1,
    H2_FRAME_PRIORITY      = 0x2,
    H2_FRAME_RST_STREAM    = 0x3,
    H2_FRAME_SETTINGS      = 0x4,
    H2_FRAME_PUSH_PROMISE  = 0x5,
    H2_FRAME_PING          = 0x6,
    H2_FRAME_GOAWAY        = 0x7,
    H2_FRAME_WINDOW_UPDATE = 0x8,
    H2_FRAME_CONTINUATION  = 0x9
};

// Frame Flags
static const uint8_t H2_FLAG_END_STREAM  = 0x1;
static const uint8_t H2_FLAG_END_HEADERS = 0x4;
static const uint8_t H2_FLAG_PADDED      = 0x8;
static const uint8_t H2_FLAG_PRIORITY    = 0x20;

// Settings Identifiers  
enum H2SettingId : uint16_t {
    H2_SETTINGS_HEADER_TABLE_SIZE      = 0x1,
    H2_SETTINGS_ENABLE_PUSH            = 0x2,
    H2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
    H2_SETTINGS_INITIAL_WINDOW_SIZE    = 0x4,
    H2_SETTINGS_MAX_FRAME_SIZE         = 0x5,
    H2_SETTINGS_MAX_HEADER_LIST_SIZE   = 0x6
};

// Error Codes
enum H2ErrorCode : uint32_t {
    H2_NO_ERROR            = 0x0,
    H2_PROTOCOL_ERROR      = 0x1,
    H2_INTERNAL_ERROR      = 0x2,
    H2_FLOW_CONTROL_ERROR  = 0x3,
    H2_SETTINGS_TIMEOUT    = 0x4,
    H2_STREAM_CLOSED       = 0x5,
    H2_FRAME_SIZE_ERROR    = 0x6,
    H2_REFUSED_STREAM      = 0x7,
    H2_CANCEL              = 0x8,
    H2_COMPRESSION_ERROR   = 0x9,
    H2_CONNECT_ERROR       = 0xa,
    H2_ENHANCE_YOUR_CALM   = 0xb,
    H2_INADEQUATE_SECURITY = 0xc,
    H2_HTTP_1_1_REQUIRED   = 0xd
};

// Connection preface
static const char* H2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
static const size_t H2_PREFACE_LEN = 24;

// ----------------------------------------------------------------------------
// HPACK Static Table (RFC 7541 Appendix A)
// ----------------------------------------------------------------------------

struct HpackEntry {
    const char* name;
    const char* value;
};

static const HpackEntry HPACK_STATIC_TABLE[] = {
    {nullptr, nullptr},  // Index 0 is unused
    {":authority", ""},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", ""},
    {"accept-ranges", ""},
    {"accept", ""},
    {"access-control-allow-origin", ""},
    {"age", ""},
    {"allow", ""},
    {"authorization", ""},
    {"cache-control", ""},
    {"content-disposition", ""},
    {"content-encoding", ""},
    {"content-language", ""},
    {"content-length", ""},
    {"content-location", ""},
    {"content-range", ""},
    {"content-type", ""},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"expect", ""},
    {"expires", ""},
    {"from", ""},
    {"host", ""},
    {"if-match", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"if-range", ""},
    {"if-unmodified-since", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"max-forwards", ""},
    {"proxy-authenticate", ""},
    {"proxy-authorization", ""},
    {"range", ""},
    {"referer", ""},
    {"refresh", ""},
    {"retry-after", ""},
    {"server", ""},
    {"set-cookie", ""},
    {"strict-transport-security", ""},
    {"transfer-encoding", ""},
    {"user-agent", ""},
    {"vary", ""},
    {"via", ""},
    {"www-authenticate", ""}
};

static const size_t HPACK_STATIC_TABLE_SIZE = sizeof(HPACK_STATIC_TABLE) / sizeof(HpackEntry);

// ----------------------------------------------------------------------------
// HPACK Dynamic Table
// ----------------------------------------------------------------------------

struct HpackDynamicEntry {
    std::string name;
    std::string value;
    
    size_t size() const {
        return name.size() + value.size() + 32;  // RFC 7541: entry size = name + value + 32
    }
};

struct HpackContext {
    std::vector<HpackDynamicEntry> dynamic_table;
    size_t max_table_size;
    size_t current_size;
    
    HpackContext() : max_table_size(4096), current_size(0) {}
    
    void add_entry(const std::string& name, const std::string& value) {
        HpackDynamicEntry entry{name, value};
        size_t entry_size = entry.size();
        
        // Evict entries if needed
        while (current_size + entry_size > max_table_size && !dynamic_table.empty()) {
            current_size -= dynamic_table.back().size();
            dynamic_table.pop_back();
        }
        
        if (entry_size <= max_table_size) {
            dynamic_table.insert(dynamic_table.begin(), entry);
            current_size += entry_size;
        }
    }
    
    bool get_entry(size_t index, std::string& name, std::string& value) const {
        if (index == 0) return false;
        
        if (index < HPACK_STATIC_TABLE_SIZE) {
            name = HPACK_STATIC_TABLE[index].name;
            value = HPACK_STATIC_TABLE[index].value;
            return true;
        }
        
        size_t dyn_index = index - HPACK_STATIC_TABLE_SIZE;
        if (dyn_index < dynamic_table.size()) {
            name = dynamic_table[dyn_index].name;
            value = dynamic_table[dyn_index].value;
            return true;
        }
        
        return false;
    }
};

// ----------------------------------------------------------------------------
// HPACK Encoding/Decoding
// ----------------------------------------------------------------------------

// Encode integer with prefix (RFC 7541 Section 5.1)
static void hpack_encode_int(std::vector<uint8_t>& out, uint32_t value, uint8_t prefix_bits, uint8_t prefix) {
    uint8_t max_prefix = (1 << prefix_bits) - 1;
    
    if (value < max_prefix) {
        out.push_back(prefix | static_cast<uint8_t>(value));
    } else {
        out.push_back(prefix | max_prefix);
        value -= max_prefix;
        while (value >= 128) {
            out.push_back(0x80 | (value & 0x7F));
            value >>= 7;
        }
        out.push_back(static_cast<uint8_t>(value));
    }
}

// Decode integer with prefix
static bool hpack_decode_int(const uint8_t*& p, const uint8_t* end, uint8_t prefix_bits, uint32_t& value) {
    if (p >= end) return false;
    
    uint8_t max_prefix = (1 << prefix_bits) - 1;
    value = *p++ & max_prefix;
    
    if (value < max_prefix) return true;
    
    uint32_t m = 0;
    while (p < end) {
        uint8_t b = *p++;
        value += static_cast<uint32_t>(b & 0x7F) << m;
        m += 7;
        
        if ((b & 0x80) == 0) return true;
        if (m > 28) return false;  // Overflow protection
    }
    
    return false;
}

// Encode string (RFC 7541 Section 5.2)
static void hpack_encode_string(std::vector<uint8_t>& out, const std::string& str, bool huffman = false) {
    // For simplicity, we're not implementing Huffman coding here
    // Just use literal string encoding
    hpack_encode_int(out, static_cast<uint32_t>(str.size()), 7, 0);
    out.insert(out.end(), str.begin(), str.end());
}

// Decode string
static bool hpack_decode_string(const uint8_t*& p, const uint8_t* end, std::string& str) {
    if (p >= end) return false;
    
    bool huffman = (*p & 0x80) != 0;
    uint32_t length;
    
    if (!hpack_decode_int(p, end, 7, length)) return false;
    if (p + length > end) return false;
    
    if (huffman) {
        // Huffman decoding would go here
        // For now, just treat as raw bytes (simplified)
        str.assign(reinterpret_cast<const char*>(p), length);
    } else {
        str.assign(reinterpret_cast<const char*>(p), length);
    }
    
    p += length;
    return true;
}

// Encode header block
static bool hpack_encode_headers(HpackContext& ctx, 
                                  const std::vector<std::pair<std::string, std::string>>& headers,
                                  std::vector<uint8_t>& out) {
    for (const auto& header : headers) {
        const std::string& name = header.first;
        const std::string& value = header.second;
        
        // Check static table for exact match
        size_t name_index = 0;
        bool exact_match = false;
        
        for (size_t i = 1; i < HPACK_STATIC_TABLE_SIZE; i++) {
            if (HPACK_STATIC_TABLE[i].name && name == HPACK_STATIC_TABLE[i].name) {
                if (HPACK_STATIC_TABLE[i].value && value == HPACK_STATIC_TABLE[i].value) {
                    exact_match = true;
                    name_index = i;
                    break;
                }
                if (name_index == 0) name_index = i;
            }
        }
        
        if (exact_match) {
            // Indexed header field (Section 6.1)
            hpack_encode_int(out, static_cast<uint32_t>(name_index), 7, 0x80);
        } else if (name_index > 0) {
            // Literal with indexed name (Section 6.2.1)
            hpack_encode_int(out, static_cast<uint32_t>(name_index), 6, 0x40);
            hpack_encode_string(out, value);
            ctx.add_entry(name, value);
        } else {
            // Literal with new name (Section 6.2.1)
            out.push_back(0x40);
            hpack_encode_string(out, name);
            hpack_encode_string(out, value);
            ctx.add_entry(name, value);
        }
    }
    
    return true;
}

// Decode header block
static bool hpack_decode_headers(HpackContext& ctx,
                                  const uint8_t* data, size_t len,
                                  std::vector<std::pair<std::string, std::string>>& headers) {
    const uint8_t* p = data;
    const uint8_t* end = data + len;
    
    while (p < end) {
        std::string name, value;
        
        if (*p & 0x80) {
            // Indexed header field
            uint32_t index;
            if (!hpack_decode_int(p, end, 7, index)) return false;
            if (!ctx.get_entry(index, name, value)) return false;
        } else if (*p & 0x40) {
            // Literal with incremental indexing
            uint32_t index;
            if (!hpack_decode_int(p, end, 6, index)) return false;
            
            if (index > 0) {
                if (!ctx.get_entry(index, name, value)) return false;
            } else {
                if (!hpack_decode_string(p, end, name)) return false;
            }
            
            if (!hpack_decode_string(p, end, value)) return false;
            ctx.add_entry(name, value);
        } else if (*p & 0x20) {
            // Dynamic table size update
            uint32_t new_size;
            if (!hpack_decode_int(p, end, 5, new_size)) return false;
            ctx.max_table_size = new_size;
            continue;
        } else {
            // Literal without indexing or never indexed
            uint32_t index;
            uint8_t mask = (*p & 0x10) ? 0x10 : 0;
            if (!hpack_decode_int(p, end, 4, index)) return false;
            
            if (index > 0) {
                if (!ctx.get_entry(index, name, value)) return false;
            } else {
                if (!hpack_decode_string(p, end, name)) return false;
            }
            
            if (!hpack_decode_string(p, end, value)) return false;
            (void)mask;  // We don't track never-indexed for now
        }
        
        headers.push_back({name, value});
    }
    
    return true;
}

// ----------------------------------------------------------------------------
// HTTP/2 Frame
// ----------------------------------------------------------------------------

struct H2Frame {
    uint32_t length;        // 24-bit
    H2FrameType type;
    uint8_t flags;
    uint32_t stream_id;     // 31-bit
    std::vector<uint8_t> payload;
};

// Serialize frame to bytes
static std::vector<uint8_t> h2_serialize_frame(const H2Frame& frame) {
    std::vector<uint8_t> out;
    out.reserve(9 + frame.payload.size());
    
    // Length (24 bits)
    out.push_back(static_cast<uint8_t>((frame.length >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((frame.length >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(frame.length & 0xFF));
    
    // Type
    out.push_back(static_cast<uint8_t>(frame.type));
    
    // Flags
    out.push_back(frame.flags);
    
    // Stream ID (31 bits, MSB reserved)
    out.push_back(static_cast<uint8_t>((frame.stream_id >> 24) & 0x7F));
    out.push_back(static_cast<uint8_t>((frame.stream_id >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((frame.stream_id >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(frame.stream_id & 0xFF));
    
    // Payload
    out.insert(out.end(), frame.payload.begin(), frame.payload.end());
    
    return out;
}

// Parse frame from bytes
static bool h2_parse_frame(const uint8_t* data, size_t len, H2Frame& frame, size_t& consumed) {
    if (len < 9) return false;
    
    // Length
    frame.length = (static_cast<uint32_t>(data[0]) << 16) |
                   (static_cast<uint32_t>(data[1]) << 8) |
                   static_cast<uint32_t>(data[2]);
    
    // Type
    frame.type = static_cast<H2FrameType>(data[3]);
    
    // Flags
    frame.flags = data[4];
    
    // Stream ID
    frame.stream_id = ((static_cast<uint32_t>(data[5]) & 0x7F) << 24) |
                      (static_cast<uint32_t>(data[6]) << 16) |
                      (static_cast<uint32_t>(data[7]) << 8) |
                      static_cast<uint32_t>(data[8]);
    
    if (len < 9 + frame.length) return false;
    
    // Payload
    frame.payload.assign(data + 9, data + 9 + frame.length);
    consumed = 9 + frame.length;
    
    return true;
}

// ----------------------------------------------------------------------------
// HTTP/2 Stream
// ----------------------------------------------------------------------------

enum H2StreamState {
    H2_STATE_IDLE,
    H2_STATE_OPEN,
    H2_STATE_HALF_CLOSED_LOCAL,
    H2_STATE_HALF_CLOSED_REMOTE,
    H2_STATE_CLOSED
};

struct H2Stream {
    uint32_t id;
    H2StreamState state;
    int32_t send_window;
    int32_t recv_window;
    std::vector<std::pair<std::string, std::string>> request_headers;
    std::vector<std::pair<std::string, std::string>> response_headers;
    std::vector<uint8_t> data;
};

// ----------------------------------------------------------------------------
// HTTP/2 Session
// ----------------------------------------------------------------------------

struct NxHttp2Session {
    void* socket;                           // Underlying socket
    bool is_ssl;
    HpackContext hpack_encoder;
    HpackContext hpack_decoder;
    
    std::map<uint32_t, H2Stream> streams;
    uint32_t next_stream_id;                // Odd for client
    
    // Connection settings
    uint32_t header_table_size;
    uint32_t enable_push;
    uint32_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
    uint32_t max_header_list_size;
    
    int32_t send_window;
    int32_t recv_window;
    
    std::mutex session_mutex;
    bool connection_error;
    H2ErrorCode error_code;
    
    NxHttp2Session() 
        : socket(nullptr), is_ssl(false), next_stream_id(1),
          header_table_size(4096), enable_push(1),
          max_concurrent_streams(100), initial_window_size(65535),
          max_frame_size(16384), max_header_list_size(8192),
          send_window(65535), recv_window(65535),
          connection_error(false), error_code(H2_NO_ERROR) {}
};

// ----------------------------------------------------------------------------
// Public C API
// ----------------------------------------------------------------------------

extern "C" {

NxHttp2Session* nx_http2_session_create(void) {
#if !NXHTTP_ENABLE_HTTP2
    // HTTP/2 is disabled by default for security
    // Define NXHTTP_ENABLE_HTTP2=1 to enable after testing
    return nullptr;
#else
    return new NxHttp2Session();
#endif
}

void nx_http2_session_free(NxHttp2Session* session) {
    delete session;
}

bool nx_http2_send_preface(NxHttp2Session* session, uint8_t* out_buf, size_t* out_len) {
    if (!session || !out_buf || !out_len) return false;
    
    // Connection preface + SETTINGS frame
    size_t needed = H2_PREFACE_LEN + 9;  // Preface + empty SETTINGS
    if (*out_len < needed) return false;
    
    // Copy preface
    memcpy(out_buf, H2_PREFACE, H2_PREFACE_LEN);
    
    // Add empty SETTINGS frame
    H2Frame settings;
    settings.length = 0;
    settings.type = H2_FRAME_SETTINGS;
    settings.flags = 0;
    settings.stream_id = 0;
    
    auto frame_data = h2_serialize_frame(settings);
    memcpy(out_buf + H2_PREFACE_LEN, frame_data.data(), frame_data.size());
    
    *out_len = H2_PREFACE_LEN + frame_data.size();
    return true;
}

uint32_t nx_http2_create_stream(NxHttp2Session* session) {
    if (!session) return 0;
    
    std::lock_guard<std::mutex> lock(session->session_mutex);
    
    uint32_t stream_id = session->next_stream_id;
    session->next_stream_id += 2;  // Client streams are odd
    
    H2Stream stream;
    stream.id = stream_id;
    stream.state = H2_STATE_OPEN;
    stream.send_window = static_cast<int32_t>(session->initial_window_size);
    stream.recv_window = static_cast<int32_t>(session->initial_window_size);
    
    session->streams[stream_id] = stream;
    
    return stream_id;
}

bool nx_http2_encode_headers(NxHttp2Session* session, uint32_t stream_id,
                              const char** names, const char** values, size_t count,
                              uint8_t* out_buf, size_t* out_len) {
    if (!session || !names || !values || !out_buf || !out_len) return false;
    
    std::lock_guard<std::mutex> lock(session->session_mutex);
    
    std::vector<std::pair<std::string, std::string>> headers;
    for (size_t i = 0; i < count; i++) {
        headers.push_back({names[i], values[i]});
    }
    
    std::vector<uint8_t> header_block;
    if (!hpack_encode_headers(session->hpack_encoder, headers, header_block)) {
        return false;
    }
    
    H2Frame frame;
    frame.length = static_cast<uint32_t>(header_block.size());
    frame.type = H2_FRAME_HEADERS;
    frame.flags = H2_FLAG_END_HEADERS;  // Simple case: one frame
    frame.stream_id = stream_id;
    frame.payload = header_block;
    
    auto frame_bytes = h2_serialize_frame(frame);
    if (*out_len < frame_bytes.size()) return false;
    
    memcpy(out_buf, frame_bytes.data(), frame_bytes.size());
    *out_len = frame_bytes.size();
    
    return true;
}

bool nx_http2_decode_headers(NxHttp2Session* session, const uint8_t* data, size_t len,
                              char*** out_names, char*** out_values, size_t* out_count) {
    if (!session || !data || !out_names || !out_values || !out_count) return false;
    
    std::lock_guard<std::mutex> lock(session->session_mutex);
    
    std::vector<std::pair<std::string, std::string>> headers;
    if (!hpack_decode_headers(session->hpack_decoder, data, len, headers)) {
        return false;
    }
    
    *out_count = headers.size();
    *out_names = static_cast<char**>(malloc(headers.size() * sizeof(char*)));
    *out_values = static_cast<char**>(malloc(headers.size() * sizeof(char*)));
    
    for (size_t i = 0; i < headers.size(); i++) {
        (*out_names)[i] = strdup(headers[i].first.c_str());
        (*out_values)[i] = strdup(headers[i].second.c_str());
    }
    
    return true;
}

bool nx_http2_parse_frame(const uint8_t* data, size_t len,
                           uint8_t* out_type, uint8_t* out_flags,
                           uint32_t* out_stream_id, size_t* out_payload_len) {
    if (!data || len < 9) return false;
    
    H2Frame frame;
    size_t consumed;
    
    if (!h2_parse_frame(data, len, frame, consumed)) return false;
    
    if (out_type) *out_type = static_cast<uint8_t>(frame.type);
    if (out_flags) *out_flags = frame.flags;
    if (out_stream_id) *out_stream_id = frame.stream_id;
    if (out_payload_len) *out_payload_len = frame.length;
    
    return true;
}

const char* nx_http2_error_string(uint32_t error_code) {
    switch (static_cast<H2ErrorCode>(error_code)) {
        case H2_NO_ERROR: return "No error";
        case H2_PROTOCOL_ERROR: return "Protocol error";
        case H2_INTERNAL_ERROR: return "Internal error";
        case H2_FLOW_CONTROL_ERROR: return "Flow control error";
        case H2_SETTINGS_TIMEOUT: return "Settings timeout";
        case H2_STREAM_CLOSED: return "Stream closed";
        case H2_FRAME_SIZE_ERROR: return "Frame size error";
        case H2_REFUSED_STREAM: return "Refused stream";
        case H2_CANCEL: return "Cancelled";
        case H2_COMPRESSION_ERROR: return "Compression error";
        case H2_CONNECT_ERROR: return "Connect error";
        case H2_ENHANCE_YOUR_CALM: return "Rate limit exceeded";
        case H2_INADEQUATE_SECURITY: return "Inadequate security";
        case H2_HTTP_1_1_REQUIRED: return "HTTP/1.1 required";
        default: return "Unknown error";
    }
}

} // extern "C"
