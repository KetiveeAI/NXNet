// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file punycode.cpp
 * @brief Punycode encoding/decoding for Internationalized Domain Names (IDN)
 * 
 * Original implementation based on RFC 3492 algorithm.
 * Converts Unicode domain labels to ASCII-compatible encoding.
 */

#include "nxhttp.h"
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

// ----------------------------------------------------------------------------
// Punycode Constants (RFC 3492)
// ----------------------------------------------------------------------------

static const int32_t PUNY_BASE = 36;
static const int32_t PUNY_TMIN = 1;
static const int32_t PUNY_TMAX = 26;
static const int32_t PUNY_SKEW = 38;
static const int32_t PUNY_DAMP = 700;
static const int32_t PUNY_INITIAL_BIAS = 72;
static const int32_t PUNY_INITIAL_N = 128;
static const char PUNY_DELIMITER = '-';
static const char* PUNY_PREFIX = "xn--";

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

// Encode a digit to base-36 character
static char encode_digit(int32_t d) {
    if (d < 26) return 'a' + d;
    return '0' + (d - 26);
}

// Decode a base-36 character to digit
static int32_t decode_digit(char c) {
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= '0' && c <= '9') return 26 + c - '0';
    return -1;
}

// Bias adaptation function (RFC 3492 Section 3.4)
static int32_t adapt_bias(int32_t delta, int32_t num_points, bool first_time) {
    delta = first_time ? delta / PUNY_DAMP : delta / 2;
    delta += delta / num_points;
    
    int32_t k = 0;
    while (delta > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) / 2) {
        delta /= (PUNY_BASE - PUNY_TMIN);
        k += PUNY_BASE;
    }
    
    return k + ((PUNY_BASE - PUNY_TMIN + 1) * delta) / (delta + PUNY_SKEW);
}

// Check if character is basic ASCII (0-127)
static bool is_basic(uint32_t cp) {
    return cp < 128;
}

// Convert UTF-8 string to Unicode code points
// STRICT MODE: Returns empty vector on ANY invalid UTF-8
// Does NOT guess or skip invalid bytes - security critical
static std::vector<uint32_t> utf8_to_codepoints(const char* str, bool* valid = nullptr) {
    std::vector<uint32_t> result;
    const unsigned char* p = reinterpret_cast<const unsigned char*>(str);
    bool is_valid = true;
    
    while (*p) {
        uint32_t cp;
        int expected_continuation = 0;
        
        if (*p < 0x80) {
            // Single byte (ASCII)
            cp = *p++;
        } else if ((*p & 0xE0) == 0xC0) {
            // Two bytes
            if (*p < 0xC2) {
                // Overlong encoding (security issue!)
                is_valid = false;
                break;
            }
            cp = (*p++ & 0x1F) << 6;
            expected_continuation = 1;
        } else if ((*p & 0xF0) == 0xE0) {
            // Three bytes
            cp = (*p++ & 0x0F) << 12;
            expected_continuation = 2;
        } else if ((*p & 0xF8) == 0xF0) {
            // Four bytes
            if (*p > 0xF4) {
                // Code point would be > U+10FFFF
                is_valid = false;
                break;
            }
            cp = (*p++ & 0x07) << 18;
            expected_continuation = 3;
        } else {
            // Invalid start byte (0x80-0xBF, 0xF5-0xFF)
            is_valid = false;
            break;
        }
        
        // Read continuation bytes
        for (int i = expected_continuation - 1; i >= 0; i--) {
            if ((*p & 0xC0) != 0x80) {
                // Missing or invalid continuation byte
                is_valid = false;
                break;
            }
            cp |= static_cast<uint32_t>(*p++ & 0x3F) << (i * 6);
        }
        
        if (!is_valid) break;
        
        // Validate code point range
        if (cp > 0x10FFFF) {
            is_valid = false;
            break;
        }
        
        // Reject surrogate code points (U+D800-U+DFFF)
        if (cp >= 0xD800 && cp <= 0xDFFF) {
            is_valid = false;
            break;
        }
        
        result.push_back(cp);
    }
    
    if (valid) *valid = is_valid;
    
#if NXHTTP_STRICT_IDN
    // In strict mode, return empty on invalid
    if (!is_valid) {
        result.clear();
    }
#endif
    
    return result;
}

// Convert Unicode code points to UTF-8 string
static std::string codepoints_to_utf8(const std::vector<uint32_t>& cps) {
    std::string result;
    
    for (uint32_t cp : cps) {
        if (cp < 0x80) {
            result += static_cast<char>(cp);
        } else if (cp < 0x800) {
            result += static_cast<char>(0xC0 | (cp >> 6));
            result += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            result += static_cast<char>(0xE0 | (cp >> 12));
            result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            result += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            result += static_cast<char>(0xF0 | (cp >> 18));
            result += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            result += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            result += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    
    return result;
}

// ----------------------------------------------------------------------------
// Punycode Encoding (RFC 3492 Section 6.3)
// ----------------------------------------------------------------------------

static bool punycode_encode_label(const std::vector<uint32_t>& input, std::string& output) {
    output.clear();
    
    // Copy all basic code points to output
    size_t basic_count = 0;
    for (uint32_t cp : input) {
        if (is_basic(cp)) {
            output += static_cast<char>(cp);
            basic_count++;
        }
    }
    
    // Add delimiter if we have basic characters AND non-basic characters
    size_t handled = basic_count;
    if (basic_count > 0 && basic_count < input.size()) {
        output += PUNY_DELIMITER;
    }
    
    int32_t n = PUNY_INITIAL_N;
    int32_t delta = 0;
    int32_t bias = PUNY_INITIAL_BIAS;
    
    while (handled < input.size()) {
        // Find the minimum code point >= n
        int32_t m = INT32_MAX;
        for (uint32_t cp : input) {
            if (static_cast<int32_t>(cp) >= n && static_cast<int32_t>(cp) < m) {
                m = static_cast<int32_t>(cp);
            }
        }
        
        // Check for overflow
        if (m - n > (INT32_MAX - delta) / static_cast<int32_t>(handled + 1)) {
            return false;
        }
        
        delta += (m - n) * static_cast<int32_t>(handled + 1);
        n = m;
        
        for (uint32_t cp : input) {
            if (static_cast<int32_t>(cp) < n) {
                delta++;
                if (delta < 0) return false;  // Overflow
            }
            
            if (static_cast<int32_t>(cp) == n) {
                // Encode delta as variable-length integer
                int32_t q = delta;
                int32_t k = PUNY_BASE;
                
                while (true) {
                    int32_t t;
                    if (k <= bias) t = PUNY_TMIN;
                    else if (k >= bias + PUNY_TMAX) t = PUNY_TMAX;
                    else t = k - bias;
                    
                    if (q < t) break;
                    
                    output += encode_digit(t + (q - t) % (PUNY_BASE - t));
                    q = (q - t) / (PUNY_BASE - t);
                    k += PUNY_BASE;
                }
                
                output += encode_digit(q);
                bias = adapt_bias(delta, static_cast<int32_t>(handled + 1), handled == basic_count);
                delta = 0;
                handled++;
            }
        }
        
        delta++;
        n++;
    }
    
    return true;
}

// ----------------------------------------------------------------------------
// Punycode Decoding (RFC 3492 Section 6.2)
// ----------------------------------------------------------------------------

static bool punycode_decode_label(const char* input, std::vector<uint32_t>& output) {
    output.clear();
    
    // Find the last delimiter
    const char* delim_pos = strrchr(input, PUNY_DELIMITER);
    
    // Copy basic characters
    if (delim_pos) {
        for (const char* p = input; p < delim_pos; p++) {
            if (!is_basic(static_cast<unsigned char>(*p))) return false;
            output.push_back(static_cast<uint32_t>(*p));
        }
        input = delim_pos + 1;
    }
    
    int32_t n = PUNY_INITIAL_N;
    int32_t i = 0;
    int32_t bias = PUNY_INITIAL_BIAS;
    
    while (*input) {
        int32_t old_i = i;
        int32_t w = 1;
        int32_t k = PUNY_BASE;
        
        while (true) {
            if (!*input) return false;
            
            int32_t digit = decode_digit(*input++);
            if (digit < 0) return false;
            
            if (digit > (INT32_MAX - i) / w) return false;
            i += digit * w;
            
            int32_t t;
            if (k <= bias) t = PUNY_TMIN;
            else if (k >= bias + PUNY_TMAX) t = PUNY_TMAX;
            else t = k - bias;
            
            if (digit < t) break;
            
            if (w > INT32_MAX / (PUNY_BASE - t)) return false;
            w *= (PUNY_BASE - t);
            k += PUNY_BASE;
        }
        
        bias = adapt_bias(i - old_i, static_cast<int32_t>(output.size() + 1), old_i == 0);
        
        if (i / static_cast<int32_t>(output.size() + 1) > INT32_MAX - n) return false;
        n += i / static_cast<int32_t>(output.size() + 1);
        i %= static_cast<int32_t>(output.size() + 1);
        
        // Insert n at position i
        output.insert(output.begin() + i, static_cast<uint32_t>(n));
        i++;
    }
    
    return true;
}

// ----------------------------------------------------------------------------
// IDN Functions (Domain-level encoding)
// ----------------------------------------------------------------------------

// Check if domain needs IDN encoding
static bool needs_idn_encoding(const char* domain) {
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(domain); *p; p++) {
        if (*p >= 128) return true;
    }
    return false;
}

// Check if label is already Punycode encoded
static bool is_punycode_label(const char* label, size_t len) {
    return len > 4 && strncasecmp(label, PUNY_PREFIX, 4) == 0;
}

// ----------------------------------------------------------------------------
// Public C API
// ----------------------------------------------------------------------------

extern "C" {

char* nx_idn_to_ascii(const char* unicode_domain) {
    if (!unicode_domain) return nullptr;
    
    // If no non-ASCII chars, return copy
    if (!needs_idn_encoding(unicode_domain)) {
        return strdup(unicode_domain);
    }
    
    std::string result;
    const char* p = unicode_domain;
    
    while (*p) {
        // Find next label (separated by '.')
        const char* label_start = p;
        while (*p && *p != '.') p++;
        size_t label_len = p - label_start;
        
        if (label_len == 0) {
            if (*p == '.') {
                result += '.';
                p++;
            }
            continue;
        }
        
        // Check if this label needs encoding
        std::string label(label_start, label_len);
        bool has_non_ascii = false;
        for (char c : label) {
            if (static_cast<unsigned char>(c) >= 128) {
                has_non_ascii = true;
                break;
            }
        }
        
        if (has_non_ascii) {
            // Convert to Punycode (STRICT: reject invalid UTF-8)
            bool utf8_valid = false;
            std::vector<uint32_t> codepoints = utf8_to_codepoints(label.c_str(), &utf8_valid);
            
            // STRICT MODE: Do NOT guess on invalid UTF-8
            if (!utf8_valid || codepoints.empty()) {
                return nullptr;  // Reject, not guess
            }
            
            std::string encoded;
            
            if (!punycode_encode_label(codepoints, encoded)) {
                return nullptr;  // Encoding failed
            }
            
            result += PUNY_PREFIX;
            result += encoded;
        } else {
            // Keep as-is (but lowercase)
            for (char c : label) {
                result += static_cast<char>(tolower(c));
            }
        }
        
        if (*p == '.') {
            result += '.';
            p++;
        }
    }
    
    return strdup(result.c_str());
}

char* nx_idn_to_unicode(const char* ascii_domain) {
    if (!ascii_domain) return nullptr;
    
    std::string result;
    const char* p = ascii_domain;
    
    while (*p) {
        // Find next label
        const char* label_start = p;
        while (*p && *p != '.') p++;
        size_t label_len = p - label_start;
        
        if (label_len == 0) {
            if (*p == '.') {
                result += '.';
                p++;
            }
            continue;
        }
        
        std::string label(label_start, label_len);
        
        // Check if Punycode encoded
        if (is_punycode_label(label_start, label_len)) {
            std::vector<uint32_t> decoded;
            
            if (!punycode_decode_label(label.c_str() + 4, decoded)) {
                // Decoding failed, keep original
                result += label;
            } else {
                result += codepoints_to_utf8(decoded);
            }
        } else {
            result += label;
        }
        
        if (*p == '.') {
            result += '.';
            p++;
        }
    }
    
    return strdup(result.c_str());
}

bool nx_idn_is_valid(const char* domain) {
    if (!domain || !*domain) return false;
    
    // Check total length (max 253 characters for DNS)
    size_t total_len = strlen(domain);
    if (total_len > 253) return false;
    
    const char* p = domain;
    while (*p) {
        const char* label_start = p;
        while (*p && *p != '.') p++;
        size_t label_len = p - label_start;
        
        // Each label: 1-63 characters
        if (label_len == 0 || label_len > 63) return false;
        
        // Labels can't start/end with hyphen
        if (label_start[0] == '-' || label_start[label_len - 1] == '-') {
            return false;
        }
        
        if (*p == '.') p++;
    }
    
    return true;
}

} // extern "C"
