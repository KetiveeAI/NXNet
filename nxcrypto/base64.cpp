// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file base64.cpp
 * @brief Base64 encoding/decoding
 */

#include "nxcrypto.h"
#include <cstdlib>
#include <cstring>

static const char b64_table[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const uint8_t b64_decode_table[256] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

extern "C" {

char* nx_base64_encode(const void* data, size_t len) {
    const uint8_t* input = static_cast<const uint8_t*>(data);
    size_t out_len = ((len + 2) / 3) * 4;
    char* output = static_cast<char*>(malloc(out_len + 1));
    if (!output) return nullptr;
    
    size_t i = 0, j = 0;
    while (i < len) {
        uint32_t a = i < len ? input[i++] : 0;
        uint32_t b = i < len ? input[i++] : 0;
        uint32_t c = i < len ? input[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        
        output[j++] = b64_table[(triple >> 18) & 0x3f];
        output[j++] = b64_table[(triple >> 12) & 0x3f];
        output[j++] = b64_table[(triple >> 6) & 0x3f];
        output[j++] = b64_table[triple & 0x3f];
    }
    
    // Add padding
    size_t padding = (3 - len % 3) % 3;
    for (size_t p = 0; p < padding; p++) {
        output[out_len - 1 - p] = '=';
    }
    
    output[out_len] = '\0';
    return output;
}

uint8_t* nx_base64_decode(const char* str, size_t* out_len) {
    if (!str || !out_len) return nullptr;
    
    size_t len = strlen(str);
    if (len % 4 != 0) return nullptr;
    
    size_t padding = 0;
    if (len > 0 && str[len-1] == '=') padding++;
    if (len > 1 && str[len-2] == '=') padding++;
    
    *out_len = (len / 4) * 3 - padding;
    uint8_t* output = static_cast<uint8_t*>(malloc(*out_len));
    if (!output) return nullptr;
    
    size_t i = 0, j = 0;
    while (i < len) {
        uint8_t a = str[i] == '=' ? 0 : b64_decode_table[(uint8_t)str[i]]; i++;
        uint8_t b = str[i] == '=' ? 0 : b64_decode_table[(uint8_t)str[i]]; i++;
        uint8_t c = str[i] == '=' ? 0 : b64_decode_table[(uint8_t)str[i]]; i++;
        uint8_t d = str[i] == '=' ? 0 : b64_decode_table[(uint8_t)str[i]]; i++;
        
        uint32_t triple = (a << 18) | (b << 12) | (c << 6) | d;
        
        if (j < *out_len) output[j++] = (triple >> 16) & 0xff;
        if (j < *out_len) output[j++] = (triple >> 8) & 0xff;
        if (j < *out_len) output[j++] = triple & 0xff;
    }
    
    return output;
}

} // extern "C"
