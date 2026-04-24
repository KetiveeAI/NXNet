// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file string.cpp
 * @brief NxString implementation - UTF-8 aware string utilities
 */

#include "nxbase.h"
#include <cstdlib>
#include <cstring>

extern "C" {

NxString* nx_string_create(const char* str) {
    return nx_string_create_len(str, str ? strlen(str) : 0);
}

NxString* nx_string_create_len(const char* str, size_t len) {
    NxString* s = static_cast<NxString*>(malloc(sizeof(NxString)));
    if (!s) return nullptr;
    
    s->capacity = len > 0 ? len + 1 : 16;
    s->data = static_cast<char*>(malloc(s->capacity));
    if (!s->data) {
        free(s);
        return nullptr;
    }
    
    if (str && len > 0) {
        memcpy(s->data, str, len);
    }
    s->data[len] = '\0';
    s->len = len;
    return s;
}

void nx_string_destroy(NxString* s) {
    if (s) {
        free(s->data);
        free(s);
    }
}

NxResult nx_string_append(NxString* s, const char* str) {
    if (!str) return NX_ERROR_INVALID;
    return nx_string_append_len(s, str, strlen(str));
}

NxResult nx_string_append_len(NxString* s, const char* str, size_t len) {
    if (!s || (!str && len > 0)) return NX_ERROR_INVALID;
    if (len == 0) return NX_OK;
    
    size_t new_len = s->len + len;
    if (new_len + 1 > s->capacity) {
        size_t new_capacity = s->capacity;
        while (new_capacity < new_len + 1) {
            new_capacity *= 2;
        }
        char* new_data = static_cast<char*>(realloc(s->data, new_capacity));
        if (!new_data) return NX_ERROR_NOMEM;
        s->data = new_data;
        s->capacity = new_capacity;
    }
    
    memcpy(s->data + s->len, str, len);
    s->len = new_len;
    s->data[s->len] = '\0';
    return NX_OK;
}

void nx_string_clear(NxString* s) {
    if (s) {
        s->len = 0;
        s->data[0] = '\0';
    }
}

const char* nx_string_cstr(const NxString* s) {
    return s ? s->data : "";
}

size_t nx_string_len(const NxString* s) {
    return s ? s->len : 0;
}

// UTF-8 utilities
size_t nx_utf8_len(const char* str) {
    if (!str) return 0;
    
    size_t count = 0;
    while (*str) {
        // Count only first bytes of UTF-8 sequences (not continuation bytes)
        if ((*str & 0xC0) != 0x80) {
            count++;
        }
        str++;
    }
    return count;
}

size_t nx_utf8_char_len(uint8_t first_byte) {
    if ((first_byte & 0x80) == 0x00) return 1;      // 0xxxxxxx - ASCII
    if ((first_byte & 0xE0) == 0xC0) return 2;      // 110xxxxx
    if ((first_byte & 0xF0) == 0xE0) return 3;      // 1110xxxx
    if ((first_byte & 0xF8) == 0xF0) return 4;      // 11110xxx
    return 1;  // Invalid, treat as 1 byte
}

bool nx_utf8_valid(const char* str, size_t len) {
    if (!str) return len == 0;
    
    const uint8_t* p = reinterpret_cast<const uint8_t*>(str);
    const uint8_t* end = p + len;
    
    while (p < end) {
        size_t char_len = nx_utf8_char_len(*p);
        if (p + char_len > end) return false;  // Truncated
        
        // Check continuation bytes
        for (size_t i = 1; i < char_len; i++) {
            if ((p[i] & 0xC0) != 0x80) return false;
        }
        
        p += char_len;
    }
    return true;
}

} // extern "C"
