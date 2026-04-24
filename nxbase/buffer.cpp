// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file buffer.cpp
 * @brief NxBuffer implementation - Dynamic byte buffer
 */

#include "nxbase.h"
#include <cstdlib>
#include <cstring>
#include <algorithm>

extern "C" {

NxBuffer* nx_buffer_create(size_t initial_capacity) {
    NxBuffer* buf = static_cast<NxBuffer*>(malloc(sizeof(NxBuffer)));
    if (!buf) return nullptr;
    
    buf->capacity = initial_capacity > 0 ? initial_capacity : 64;
    buf->data = static_cast<uint8_t*>(malloc(buf->capacity));
    if (!buf->data) {
        free(buf);
        return nullptr;
    }
    buf->size = 0;
    return buf;
}

void nx_buffer_destroy(NxBuffer* buf) {
    if (buf) {
        free(buf->data);
        free(buf);
    }
}

NxResult nx_buffer_reserve(NxBuffer* buf, size_t capacity) {
    if (!buf) return NX_ERROR_INVALID;
    if (capacity <= buf->capacity) return NX_OK;
    
    size_t new_capacity = buf->capacity;
    while (new_capacity < capacity) {
        new_capacity *= 2;
    }
    
    uint8_t* new_data = static_cast<uint8_t*>(realloc(buf->data, new_capacity));
    if (!new_data) return NX_ERROR_NOMEM;
    
    buf->data = new_data;
    buf->capacity = new_capacity;
    return NX_OK;
}

NxResult nx_buffer_append(NxBuffer* buf, const void* data, size_t len) {
    if (!buf || (!data && len > 0)) return NX_ERROR_INVALID;
    if (len == 0) return NX_OK;
    
    NxResult res = nx_buffer_reserve(buf, buf->size + len);
    if (res != NX_OK) return res;
    
    memcpy(buf->data + buf->size, data, len);
    buf->size += len;
    return NX_OK;
}

NxResult nx_buffer_append_byte(NxBuffer* buf, uint8_t byte) {
    return nx_buffer_append(buf, &byte, 1);
}

NxResult nx_buffer_append_str(NxBuffer* buf, const char* str) {
    if (!str) return NX_ERROR_INVALID;
    return nx_buffer_append(buf, str, strlen(str));
}

void nx_buffer_clear(NxBuffer* buf) {
    if (buf) buf->size = 0;
}

char* nx_buffer_to_string(NxBuffer* buf) {
    if (!buf) return nullptr;
    
    char* str = static_cast<char*>(malloc(buf->size + 1));
    if (!str) return nullptr;
    
    memcpy(str, buf->data, buf->size);
    str[buf->size] = '\0';
    return str;
}

} // extern "C"
