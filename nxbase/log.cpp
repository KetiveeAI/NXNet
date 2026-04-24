// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file log.cpp
 * @brief NxLog implementation - Logging utilities
 */

#include "nxbase.h"
#include <cstdio>
#include <cstdarg>
#include <cstring>

static NxLogLevel g_log_level = NX_LOG_INFO;
static NxLogCallback g_log_callback = nullptr;

static const char* level_names[] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

static const char* level_colors[] = {
    "\x1b[90m", "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[35m"
};

extern "C" {

const char* nx_error_string(NxResult result) {
    switch (result) {
        case NX_OK:                return "OK";
        case NX_ERROR:             return "Error";
        case NX_ERROR_NOMEM:       return "Out of memory";
        case NX_ERROR_INVALID:     return "Invalid argument";
        case NX_ERROR_IO:          return "I/O error";
        case NX_ERROR_TIMEOUT:     return "Timeout";
        case NX_ERROR_PARSE:       return "Parse error";
        case NX_ERROR_NOT_FOUND:   return "Not found";
        case NX_ERROR_OVERFLOW:    return "Overflow";
        case NX_ERROR_UNSUPPORTED: return "Unsupported";
        default:                   return "Unknown error";
    }
}

void nx_log_set_level(NxLogLevel level) {
    g_log_level = level;
}

void nx_log_set_callback(NxLogCallback callback) {
    g_log_callback = callback;
}

void nx_log(NxLogLevel level, const char* file, int line, const char* fmt, ...) {
    if (level < g_log_level) return;
    
    // Format message
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    
    if (g_log_callback) {
        g_log_callback(level, file, line, msg);
        return;
    }
    
    // Default: print to stderr
    // Extract filename from path
    const char* filename = file;
    const char* slash = strrchr(file, '/');
    if (slash) filename = slash + 1;
    
    fprintf(stderr, "%s%-5s\x1b[0m \x1b[90m%s:%d:\x1b[0m %s\n",
            level_colors[level], level_names[level], filename, line, msg);
}

} // extern "C"
