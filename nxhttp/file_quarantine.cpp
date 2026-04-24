// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file file_quarantine.cpp
 * @brief File quarantine and origin tracking using extended attributes
 * 
 * Security feature: Track where downloaded files came from.
 * Uses Linux xattr or macOS quarantine attributes.
 */

#include "nxhttp.h"
#include <cstdlib>
#include <cstring>
#include <ctime>

// Platform-specific xattr support
#if defined(__linux__)
#include <sys/xattr.h>
#define HAS_XATTR 1
#elif defined(__APPLE__)
#include <sys/xattr.h>
#define HAS_XATTR 1
#else
#define HAS_XATTR 0
#endif

extern "C" {

// Attribute keys for file security metadata
#define NX_XATTR_ORIGIN      "user.zepra.origin"
#define NX_XATTR_SOURCE_URL  "user.zepra.source_url"
#define NX_XATTR_DOMAIN      "user.zepra.domain"
#define NX_XATTR_TIME        "user.zepra.download_time"
#define NX_XATTR_HASH        "user.zepra.sha256"
#define NX_XATTR_VERIFIED    "user.zepra.verified"

// ============================================================================
// File Security Info
// ============================================================================

NxFileSecurityInfo* nx_file_get_security_info(const char* path) {
    if (!path) return nullptr;
    
    NxFileSecurityInfo* info = static_cast<NxFileSecurityInfo*>(
        calloc(1, sizeof(NxFileSecurityInfo)));
    if (!info) return nullptr;
    
    // Default values
    info->origin = NX_FILE_ORIGIN_LOCAL;  // Assume local if no metadata
    info->is_quarantined = false;
    info->user_verified = false;
    info->download_time = 0;
    
#if HAS_XATTR
    char buffer[4096] = {0};
    ssize_t len;
    
    // Read origin
    len = getxattr(path, NX_XATTR_ORIGIN, buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';
        info->origin = static_cast<NxFileOrigin>(atoi(buffer));
        info->is_quarantined = (info->origin != NX_FILE_ORIGIN_LOCAL);
    }
    
    // Read source URL
    len = getxattr(path, NX_XATTR_SOURCE_URL, buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';
        info->source_url = strdup(buffer);
    }
    
    // Read domain
    len = getxattr(path, NX_XATTR_DOMAIN, buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';
        info->source_domain = strdup(buffer);
    }
    
    // Read download time
    len = getxattr(path, NX_XATTR_TIME, buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';
        info->download_time = static_cast<int64_t>(atoll(buffer));
    }
    
    // Read hash
    len = getxattr(path, NX_XATTR_HASH, buffer, 64);
    if (len > 0 && len <= 64) {
        memcpy(info->sha256, buffer, len);
        info->sha256[len] = '\0';
    }
    
    // Read verified flag
    len = getxattr(path, NX_XATTR_VERIFIED, buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';
        info->user_verified = (buffer[0] == '1');
        // If verified, not quarantined
        if (info->user_verified) {
            info->is_quarantined = false;
        }
    }
#endif
    
    return info;
}

void nx_file_security_info_free(NxFileSecurityInfo* info) {
    if (info) {
        free(info->source_url);
        free(info->source_domain);
        free(info);
    }
}

bool nx_file_set_quarantine(const char* path, const NxFileSecurityInfo* info) {
    if (!path || !info) return false;
    
#if HAS_XATTR
    char buffer[32];
    int ret;
    
    // Set origin
    snprintf(buffer, sizeof(buffer), "%d", static_cast<int>(info->origin));
    ret = setxattr(path, NX_XATTR_ORIGIN, buffer, strlen(buffer), 0);
    if (ret < 0) return false;
    
    // Set source URL
    if (info->source_url) {
        ret = setxattr(path, NX_XATTR_SOURCE_URL, info->source_url, 
                      strlen(info->source_url), 0);
        if (ret < 0) return false;
    }
    
    // Set domain
    if (info->source_domain) {
        ret = setxattr(path, NX_XATTR_DOMAIN, info->source_domain,
                      strlen(info->source_domain), 0);
        if (ret < 0) return false;
    }
    
    // Set download time
    snprintf(buffer, sizeof(buffer), "%lld", static_cast<long long>(info->download_time));
    ret = setxattr(path, NX_XATTR_TIME, buffer, strlen(buffer), 0);
    if (ret < 0) return false;
    
    // Set hash
    if (info->sha256[0]) {
        ret = setxattr(path, NX_XATTR_HASH, info->sha256, strlen(info->sha256), 0);
        if (ret < 0) return false;
    }
    
    // Set verified flag
    buffer[0] = info->user_verified ? '1' : '0';
    buffer[1] = '\0';
    ret = setxattr(path, NX_XATTR_VERIFIED, buffer, 1, 0);
    if (ret < 0) return false;
    
    return true;
#else
    (void)path;
    (void)info;
    return false;  // No xattr support
#endif
}

bool nx_file_remove_quarantine(const char* path) {
    if (!path) return false;
    
#if HAS_XATTR
    // Set verified flag to remove quarantine
    int ret = setxattr(path, NX_XATTR_VERIFIED, "1", 1, 0);
    return ret >= 0;
#else
    (void)path;
    return false;
#endif
}

bool nx_file_is_quarantined(const char* path) {
    if (!path) return false;
    
#if HAS_XATTR
    char buffer[16] = {0};
    
    // Check if has origin attribute
    ssize_t len = getxattr(path, NX_XATTR_ORIGIN, buffer, sizeof(buffer) - 1);
    if (len <= 0) {
        return false;  // No origin = local file, not quarantined
    }
    
    buffer[len] = '\0';
    NxFileOrigin origin = static_cast<NxFileOrigin>(atoi(buffer));
    
    // Local files are not quarantined
    if (origin == NX_FILE_ORIGIN_LOCAL) {
        return false;
    }
    
    // Check verified flag
    len = getxattr(path, NX_XATTR_VERIFIED, buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';
        if (buffer[0] == '1') {
            return false;  // User verified, not quarantined
        }
    }
    
    // Downloaded file, not verified = quarantined
    return true;
#else
    (void)path;
    return false;
#endif
}

} // extern "C"
