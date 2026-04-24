// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file nxcrypto.h
 * @brief NxCrypto - Abstracted crypto/TLS interface for Zepra
 * 
 * Design: Abstracted interface that can use different backends:
 * - Native implementation (future)
 * - OpenSSL backend (current)
 * - mbedTLS backend (lightweight alternative)
 * 
 * Provides:
 * - TLS client (for HTTPS)
 * - Hashing (SHA-256, SHA-512)
 * - Random bytes
 * - Base64 encoding
 */

#ifndef NXCRYPTO_H
#define NXCRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Error Codes
// ============================================================================

typedef enum {
    NX_CRYPTO_OK = 0,
    NX_CRYPTO_ERROR = -1,
    NX_CRYPTO_ERROR_NOMEM = -2,
    NX_CRYPTO_ERROR_INVALID = -3,
    NX_CRYPTO_ERROR_HANDSHAKE = -4,
    NX_CRYPTO_ERROR_CERTIFICATE = -5,
    NX_CRYPTO_ERROR_IO = -6,
    NX_CRYPTO_ERROR_BACKEND = -7
} NxCryptoError;

const char* nx_crypto_error_string(NxCryptoError err);

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize crypto library. Call once at startup.
 */
NxCryptoError nx_crypto_init(void);

/**
 * Cleanup crypto library. Call at shutdown.
 */
void nx_crypto_cleanup(void);

// ============================================================================
// Hashing
// ============================================================================

// SHA-256 (32 bytes output)
#define NX_SHA256_DIGEST_SIZE 32

typedef struct NxSha256Context NxSha256Context;

NxSha256Context* nx_sha256_create(void);
void nx_sha256_free(NxSha256Context* ctx);
void nx_sha256_update(NxSha256Context* ctx, const void* data, size_t len);
void nx_sha256_final(NxSha256Context* ctx, uint8_t out[NX_SHA256_DIGEST_SIZE]);

// One-shot hash
void nx_sha256(const void* data, size_t len, uint8_t out[NX_SHA256_DIGEST_SIZE]);
char* nx_sha256_hex(const void* data, size_t len);  // Returns hex string, caller frees

// SHA-512 (64 bytes output)
#define NX_SHA512_DIGEST_SIZE 64

typedef struct NxSha512Context NxSha512Context;

NxSha512Context* nx_sha512_create(void);
void nx_sha512_free(NxSha512Context* ctx);
void nx_sha512_update(NxSha512Context* ctx, const void* data, size_t len);
void nx_sha512_final(NxSha512Context* ctx, uint8_t out[NX_SHA512_DIGEST_SIZE]);
void nx_sha512(const void* data, size_t len, uint8_t out[NX_SHA512_DIGEST_SIZE]);

// MD5 (for legacy protocols, 16 bytes output)
#define NX_MD5_DIGEST_SIZE 16
void nx_md5(const void* data, size_t len, uint8_t out[NX_MD5_DIGEST_SIZE]);

// ============================================================================
// HMAC
// ============================================================================

void nx_hmac_sha256(const void* key, size_t key_len,
                    const void* data, size_t data_len,
                    uint8_t out[NX_SHA256_DIGEST_SIZE]);

// ============================================================================
// Random
// ============================================================================

/**
 * Generate cryptographically secure random bytes.
 */
NxCryptoError nx_random_bytes(void* buf, size_t len);

/**
 * Generate random 32-bit integer.
 */
uint32_t nx_random_u32(void);

// ============================================================================
// Base64
// ============================================================================

/**
 * Base64 encode. Returns allocated string, caller frees.
 */
char* nx_base64_encode(const void* data, size_t len);

/**
 * Base64 decode. Returns allocated buffer, caller frees.
 */
uint8_t* nx_base64_decode(const char* str, size_t* out_len);

// ============================================================================
// TLS Client (abstracted)
// ============================================================================

typedef struct NxTlsContext NxTlsContext;
typedef struct NxTlsConnection NxTlsConnection;

typedef struct {
    bool verify_peer;           // Verify server certificate (default: true)
    bool verify_hostname;       // Verify hostname matches cert (default: true)
    const char* ca_file;        // Optional CA bundle file path
    const char* ca_path;        // Optional CA directory path
    const char* client_cert;    // Optional client certificate
    const char* client_key;     // Optional client private key
} NxTlsConfig;

/**
 * Create TLS context with configuration.
 */
NxTlsContext* nx_tls_context_create(const NxTlsConfig* config);
void nx_tls_context_free(NxTlsContext* ctx);

/**
 * Establish TLS connection on existing socket.
 * @param ctx TLS context
 * @param socket Connected TCP socket
 * @param hostname Server hostname for SNI
 */
NxTlsConnection* nx_tls_connect(NxTlsContext* ctx, int socket, const char* hostname);
void nx_tls_close(NxTlsConnection* conn);

/**
 * Read/write through TLS connection.
 */
int nx_tls_read(NxTlsConnection* conn, void* buf, size_t len);
int nx_tls_write(NxTlsConnection* conn, const void* data, size_t len);

/**
 * Get last error for connection.
 */
NxCryptoError nx_tls_get_error(NxTlsConnection* conn);

/**
 * Get peer certificate info (for display to user).
 */
typedef struct {
    char* subject;              // Certificate subject (CN)
    char* issuer;               // Issuer
    char* valid_from;           // Validity start
    char* valid_to;             // Validity end
    bool is_valid;              // Currently valid
} NxTlsCertInfo;

NxTlsCertInfo* nx_tls_get_peer_cert(NxTlsConnection* conn);
void nx_tls_cert_info_free(NxTlsCertInfo* info);

// ============================================================================
// AES-GCM Encryption
// ============================================================================

#define NX_AES_GCM_KEY_SIZE 32      // 256-bit key
#define NX_AES_GCM_IV_SIZE 12       // 96-bit IV
#define NX_AES_GCM_TAG_SIZE 16      // 128-bit auth tag

/**
 * AES-256-GCM encrypt.
 * @param key 32-byte key
 * @param iv 12-byte IV (should be random/unique per message)
 * @param plaintext Data to encrypt
 * @param plaintext_len Length of plaintext
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len Length of AAD
 * @param ciphertext Output buffer (same size as plaintext)
 * @param tag Output 16-byte authentication tag
 */
NxCryptoError nx_aes_gcm_encrypt(
    const uint8_t key[NX_AES_GCM_KEY_SIZE],
    const uint8_t iv[NX_AES_GCM_IV_SIZE],
    const void* plaintext, size_t plaintext_len,
    const void* aad, size_t aad_len,
    void* ciphertext,
    uint8_t tag[NX_AES_GCM_TAG_SIZE]
);

/**
 * AES-256-GCM decrypt.
 */
NxCryptoError nx_aes_gcm_decrypt(
    const uint8_t key[NX_AES_GCM_KEY_SIZE],
    const uint8_t iv[NX_AES_GCM_IV_SIZE],
    const void* ciphertext, size_t ciphertext_len,
    const void* aad, size_t aad_len,
    const uint8_t tag[NX_AES_GCM_TAG_SIZE],
    void* plaintext
);

#ifdef __cplusplus
}
#endif

// ============================================================================
// C++ Wrapper
// ============================================================================

#ifdef __cplusplus
#include <string>
#include <vector>
#include <stdexcept>

namespace nx {

class CryptoException : public std::runtime_error {
public:
    CryptoException(const std::string& msg) : std::runtime_error(msg) {}
};

// SHA-256 convenience
inline std::string sha256Hex(const std::string& data) {
    char* hex = nx_sha256_hex(data.data(), data.size());
    std::string result(hex);
    free(hex);
    return result;
}

inline std::vector<uint8_t> sha256(const std::string& data) {
    std::vector<uint8_t> hash(NX_SHA256_DIGEST_SIZE);
    nx_sha256(data.data(), data.size(), hash.data());
    return hash;
}

// Base64 convenience
inline std::string base64Encode(const std::vector<uint8_t>& data) {
    char* encoded = nx_base64_encode(data.data(), data.size());
    std::string result(encoded);
    free(encoded);
    return result;
}

inline std::vector<uint8_t> base64Decode(const std::string& str) {
    size_t len;
    uint8_t* decoded = nx_base64_decode(str.c_str(), &len);
    std::vector<uint8_t> result(decoded, decoded + len);
    free(decoded);
    return result;
}

// Random
inline std::vector<uint8_t> randomBytes(size_t count) {
    std::vector<uint8_t> buf(count);
    nx_random_bytes(buf.data(), count);
    return buf;
}

// TLS client wrapper
class TlsConnection {
public:
    TlsConnection(int socket, const std::string& hostname, const NxTlsConfig* config = nullptr) {
        ctx_ = nx_tls_context_create(config);
        if (!ctx_) throw CryptoException("Failed to create TLS context");
        
        conn_ = nx_tls_connect(ctx_, socket, hostname.c_str());
        if (!conn_) {
            nx_tls_context_free(ctx_);
            throw CryptoException("TLS handshake failed");
        }
    }
    
    ~TlsConnection() {
        if (conn_) nx_tls_close(conn_);
        if (ctx_) nx_tls_context_free(ctx_);
    }
    
    int read(void* buf, size_t len) { return nx_tls_read(conn_, buf, len); }
    int write(const void* data, size_t len) { return nx_tls_write(conn_, data, len); }
    
    TlsConnection(const TlsConnection&) = delete;
    TlsConnection& operator=(const TlsConnection&) = delete;
    
private:
    NxTlsContext* ctx_;
    NxTlsConnection* conn_;
};

} // namespace nx

#endif // __cplusplus

#endif // NXCRYPTO_H
