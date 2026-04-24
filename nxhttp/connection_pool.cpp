// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file connection_pool.cpp
 * @brief HTTP Connection Pooling for connection reuse
 * 
 * Original implementation inspired by browser networking concepts.
 * Reuses TCP connections to reduce latency for multiple requests to same host.
 */

#include "nxhttp.h"
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#define SOCKET_INVALID INVALID_SOCKET
#define close_socket closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
typedef int socket_t;
#define SOCKET_INVALID (-1)
#define close_socket close
#endif

// Forward declare SSL socket type
namespace Zepra { namespace Networking { class SSLContext; } }

// ----------------------------------------------------------------------------
// Connection Entry - represents a pooled connection
// ----------------------------------------------------------------------------

struct PooledConnection {
    socket_t socket;
    void* ssl_socket;           // SSLSocket*, nullptr for plain HTTP
    std::string host;
    int port;
    bool is_ssl;
    std::chrono::steady_clock::time_point last_used;
    bool in_use;
};

// ----------------------------------------------------------------------------
// Connection Pool Implementation
// ----------------------------------------------------------------------------

struct NxConnectionPool {
    std::vector<PooledConnection*> connections;
    std::mutex pool_mutex;
    int max_per_host;                // Max connections per (host, port, ssl) tuple
    int max_total;                   // Max total connections
    int idle_timeout_ms;             // Close idle connections after this time
    
    NxConnectionPool(int max_ph, int max_t, int idle_ms) 
        : max_per_host(max_ph), max_total(max_t), idle_timeout_ms(idle_ms) {}
    
    ~NxConnectionPool() {
        for (auto* conn : connections) {
            if (conn->socket != SOCKET_INVALID) {
                close_socket(conn->socket);
            }
            delete conn;
        }
    }
};

// Count active connections to a specific origin
static int count_connections_to_origin(NxConnectionPool* pool, 
                                        const char* host, int port, bool ssl) {
    int count = 0;
    for (const auto* conn : pool->connections) {
        if (conn->host == host && conn->port == port && conn->is_ssl == ssl) {
            count++;
        }
    }
    return count;
}

// Find an available connection to reuse
static PooledConnection* find_available_connection(NxConnectionPool* pool,
                                                    const char* host, int port, bool ssl) {
    auto now = std::chrono::steady_clock::now();
    
    for (auto* conn : pool->connections) {
        if (conn->in_use) continue;
        if (conn->host != host || conn->port != port || conn->is_ssl != ssl) continue;
        
        // Check if connection is still fresh
        auto age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - conn->last_used).count();
        
        if (age_ms > pool->idle_timeout_ms) {
            // Connection too old, close it
            if (conn->socket != SOCKET_INVALID) {
                close_socket(conn->socket);
                conn->socket = SOCKET_INVALID;
            }
            continue;
        }
        
        // Check if socket is still valid (simple check: select with 0 timeout)
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(conn->socket, &read_fds);
        struct timeval tv = {0, 0};
        
        int result = select(conn->socket + 1, &read_fds, nullptr, nullptr, &tv);
        if (result < 0 || (result > 0 && FD_ISSET(conn->socket, &read_fds))) {
            // Socket error or has data (possibly closed by server)
            close_socket(conn->socket);
            conn->socket = SOCKET_INVALID;
            continue;
        }
        
        // Connection is valid and reusable
        conn->in_use = true;
        conn->last_used = now;
        return conn;
    }
    
    return nullptr;
}

// Remove closed connections from pool
static void cleanup_closed_connections(NxConnectionPool* pool) {
    auto it = pool->connections.begin();
    while (it != pool->connections.end()) {
        if ((*it)->socket == SOCKET_INVALID && !(*it)->in_use) {
            delete *it;
            it = pool->connections.erase(it);
        } else {
            ++it;
        }
    }
}

// Remove idle connections that exceeded timeout
static void cleanup_idle_connections(NxConnectionPool* pool) {
    auto now = std::chrono::steady_clock::now();
    
    for (auto* conn : pool->connections) {
        if (conn->in_use) continue;
        
        auto age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - conn->last_used).count();
        
        if (age_ms > pool->idle_timeout_ms) {
            if (conn->socket != SOCKET_INVALID) {
                close_socket(conn->socket);
                conn->socket = SOCKET_INVALID;
            }
        }
    }
    
    cleanup_closed_connections(pool);
}

// ----------------------------------------------------------------------------
// Public C API
// ----------------------------------------------------------------------------

extern "C" {

NxConnectionPool* nx_conn_pool_create(int max_per_host, int max_total, int idle_timeout_ms) {
    if (max_per_host <= 0) max_per_host = 6;      // HTTP/1.1 standard
    if (max_total <= 0) max_total = 64;           // Reasonable default
    if (idle_timeout_ms <= 0) idle_timeout_ms = 60000;  // 1 minute default
    
    return new NxConnectionPool(max_per_host, max_total, idle_timeout_ms);
}

void nx_conn_pool_free(NxConnectionPool* pool) {
    delete pool;
}

socket_t nx_conn_pool_acquire(NxConnectionPool* pool, const char* host, int port, 
                               bool ssl, bool* reused) {
    if (!pool || !host) {
        if (reused) *reused = false;
        return SOCKET_INVALID;
    }
    
    std::lock_guard<std::mutex> lock(pool->pool_mutex);
    
    // Try to find existing connection
    PooledConnection* existing = find_available_connection(pool, host, port, ssl);
    if (existing) {
        if (reused) *reused = true;
        return existing->socket;
    }
    
    // No existing connection available
    if (reused) *reused = false;
    
    // Check if we can create a new connection
    int origin_count = count_connections_to_origin(pool, host, port, ssl);
    if (origin_count >= pool->max_per_host) {
        // Too many connections to this origin, wait or fail
        return SOCKET_INVALID;
    }
    
    if ((int)pool->connections.size() >= pool->max_total) {
        // At max capacity, cleanup idle and try again
        cleanup_idle_connections(pool);
        if ((int)pool->connections.size() >= pool->max_total) {
            return SOCKET_INVALID;
        }
    }
    
    // Return INVALID to signal caller should create new connection
    // Caller will add it to pool via nx_conn_pool_add
    return SOCKET_INVALID;
}

void nx_conn_pool_add(NxConnectionPool* pool, socket_t socket, const char* host, 
                      int port, bool ssl) {
    if (!pool || socket == SOCKET_INVALID || !host) return;
    
    std::lock_guard<std::mutex> lock(pool->pool_mutex);
    
    PooledConnection* conn = new PooledConnection();
    conn->socket = socket;
    conn->ssl_socket = nullptr;
    conn->host = host;
    conn->port = port;
    conn->is_ssl = ssl;
    conn->last_used = std::chrono::steady_clock::now();
    conn->in_use = true;
    
    pool->connections.push_back(conn);
}

void nx_conn_pool_release(NxConnectionPool* pool, socket_t socket, bool keep_alive) {
    if (!pool) return;
    
    std::lock_guard<std::mutex> lock(pool->pool_mutex);
    
    for (auto* conn : pool->connections) {
        if (conn->socket == socket) {
            if (keep_alive) {
                // Return to pool for reuse
                conn->in_use = false;
                conn->last_used = std::chrono::steady_clock::now();
            } else {
                // Close connection
                close_socket(conn->socket);
                conn->socket = SOCKET_INVALID;
                conn->in_use = false;
            }
            return;
        }
    }
    
    // Socket not in pool, just close it
    if (socket != SOCKET_INVALID) {
        close_socket(socket);
    }
}

void nx_conn_pool_cleanup(NxConnectionPool* pool) {
    if (!pool) return;
    
    std::lock_guard<std::mutex> lock(pool->pool_mutex);
    cleanup_idle_connections(pool);
}

int nx_conn_pool_active_count(NxConnectionPool* pool) {
    if (!pool) return 0;
    
    std::lock_guard<std::mutex> lock(pool->pool_mutex);
    int count = 0;
    for (const auto* conn : pool->connections) {
        if (conn->socket != SOCKET_INVALID) count++;
    }
    return count;
}

int nx_conn_pool_reuse_count(NxConnectionPool* pool) {
    if (!pool) return 0;
    
    std::lock_guard<std::mutex> lock(pool->pool_mutex);
    int count = 0;
    for (const auto* conn : pool->connections) {
        if (!conn->in_use && conn->socket != SOCKET_INVALID) count++;
    }
    return count;
}

} // extern "C"
