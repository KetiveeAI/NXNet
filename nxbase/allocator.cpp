// Copyright (c) 2025 KetiveeAI. All rights reserved.
// Licensed under KPL-2.0. See LICENSE file for details.
/**
 * @file allocator.cpp
 * @brief NxPool implementation - Memory pool allocator
 */

#include "nxbase.h"
#include <cstdlib>
#include <cstring>
#include <vector>

struct NxPoolBlock {
    uint8_t* memory;
    size_t used;
    size_t capacity;
};

struct NxPool {
    std::vector<NxPoolBlock> blocks;
    size_t block_size;
};

extern "C" {

NxPool* nx_pool_create(size_t block_size) {
    NxPool* pool = new (std::nothrow) NxPool;
    if (!pool) return nullptr;
    
    pool->block_size = block_size > 0 ? block_size : 4096;
    return pool;
}

void nx_pool_destroy(NxPool* pool) {
    if (!pool) return;
    
    for (auto& block : pool->blocks) {
        free(block.memory);
    }
    delete pool;
}

static NxPoolBlock* nx_pool_add_block(NxPool* pool, size_t min_size) {
    size_t capacity = pool->block_size;
    while (capacity < min_size) {
        capacity *= 2;
    }
    
    NxPoolBlock block;
    block.memory = static_cast<uint8_t*>(malloc(capacity));
    if (!block.memory) return nullptr;
    
    block.used = 0;
    block.capacity = capacity;
    pool->blocks.push_back(block);
    return &pool->blocks.back();
}

void* nx_pool_alloc(NxPool* pool, size_t size) {
    if (!pool || size == 0) return nullptr;
    
    // Align to 8 bytes
    size = (size + 7) & ~7;
    
    // Find block with enough space
    for (auto& block : pool->blocks) {
        if (block.capacity - block.used >= size) {
            void* ptr = block.memory + block.used;
            block.used += size;
            return ptr;
        }
    }
    
    // Allocate new block
    NxPoolBlock* block = nx_pool_add_block(pool, size);
    if (!block) return nullptr;
    
    void* ptr = block->memory;
    block->used = size;
    return ptr;
}

void nx_pool_reset(NxPool* pool) {
    if (!pool) return;
    
    for (auto& block : pool->blocks) {
        block.used = 0;
    }
}

} // extern "C"
