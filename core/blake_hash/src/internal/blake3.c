// blake3.c
#include "../../include/blake3.h"
#include <string.h>

// BLAKE3 초기화 벡터
static const uint32_t blake3_IV[8] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL,
};

// 메시지 스케줄링 순열
static const uint8_t blake3_msg_schedule[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
};

// 플래그 상수
enum blake3_flags {
    CHUNK_START = 1 << 0,
    CHUNK_END = 1 << 1,
    PARENT = 1 << 2,
    ROOT = 1 << 3,
    KEYED_HASH = 1 << 4,
    DERIVE_KEY_CONTEXT = 1 << 5,
    DERIVE_KEY_MATERIAL = 1 << 6,
};

static uint32_t rotr32(uint32_t w, unsigned c) {
    return (w >> c) | (w << (32 - c));
}

static void g(uint32_t *state, size_t a, size_t b, size_t c, size_t d, uint32_t x, uint32_t y) {
    state[a] = state[a] + state[b] + x;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + y;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
}

static void round_fn(uint32_t state[16], const uint32_t *msg, size_t round) {
    // 열 믹싱
    g(state, 0, 4, 8, 12, msg[blake3_msg_schedule[round][0]], msg[blake3_msg_schedule[round][1]]);
    g(state, 1, 5, 9, 13, msg[blake3_msg_schedule[round][2]], msg[blake3_msg_schedule[round][3]]);
    g(state, 2, 6, 10, 14, msg[blake3_msg_schedule[round][4]], msg[blake3_msg_schedule[round][5]]);
    g(state, 3, 7, 11, 15, msg[blake3_msg_schedule[round][6]], msg[blake3_msg_schedule[round][7]]);
    
    // 대각선 믹싱
    g(state, 0, 5, 10, 15, msg[blake3_msg_schedule[round][8]], msg[blake3_msg_schedule[round][9]]);
    g(state, 1, 6, 11, 12, msg[blake3_msg_schedule[round][10]], msg[blake3_msg_schedule[round][11]]);
    g(state, 2, 7, 8, 13, msg[blake3_msg_schedule[round][12]], msg[blake3_msg_schedule[round][13]]);
    g(state, 3, 4, 9, 14, msg[blake3_msg_schedule[round][14]], msg[blake3_msg_schedule[round][15]]);
}

static void blake3_compress_in_place(uint32_t cv[8],
                                   const uint8_t block[BLAKE3_BLOCK_LEN],
                                   uint8_t block_len,
                                   uint64_t counter,
                                   uint8_t flags) {
    uint32_t state[16];
    
    // 초기화
    memcpy(state, cv, 8 * sizeof(uint32_t));
    memcpy(state + 8, blake3_IV, 8 * sizeof(uint32_t));
    
    state[12] = (uint32_t)counter;
    state[13] = (uint32_t)(counter >> 32);
    state[14] = (uint32_t)block_len;
    state[15] = (uint32_t)flags;
    
    // 메시지를 32비트 워드로 변환
    uint32_t block_words[16];
    for (size_t i = 0; i < 16; i++) {
        block_words[i] = ((uint32_t)block[4 * i]) |
                        ((uint32_t)block[4 * i + 1] << 8) |
                        ((uint32_t)block[4 * i + 2] << 16) |
                        ((uint32_t)block[4 * i + 3] << 24);
    }
    
    // 7라운드 압축
    for (size_t round = 0; round < 7; round++) {
        round_fn(state, block_words, round);
    }
    
    // 결과 업데이트
    for (size_t i = 0; i < 8; i++) {
        cv[i] = state[i] ^ state[i + 8];
    }
}

static void blake3_compress_xof(const uint32_t cv[8],
                               const uint8_t block[BLAKE3_BLOCK_LEN],
                               uint8_t block_len,
                               uint64_t counter,
                               uint8_t flags,
                               uint8_t out[64]) {
    uint32_t state[16];
    
    // 초기화
    memcpy(state, cv, 8 * sizeof(uint32_t));
    memcpy(state + 8, blake3_IV, 8 * sizeof(uint32_t));
    
    state[12] = (uint32_t)counter;
    state[13] = (uint32_t)(counter >> 32);
    state[14] = (uint32_t)block_len;
    state[15] = (uint32_t)flags;
    
    // 메시지를 32비트 워드로 변환
    uint32_t block_words[16];
    for (size_t i = 0; i < 16; i++) {
        block_words[i] = ((uint32_t)block[4 * i]) |
                        ((uint32_t)block[4 * i + 1] << 8) |
                        ((uint32_t)block[4 * i + 2] << 16) |
                        ((uint32_t)block[4 * i + 3] << 24);
    }
    
    // 7라운드 압축
    for (size_t round = 0; round < 7; round++) {
        round_fn(state, block_words, round);
    }
    
    // 출력 생성
    for (size_t i = 0; i < 16; i++) {
        uint32_t word = state[i] ^ state[i % 8];
        out[4 * i] = (uint8_t)word;
        out[4 * i + 1] = (uint8_t)(word >> 8);
        out[4 * i + 2] = (uint8_t)(word >> 16);
        out[4 * i + 3] = (uint8_t)(word >> 24);
    }
}

static void chunk_state_init(blake3_chunk_state *self, const uint32_t key[8], uint8_t flags) {
    memcpy(self->cv, key, 8 * sizeof(uint32_t));
    self->chunk_counter = 0;
    memset(self->buf, 0, BLAKE3_BLOCK_LEN);
    self->buf_len = 0;
    self->blocks_compressed = 0;
    self->flags = flags;
}

static void chunk_state_update(blake3_chunk_state *self, const uint8_t *input, size_t input_len) {
    while (input_len > 0) {
        // 버퍼 채우기
        if (self->buf_len == BLAKE3_BLOCK_LEN) {
            // 블록 압축
            uint8_t block_flags = self->flags | (self->blocks_compressed == 0 ? CHUNK_START : 0);
            blake3_compress_in_place(self->cv, self->buf, BLAKE3_BLOCK_LEN, self->chunk_counter, block_flags);
            self->blocks_compressed += 1;
            self->buf_len = 0;
        }
        
        size_t want = BLAKE3_BLOCK_LEN - self->buf_len;
        size_t take = input_len < want ? input_len : want;
        memcpy(&self->buf[self->buf_len], input, take);
        self->buf_len += take;
        input += take;
        input_len -= take;
    }
}

static void chunk_state_output(const blake3_chunk_state *self, uint8_t out[64]) {
    uint8_t block_flags = self->flags | 
                         (self->blocks_compressed == 0 ? CHUNK_START : 0) | 
                         CHUNK_END;
    blake3_compress_xof(self->cv, self->buf, self->buf_len, self->chunk_counter, block_flags, out);
}

static void parent_output(const uint8_t block[64], const uint32_t key[8], uint8_t flags, uint8_t out[64]) {
    blake3_compress_xof(key, block, BLAKE3_BLOCK_LEN, 0, flags | PARENT, out);
}

static void parent_cv(const uint8_t block[64], const uint32_t key[8], uint8_t flags, uint32_t out[8]) {
    uint8_t cv_bytes[32];
    parent_output(block, key, flags, cv_bytes);
    for (size_t i = 0; i < 8; i++) {
        out[i] = ((uint32_t)cv_bytes[4 * i]) |
                ((uint32_t)cv_bytes[4 * i + 1] << 8) |
                ((uint32_t)cv_bytes[4 * i + 2] << 16) |
                ((uint32_t)cv_bytes[4 * i + 3] << 24);
    }
}

static void add_chunk_cv(blake3_hasher *self, uint32_t new_cv[8], uint64_t total_chunks) {
    // 스택에 CV 추가
    while (total_chunks & 1) {
        uint8_t parent_block[64];
        memcpy(parent_block, &self->cv_stack[(self->cv_stack_len - 1) * 8], 32);
        memcpy(parent_block + 32, new_cv, 32);
        parent_cv(parent_block, self->key, self->chunk.flags, new_cv);
        self->cv_stack_len -= 1;
        total_chunks >>= 1;
    }
    memcpy(&self->cv_stack[self->cv_stack_len * 8], new_cv, 32);
    self->cv_stack_len += 1;
}

void blake3_hasher_init(blake3_hasher *self) {
    memcpy(self->key, blake3_IV, 8 * sizeof(uint32_t));
    chunk_state_init(&self->chunk, self->key, 0);
    self->cv_stack_len = 0;
}

void blake3_hasher_init_keyed(blake3_hasher *self, const uint8_t key[BLAKE3_KEY_LEN]) {
    for (size_t i = 0; i < 8; i++) {
        self->key[i] = ((uint32_t)key[4 * i]) |
                      ((uint32_t)key[4 * i + 1] << 8) |
                      ((uint32_t)key[4 * i + 2] << 16) |
                      ((uint32_t)key[4 * i + 3] << 24);
    }
    chunk_state_init(&self->chunk, self->key, KEYED_HASH);
    self->cv_stack_len = 0;
}

void blake3_hasher_init_derive_key(blake3_hasher *self, const char *context) {
    blake3_hasher context_hasher;
    blake3_hasher_init(&context_hasher);
    context_hasher.chunk.flags |= DERIVE_KEY_CONTEXT;
    blake3_hasher_update(&context_hasher, context, strlen(context));
    uint8_t context_key[BLAKE3_KEY_LEN];
    blake3_hasher_finalize(&context_hasher, context_key, BLAKE3_KEY_LEN);
    blake3_hasher_init_keyed(self, context_key);
    self->chunk.flags |= DERIVE_KEY_MATERIAL;
}

void blake3_hasher_update(blake3_hasher *self, const void *input, size_t input_len) {
    const uint8_t *input_bytes = (const uint8_t *)input;
    
    while (input_len > 0) {
        // 현재 청크가 꽉 찼는지 확인
        if (self->chunk.buf_len == BLAKE3_BLOCK_LEN && 
            self->chunk.blocks_compressed == BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN - 1) {
            // 청크 완료
            uint8_t chunk_cv[64];
            chunk_state_output(&self->chunk, chunk_cv);
            uint32_t chunk_cv_words[8];
            for (size_t i = 0; i < 8; i++) {
                chunk_cv_words[i] = ((uint32_t)chunk_cv[4 * i]) |
                                   ((uint32_t)chunk_cv[4 * i + 1] << 8) |
                                   ((uint32_t)chunk_cv[4 * i + 2] << 16) |
                                   ((uint32_t)chunk_cv[4 * i + 3] << 24);
            }
            add_chunk_cv(self, chunk_cv_words, self->chunk.chunk_counter + 1);
            chunk_state_init(&self->chunk, self->key, self->chunk.flags);
            self->chunk.chunk_counter += 1;
        }
        
        size_t want = BLAKE3_CHUNK_LEN - (self->chunk.blocks_compressed * BLAKE3_BLOCK_LEN + self->chunk.buf_len);
        size_t take = input_len < want ? input_len : want;
        chunk_state_update(&self->chunk, input_bytes, take);
        input_bytes += take;
        input_len -= take;
    }
}

void blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out, size_t out_len) {
    // 현재 청크의 CV 계산
    uint8_t chunk_cv[64];
    chunk_state_output(&self->chunk, chunk_cv);
    uint32_t chunk_cv_words[8];
    for (size_t i = 0; i < 8; i++) {
        chunk_cv_words[i] = ((uint32_t)chunk_cv[4 * i]) |
                           ((uint32_t)chunk_cv[4 * i + 1] << 8) |
                           ((uint32_t)chunk_cv[4 * i + 2] << 16) |
                           ((uint32_t)chunk_cv[4 * i + 3] << 24);
    }
    
    // 루트 노드 계산
    uint32_t parent_nodes[8];
    memcpy(parent_nodes, chunk_cv_words, 32);
    
    for (size_t i = self->cv_stack_len; i > 0; i--) {
        uint8_t parent_block[64];
        memcpy(parent_block, &self->cv_stack[(i - 1) * 8], 32);
        memcpy(parent_block + 32, parent_nodes, 32);
        parent_cv(parent_block, self->key, self->chunk.flags, parent_nodes);
    }
    
    // 최종 출력 생성
    uint8_t wide_buf[64];
    blake3_compress_xof(parent_nodes, (uint8_t*)parent_nodes, 32, 0, self->chunk.flags | ROOT, wide_buf);
    memcpy(out, wide_buf, out_len < 64 ? out_len : 64);
    
    // 64바이트보다 더 많이 요청된 경우
    if (out_len > 64) {
        for (size_t output_block_counter = 1; out_len > 64; output_block_counter++) {
            blake3_compress_xof(parent_nodes, (uint8_t*)parent_nodes, 32, output_block_counter, self->chunk.flags | ROOT, wide_buf);
            size_t this_block_len = out_len > 64 ? 64 : out_len;
            memcpy(out + 64 * output_block_counter, wide_buf, this_block_len);
            out_len -= this_block_len;
        }
    }
}

void blake3(const void *input, size_t input_len, uint8_t *out, size_t out_len) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, input_len);
    blake3_hasher_finalize(&hasher, out, out_len);
}