//
// Created by axzsw on 2025-02-02.
//

#ifndef BLAKE3_H
#define BLAKE3_H

#include <stddef.h>
#include <stdint.h>

// BLAKE3 상수
#define BLAKE3_OUT_LEN 32
#define BLAKE3_KEY_LEN 32
#define BLAKE3_CONTEXT_LEN 64
#define BLAKE3_BLOCK_LEN 64
#define BLAKE3_CHUNK_LEN 1024
#define BLAKE3_MAX_DEPTH 54

// BLAKE3 상태 구조체
typedef struct {
    uint32_t cv[8];                   // 체이닝 값
    uint64_t chunk_counter;           // 청크 카운터
    uint8_t buf[BLAKE3_BLOCK_LEN];   // 입력 버퍼
    uint8_t buf_len;                 // 버퍼에 있는 바이트 수
    uint8_t blocks_compressed;       // 압축된 블록 수
    uint8_t flags;                   // 플래그
} blake3_chunk_state;

typedef struct {
    uint32_t key[8];                 // 키 (옵션)
    blake3_chunk_state chunk;        // 현재 청크 상태
    uint8_t cv_stack_len;           // 스택 길이
    uint32_t cv_stack[BLAKE3_MAX_DEPTH * 8]; // CV 스택
} blake3_hasher;

// 주요 함수 선언
void blake3_hasher_init(blake3_hasher *self);
void blake3_hasher_init_keyed(blake3_hasher *self, const uint8_t key[BLAKE3_KEY_LEN]);
void blake3_hasher_init_derive_key(blake3_hasher *self, const char *context);
void blake3_hasher_update(blake3_hasher *self, const void *input, size_t input_len);
void blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out, size_t out_len);

// 편의 함수
void blake3(const void *input, size_t input_len, uint8_t *out, size_t out_len);

#endif //BLAKE3_H