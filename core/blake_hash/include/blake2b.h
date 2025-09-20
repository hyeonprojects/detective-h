//
// Created by axzsw on 2025-02-02.
//

#ifndef BLAKE2B_H
#define BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

// BLAKE2b 상태 구조체
typedef struct {
    uint64_t h[8];                   // 체이닝 값
    uint64_t t[2];                   // 메시지 바이트 카운터
    uint64_t f[2];                   // 최종 블록 플래그
    uint8_t  buf[128];              // 입력 버퍼
    size_t   buflen;                // 버퍼에 있는 바이트 수
    size_t   outlen;                // 원하는 출력 길이
    uint8_t  last_node;            // 최종 노드 플래그
} blake2b_state;

// 주요 함수 선언
int blake2b_init(blake2b_state *S, size_t outlen);
int blake2b_update(blake2b_state *S, const void *in, size_t inlen);
int blake2b_final(blake2b_state *S, void *out, size_t outlen);

#endif //BLAKE2B_H
