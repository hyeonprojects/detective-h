//
// Created by hyeonproject on 2025-02-02.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/hash.h"

// 플랫폼별 EXPORT 매크로 정의
#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

EXPORT char* hash(const char* input) {
    // BLAKE2b-512는 64바이트 출력
    uint8_t hash[64] = {0};

    // 16진수 문자열을 저장할 버퍼 (64바이트 * 2 + 널 종료 문자)
    char* result = (char*)malloc(129);
    if (result == NULL) {
        return NULL;
    }

    blake2b_state S;

    // 초기화
    if (blake2b_init(&S, sizeof(hash)) != 0) {
        free(result);
        return NULL;
    }

    // 데이터 업데이트
    if (blake2b_update(&S, input, strlen(input)) != 0) {
        free(result);
        return NULL;
    }

    // 해시 완료
    if (blake2b_final(&S, hash, sizeof(hash)) != 0) {
        free(result);
        return NULL;
    }

    // 해시값을 16진수 문자열로 변환
    for(size_t i = 0; i < sizeof(hash); i++) {
        snprintf(result + (i * 2), 3, "%02x", hash[i]);
    }
    result[128] = '\0';  // 널 종료 문자 추가

    return result;
}
