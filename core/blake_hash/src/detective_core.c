* @file detective_core.c
* @brief Detective-H Core Module - BLAKE3 해시 및 배치 비교 구현
/**
 *
 * 이 파일은 detective_core.h에 선언된 모든 함수를 구현합니다.
 * 내부적으로 blake3.h의 BLAKE3 알고리즘을 사용합니다.
 *
 * ──────────────────────────────────────────────
 * 빌드 방법 (Clang):
 *   cmake .. -G "Ninja" -DCMAKE_C_COMPILER=clang
 *   cmake --build .
 *
 * 결과물: detective_core.dll (Windows) / libdetective_core.so (Linux)
 * ──────────────────────────────────────────────
 *
 * @author Detective-H Team
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/detective_core.h"
#include "../include/blake3.h"

/* ═══════════════════════════════════════════════
 * 내부 유틸리티 함수
 * ═══════════════════════════════════════════════ */

/**
 * @brief 바이트 배열을 16진수 문자열로 변환
 *
 * @param bytes   변환할 바이트 배열
 * @param len     바이트 배열 길이
 * @param hex_out 결과 문자열 버퍼 (최소 len*2+1 크기)
 *
 * 내부 사용 예시:
 *   uint8_t hash[32];
 *   char hex[65];
 *   bytes_to_hex(hash, 32, hex);  // hex = "a8f5f167..."
 */
static void bytes_to_hex(const uint8_t* bytes, size_t len, char* hex_out) {
    for (size_t i = 0; i < len; i++) {
        snprintf(hex_out + (i * 2), 3, "%02x", bytes[i]);
    }
    hex_out[len * 2] = '\0';
}

/**
 * @brief popcount - 바이트 내 1인 비트 개수 세기
 *
 * 해밍 거리 계산에 사용됩니다.
 * 컴파일러 built-in을 사용할 수 없을 때 fallback입니다.
 */
static int count_bits(uint8_t byte) {
    int count = 0;
    while (byte) {
        count += byte & 1;
        byte >>= 1;
    }
    return count;
}

/* ═══════════════════════════════════════════════
 * 1. 단일 해시 함수 구현
 * ═══════════════════════════════════════════════ */

/**
 * blake3_hash_string - 문자열 → BLAKE3 해시 (16진수 문자열)
 *
 * 사용 예시 (C):
 *   char* h = blake3_hash_string("hello world");
 *   // h = "d74981ef093..."
 *   free_hash(h);
 *
 * 사용 예시 (Python via ctypes):
 *   result = lib.blake3_hash_string(b"hello world")
 *   print(result.decode())
 */
EXPORT char* blake3_hash_string(const char* input) {
    if (input == NULL) {
        return NULL;
    }

    /* BLAKE3 해시 계산 (32바이트 출력) */
    uint8_t hash[DETECTIVE_HASH_LEN];
    blake3((const void*)input, strlen(input), hash, DETECTIVE_HASH_LEN);

    /* 16진수 문자열 변환 */
    char* result = (char*)malloc(DETECTIVE_HEX_LEN);
    if (result == NULL) {
        return NULL;
    }

    bytes_to_hex(hash, DETECTIVE_HASH_LEN, result);
    return result;
}

/**
 * blake3_hash_bytes - 바이트 데이터 → BLAKE3 해시 (바이너리)
 *
 * 사용 예시 (C):
 *   uint8_t out[32];
 *   blake3_hash_bytes(data, data_len, out, 32);
 *
 * 사용 예시 (Python):
 *   buf = ctypes.create_string_buffer(32)
 *   lib.blake3_hash_bytes(data_ptr, len(data), buf, 32)
 *   hash_bytes = bytes(buf)
 */
EXPORT void blake3_hash_bytes(const uint8_t* data, size_t len,
                              uint8_t* out, size_t out_len) {
    if (data == NULL || out == NULL || out_len == 0) {
        return;
    }
    blake3((const void*)data, len, out, out_len);
}

/**
 * free_hash - blake3_hash_string 반환값 메모리 해제
 *
 * 사용 예시 (C):
 *   char* h = blake3_hash_string("test");
 *   // ... h 사용 ...
 *   free_hash(h);
 */
EXPORT void free_hash(char* hash_str) {
    if (hash_str != NULL) {
        free(hash_str);
    }
}

/* ═══════════════════════════════════════════════
 * 2. 해시 비교 함수 구현
 * ═══════════════════════════════════════════════ */

/**
 * hash_compare - 두 해시 문자열 완전 비교
 *
 * 바이러스 DB에서 정확히 같은 시그니처를 찾을 때 사용합니다.
 *
 * 사용 예시 (C):
 *   char* h1 = blake3_hash_string("virus_code_A");
 *   char* h2 = blake3_hash_string("virus_code_A");
 *   int result = hash_compare(h1, h2);
 *   // result == 0 (일치)
 *   free_hash(h1); free_hash(h2);
 *
 * @return 0 = 일치, 1 = 불일치
 */
EXPORT int hash_compare(const char* hash1, const char* hash2) {
    if (hash1 == NULL || hash2 == NULL) {
        return 1;  /* NULL은 불일치로 처리 */
    }
    return strcmp(hash1, hash2) == 0 ? 0 : 1;
}

/**
 * hash_hamming_distance - 바이너리 해시 간 해밍 거리 (비트 단위)
 *
 * 해밍 거리가 작을수록 두 해시가 유사합니다.
 * 바이러스 변종 탐지에 활용됩니다.
 *
 * 사용 예시 (C):
 *   uint8_t h1[32], h2[32];
 *   blake3_hash_bytes(data1, len1, h1, 32);
 *   blake3_hash_bytes(data2, len2, h2, 32);
 *   int dist = hash_hamming_distance(h1, h2, 32);
 *   double similarity = 1.0 - (double)dist / (32 * 8);
 *   printf("유사도: %.1f%%\n", similarity * 100);
 *
 * @return 서로 다른 비트 개수 (0 = 완전 일치)
 */
EXPORT int hash_hamming_distance(const uint8_t* hash1, const uint8_t* hash2,
                                 size_t len) {
    if (hash1 == NULL || hash2 == NULL) {
        return -1;
    }

    int distance = 0;
    for (size_t i = 0; i < len; i++) {
        /* XOR로 다른 비트를 찾고 popcount */
        uint8_t diff = hash1[i] ^ hash2[i];
        distance += count_bits(diff);
    }
    return distance;
}

/* ═══════════════════════════════════════════════
 * 3. 배치 해시 처리 구현 (Python List 대응)
 * ═══════════════════════════════════════════════ */

/**
 * batch_hash_strings - 문자열 배열 일괄 BLAKE3 해시
 *
 * Python에서 리스트를 전달받아 C에서 고속으로 처리합니다.
 * 각 문자열마다 blake3_hash_string()을 호출합니다.
 *
 * 사용 예시 (C):
 *   const char* codes[] = {
 *       "import os; os.system('rm -rf /')",
 *       "print('hello')",
 *       "eval(base64.decode(...))"
 *   };
 *   char** hashes = batch_hash_strings(codes, 3);
 *   for (int i = 0; i < 3; i++) {
 *       printf("Code[%d] hash: %s\n", i, hashes[i]);
 *   }
 *   free_batch_hashes(hashes, 3);
 *
 * 사용 예시 (Python):
 *   hashes = core.batch_hash(["code1", "code2", "code3"])
 *   # hashes = ["a8f5...", "3b2c...", "7d1e..."]
 *
 * @return  해시 문자열 배열 (free_batch_hashes로 해제)
 *          실패 시 NULL
 */
EXPORT char** batch_hash_strings(const char** strings, int count) {
    if (strings == NULL || count <= 0) {
        return NULL;
    }

    /* 결과 배열 할당 */
    char** results = (char**)malloc(sizeof(char*) * count);
    if (results == NULL) {
        return NULL;
    }

    /* 각 문자열을 개별 해시 */
    for (int i = 0; i < count; i++) {
        results[i] = blake3_hash_string(strings[i]);
        if (results[i] == NULL) {
            /* 할당 실패 시 이미 할당된 것들 해제 */
            for (int j = 0; j < i; j++) {
                free(results[j]);
            }
            free(results);
            return NULL;
        }
    }

    return results;
}

/**
 * free_batch_hashes - batch_hash_strings 결과 메모리 해제
 *
 * 사용 예시 (C):
 *   char** hashes = batch_hash_strings(inputs, count);
 *   // ... 사용 ...
 *   free_batch_hashes(hashes, count);
 */
EXPORT void free_batch_hashes(char** hashes, int count) {
    if (hashes == NULL) {
        return;
    }
    for (int i = 0; i < count; i++) {
        if (hashes[i] != NULL) {
            free(hashes[i]);
        }
    }
    free(hashes);
}

/* ═══════════════════════════════════════════════
 * 4. 배치 해시 비교 구현 (바이러스 DB 매칭)
 * ═══════════════════════════════════════════════ */

/**
 * batch_compare_hash - DB 해시 배열에서 대상 해시와 일치하는 인덱스 검색
 *
 * 바이러스 시그니처 데이터베이스에서 의심 파일의 해시가
 * 어떤 바이러스와 일치하는지 빠르게 찾습니다.
 *
 * 사용 예시 (C):
 *   // DB에 5개 바이러스 시그니처가 있고, target이 [1]번, [3]번과 일치할 때
 *   const char* db[] = {"aaa...", "bbb...", "ccc...", "bbb...", "ddd..."};
 *   int match_count;
 *   int* matches = batch_compare_hash("bbb...", db, 5, &match_count);
 *   // match_count == 2, matches = [1, 3]
 *   free_match_results(matches);
 *
 * 사용 예시 (Python):
 *   matches = core.batch_compare(target_hash, db_hashes)
 *   # matches = [1, 3]
 *
 * @return  일치 인덱스 배열 (free_match_results로 해제)
 *          매칭 없으면 NULL + match_count=0
 */
EXPORT int* batch_compare_hash(const char* target_hash,
                               const char** db_hashes, int db_count,
                               int* match_count) {
    if (target_hash == NULL || db_hashes == NULL || db_count <= 0 || match_count == NULL) {
        if (match_count) *match_count = 0;
        return NULL;
    }

    /* 최대 크기로 임시 배열 할당 */
    int* temp_matches = (int*)malloc(sizeof(int) * db_count);
    if (temp_matches == NULL) {
        *match_count = 0;
        return NULL;
    }

    /* DB 순회하며 비교 */
    int count = 0;
    for (int i = 0; i < db_count; i++) {
        if (db_hashes[i] != NULL && hash_compare(target_hash, db_hashes[i]) == 0) {
            temp_matches[count] = i;
            count++;
        }
    }

    *match_count = count;

    /* 매칭 없으면 메모리 해제 후 NULL 반환 */
    if (count == 0) {
        free(temp_matches);
        return NULL;
    }

    /* 정확한 크기로 재할당 */
    int* results = (int*)realloc(temp_matches, sizeof(int) * count);
    if (results == NULL) {
        /* realloc 실패 시 원본 반환 */
        return temp_matches;
    }

    return results;
}

/**
 * free_match_results - batch_compare_hash 결과 메모리 해제
 */
EXPORT void free_match_results(int* results) {
    if (results != NULL) {
        free(results);
    }
}

/* ═══════════════════════════════════════════════
 * 5. 유사도 기반 배치 검색 구현
 * ═══════════════════════════════════════════════ */

/**
 * batch_similarity_search - 유사도 임계값 이상인 DB 항목 검색
 *
 * 해밍 거리를 기반으로 비트 단위 유사도를 계산합니다.
 * 바이러스 변종을 찾을 때 사용합니다.
 *
 * 유사도 = 1.0 - (해밍_거리 / (hash_len * 8))
 *
 * 사용 예시 (C):
 *   uint8_t target[32];
 *   blake3_hash_bytes(suspicious_data, len, target, 32);
 *
 *   // DB에서 85% 이상 유사한 항목 검색
 *   int result_count;
 *   SimilarityResult* results = batch_similarity_search(
 *       target, 32, db_hashes, db_size, 0.85, &result_count);
 *
 *   for (int i = 0; i < result_count; i++) {
 *       printf("DB[%d]: 유사도 %.1f%%\n",
 *              results[i].index, results[i].similarity * 100);
 *   }
 *   free_similarity_results(results);
 *
 * 사용 예시 (Python):
 *   results = core.similarity_search(target_bytes, db_list, 0.85)
 *   for idx, score in results:
 *       print(f"Virus #{idx}: {score:.1%} match")
 */
EXPORT SimilarityResult* batch_similarity_search(
    const uint8_t* target_hash, size_t hash_len,
    const uint8_t** db_hashes, int db_count,
    double threshold, int* result_count) {

    if (target_hash == NULL || db_hashes == NULL || db_count <= 0 ||
        result_count == NULL || hash_len == 0) {
        if (result_count) *result_count = 0;
        return NULL;
    }

    /* 최대 크기로 임시 배열 할당 */
    SimilarityResult* temp = (SimilarityResult*)malloc(
        sizeof(SimilarityResult) * db_count);
    if (temp == NULL) {
        *result_count = 0;
        return NULL;
    }

    int total_bits = (int)(hash_len * 8);
    int count = 0;

    /* DB 순회하며 유사도 계산 */
    for (int i = 0; i < db_count; i++) {
        if (db_hashes[i] == NULL) {
            continue;
        }

        int distance = hash_hamming_distance(target_hash, db_hashes[i], hash_len);
        if (distance < 0) {
            continue;
        }

        double similarity = 1.0 - ((double)distance / total_bits);

        /* 임계값 이상인 결과만 수집 */
        if (similarity >= threshold) {
            temp[count].index = i;
            temp[count].similarity = similarity;
            count++;
        }
    }

    *result_count = count;

    /* 결과 없으면 메모리 해제 */
    if (count == 0) {
        free(temp);
        return NULL;
    }

    /* 유사도 내림차순 정렬 (간단한 선택 정렬) */
    for (int i = 0; i < count - 1; i++) {
        int max_idx = i;
        for (int j = i + 1; j < count; j++) {
            if (temp[j].similarity > temp[max_idx].similarity) {
                max_idx = j;
            }
        }
        if (max_idx != i) {
            SimilarityResult swap = temp[i];
            temp[i] = temp[max_idx];
            temp[max_idx] = swap;
        }
    }

    /* 정확한 크기로 재할당 */
    SimilarityResult* results = (SimilarityResult*)realloc(
        temp, sizeof(SimilarityResult) * count);
    if (results == NULL) {
        return temp;
    }

    return results;
}

/**
 * free_similarity_results - batch_similarity_search 결과 메모리 해제
 */
EXPORT void free_similarity_results(SimilarityResult* results) {
    if (results != NULL) {
        free(results);
    }
}
