/**
 * @file detective_core.h
 * @brief Detective-H Core Module - BLAKE3 기반 해시 및 바이러스 시그니처 비교 API
 *
 * 이 모듈은 BLAKE3 해시 알고리즘을 활용하여 다음 기능을 제공합니다:
 *   1. 단일 문자열/바이트 해시 생성
 *   2. 해시 비교 (완전 일치 / 해밍 거리)
 *   3. 대량 배치 해시 생성 (Python 리스트 대응)
 *   4. 대량 배치 해시 비교 (바이러스 DB 매칭)
 *   5. 유사도 기반 배치 검색
 *
 * ──────────────────────────────────────────────
 * 사용 예시 (Python ctypes):
 * ──────────────────────────────────────────────
 *
 *   from virus_tracker.detective_core_wrapper import DetectiveCore
 *
 *   core = DetectiveCore()
 *
 *   # 1) 단일 해시
 *   h = core.hash("malicious_code_string")
 *
 *   # 2) 배치 해시 (Python 리스트 → C에서 고속 처리)
 *   hashes = core.batch_hash(["code1", "code2", "code3"])
 *
 *   # 3) DB 매칭 (일치하는 인덱스 반환)
 *   matches = core.batch_compare(target_hash, db_hashes)
 *
 *   # 4) 유사도 검색 (임계값 이상 결과)
 *   results = core.similarity_search(target_bytes, db_list, 0.85)
 *
 * ──────────────────────────────────────────────
 *
 * @author Detective-H Team
 * @date 2025-02-02
 */

#ifndef DETECTIVE_CORE_H
#define DETECTIVE_CORE_H

#include <stddef.h>
#include <stdint.h>

/* ═══════════════════════════════════════════════
 * 플랫폼별 EXPORT 매크로
 * ═══════════════════════════════════════════════ */
#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

/* ═══════════════════════════════════════════════
 * 상수 정의
 * ═══════════════════════════════════════════════ */

/** BLAKE3 기본 해시 출력 길이 (32바이트 = 256비트) */
#define DETECTIVE_HASH_LEN     32

/** 해시의 16진수 문자열 길이 (32바이트 * 2 + null terminator) */
#define DETECTIVE_HEX_LEN      (DETECTIVE_HASH_LEN * 2 + 1)

/* ═══════════════════════════════════════════════
 * 유사도 결과 구조체
 * ═══════════════════════════════════════════════ */

/**
 * @brief 유사도 검색 결과를 담는 구조체
 *
 * @param index      DB 내 매칭된 항목의 인덱스
 * @param similarity 0.0 ~ 1.0 사이의 유사도 (1.0 = 완전 일치)
 *
 * 사용 예시 (C):
 *   int count;
 *   SimilarityResult* results = batch_similarity_search(
 *       target, 32, db_hashes, db_count, 0.85, &count);
 *   for (int i = 0; i < count; i++) {
 *       printf("Index %d: %.1f%% match\n",
 *              results[i].index, results[i].similarity * 100);
 *   }
 *   free_similarity_results(results);
 */
typedef struct {
    int index;
    double similarity;
} SimilarityResult;

/* ═══════════════════════════════════════════════
 * 1. 단일 해시 함수
 * ═══════════════════════════════════════════════ */

/**
 * @brief 문자열을 BLAKE3로 해시하여 16진수 문자열로 반환
 *
 * @param input  해시할 null-terminated 문자열
 * @return       64자 16진수 문자열 (malloc 할당, free_hash()로 해제 필요)
 *               실패 시 NULL 반환
 *
 * 사용 예시 (C):
 *   char* h = blake3_hash_string("hello world");
 *   printf("Hash: %s\n", h);   // 출력: "d74981..."
 *   free_hash(h);
 */
EXPORT char* blake3_hash_string(const char* input);

/**
 * @brief 바이트 데이터를 BLAKE3로 해시하여 바이너리 결과 반환
 *
 * @param data    해시할 바이트 데이터
 * @param len     데이터 길이 (바이트)
 * @param out     해시 결과를 저장할 버퍼 (호출자가 할당)
 * @param out_len 출력 버퍼 크기 (바이트, 기본 32)
 *
 * 사용 예시 (C):
 *   uint8_t hash[32];
 *   blake3_hash_bytes((uint8_t*)"data", 4, hash, 32);
 */
EXPORT void blake3_hash_bytes(const uint8_t* data, size_t len,
                              uint8_t* out, size_t out_len);

/**
 * @brief blake3_hash_string()이 반환한 문자열 메모리 해제
 *
 * @param hash_str free할 해시 문자열 포인터
 */
EXPORT void free_hash(char* hash_str);

/* ═══════════════════════════════════════════════
 * 2. 해시 비교 함수
 * ═══════════════════════════════════════════════ */

/**
 * @brief 두 해시 문자열의 완전 일치 비교
 *
 * @param hash1  첫 번째 해시 (16진수 문자열)
 * @param hash2  두 번째 해시 (16진수 문자열)
 * @return       0 = 일치, 1 = 불일치
 *
 * 사용 예시 (C):
 *   if (hash_compare(h1, h2) == 0) {
 *       printf("바이러스 시그니처 일치!\n");
 *   }
 */
EXPORT int hash_compare(const char* hash1, const char* hash2);

/**
 * @brief 두 바이너리 해시 간 해밍 거리 계산 (비트 단위)
 *
 * 해밍 거리가 작을수록 두 해시가 유사합니다.
 *
 * @param hash1  첫 번째 해시 (바이너리)
 * @param hash2  두 번째 해시 (바이너리)
 * @param len    해시 길이 (바이트)
 * @return       다른 비트의 개수 (해밍 거리)
 */
EXPORT int hash_hamming_distance(const uint8_t* hash1, const uint8_t* hash2,
                                 size_t len);

/* ═══════════════════════════════════════════════
 * 3. 배치 해시 처리 (Python List 대응)
 * ═══════════════════════════════════════════════ */

/**
 * @brief 문자열 배열을 일괄 BLAKE3 해시 → 해시 문자열 배열 반환
 *
 * Python에서 리스트를 넘겨받아 C에서 고속으로 일괄 해시합니다.
 *
 * @param strings  null-terminated 문자열 배열
 * @param count    문자열 개수
 * @return         해시 문자열 배열 (free_batch_hashes()로 해제)
 *                 실패 시 NULL 반환
 *
 * 사용 예시 (C):
 *   const char* inputs[] = {"code1", "code2", "code3"};
 *   char** hashes = batch_hash_strings(inputs, 3);
 *   for (int i = 0; i < 3; i++) printf("[%d] %s\n", i, hashes[i]);
 *   free_batch_hashes(hashes, 3);
 */
EXPORT char** batch_hash_strings(const char** strings, int count);

/**
 * @brief batch_hash_strings()가 반환한 해시 배열 메모리 해제
 *
 * @param hashes  해제할 해시 배열
 * @param count   배열 크기
 */
EXPORT void free_batch_hashes(char** hashes, int count);

/* ═══════════════════════════════════════════════
 * 4. 배치 해시 비교 (바이러스 DB 매칭)
 * ═══════════════════════════════════════════════ */

/**
 * @brief 대상 해시를 DB 해시 배열에서 검색하여 일치 인덱스 반환
 *
 * 바이러스 시그니처 DB에서 특정 해시와 완전히 일치하는 항목을 찾습니다.
 *
 * @param target_hash  찾을 대상 해시 (16진수 문자열)
 * @param db_hashes    DB 해시 배열
 * @param db_count     DB 해시 개수
 * @param match_count  [out] 매칭된 개수가 저장될 포인터
 * @return             매칭된 인덱스 배열 (free_match_results()로 해제)
 *                     매칭 없으면 NULL, match_count=0
 *
 * 사용 예시 (C):
 *   int match_count;
 *   int* matches = batch_compare_hash(target, db, db_size, &match_count);
 *   for (int i = 0; i < match_count; i++) {
 *       printf("바이러스 #%d 발견!\n", matches[i]);
 *   }
 *   free_match_results(matches);
 */
EXPORT int* batch_compare_hash(const char* target_hash,
                               const char** db_hashes, int db_count,
                               int* match_count);

/**
 * @brief batch_compare_hash()가 반환한 결과 배열 메모리 해제
 *
 * @param results  해제할 인덱스 배열
 */
EXPORT void free_match_results(int* results);

/* ═══════════════════════════════════════════════
 * 5. 유사도 기반 배치 검색
 * ═══════════════════════════════════════════════ */

/**
 * @brief 대상 해시와 DB 해시들의 유사도를 계산하고 임계값 이상 결과 반환
 *
 * 해밍 거리를 기반으로 비트 단위 유사도를 계산합니다.
 * 바이러스 변종 탐지에 활용됩니다.
 *
 * @param target_hash   대상 해시 (바이너리)
 * @param hash_len      해시 길이 (바이트, 기본 32)
 * @param db_hashes     DB 해시 배열 (각각 바이너리)
 * @param db_count      DB 해시 개수
 * @param threshold     유사도 임계값 (0.0 ~ 1.0)
 * @param result_count  [out] 결과 개수가 저장될 포인터
 * @return              SimilarityResult 배열 (free_similarity_results()로 해제)
 *
 * 사용 예시 (C):
 *   int count;
 *   SimilarityResult* results = batch_similarity_search(
 *       target, 32, db, db_size, 0.85, &count);
 *   for (int i = 0; i < count; i++) {
 *       printf("DB[%d] 유사도: %.1f%%\n",
 *              results[i].index, results[i].similarity * 100);
 *   }
 *   free_similarity_results(results);
 */
EXPORT SimilarityResult* batch_similarity_search(
    const uint8_t* target_hash, size_t hash_len,
    const uint8_t** db_hashes, int db_count,
    double threshold, int* result_count);

/**
 * @brief batch_similarity_search()가 반환한 결과 배열 메모리 해제
 *
 * @param results  해제할 SimilarityResult 배열
 */
EXPORT void free_similarity_results(SimilarityResult* results);

#endif /* DETECTIVE_CORE_H */
