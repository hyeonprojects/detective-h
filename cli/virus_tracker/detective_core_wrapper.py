"""
Detective Core - BLAKE3 기반 해시 및 바이러스 시그니처 비교 Python 래퍼

이 모듈은 C로 구현된 detective_core 라이브러리를 Python에서
편리하게 사용할 수 있도록 ctypes 기반 래퍼를 제공합니다.

═══════════════════════════════════════════════
사용 방법
═══════════════════════════════════════════════

1. 함수형 API (간단한 사용):
    from virus_tracker.detective_core_wrapper import hash_string, batch_hash

    h = hash_string("hello world")
    hashes = batch_hash(["code1", "code2", "code3"])

2. 클래스형 API (객체지향):
    from virus_tracker.detective_core_wrapper import DetectiveCore

    core = DetectiveCore()
    h = core.hash("suspicious_code")
    hashes = core.batch_hash(["code1", "code2"])
    matches = core.batch_compare(target_hash, db_hashes)

3. 바이러스 DB 매칭:
    from virus_tracker.detective_core_wrapper import VirusSignatureDB

    db = VirusSignatureDB(["known_hash1", "known_hash2", ...])
    matches = db.search("target_hash")
    similar = db.similarity_search(target_bytes, threshold=0.85)

═══════════════════════════════════════════════
빌드 필요:
    cd core/blake_hash/build
    cmake .. -G "Ninja" -DCMAKE_C_COMPILER=clang
    cmake --build .
═══════════════════════════════════════════════
"""

import ctypes
import os
import sys
from ctypes import (
    c_char_p, c_int, c_size_t, c_double, c_uint8, c_void_p,
    POINTER, Structure, byref, create_string_buffer
)
from typing import List, Tuple, Optional


# ═══════════════════════════════════════════════
# 유사도 결과 구조체 (C 구조체 매핑)
# ═══════════════════════════════════════════════

class SimilarityResult(Structure):
    """
    C의 SimilarityResult 구조체에 대응하는 ctypes 구조체

    Fields:
        index (int): DB 내 매칭된 항목의 인덱스
        similarity (float): 0.0 ~ 1.0 사이의 유사도
    """
    _fields_ = [
        ("index", c_int),
        ("similarity", c_double),
    ]


# ═══════════════════════════════════════════════
# 라이브러리 로딩
# ═══════════════════════════════════════════════

def _find_library_path() -> str:
    """
    detective_core 네이티브 라이브러리 파일 경로를 찾습니다.

    검색 순서:
        1. core/blake_hash/build/ 하위 디렉토리
        2. 플랫폼별 파일 확장자 (.dll / .so / .dylib)

    Returns:
        라이브러리 파일의 절대 경로

    Raises:
        FileNotFoundError: 라이브러리를 찾을 수 없는 경우
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))

    if sys.platform == 'win32':
        lib_extensions = ['.dll']
        lib_name = 'detective_core'
    elif sys.platform == 'darwin':
        lib_extensions = ['.dylib']
        lib_name = 'libdetective_core'
    else:
        lib_extensions = ['.so']
        lib_name = 'libdetective_core'

    build_dirs = ['build', 'build/Debug', 'build/Release']
    possible_paths = []

    for build_dir in build_dirs:
        for ext in lib_extensions:
            path = os.path.join(project_root, 'core', 'blake_hash', build_dir, lib_name + ext)
            possible_paths.append(path)

    for path in possible_paths:
        if os.path.exists(path):
            return path

    raise FileNotFoundError(
        f"detective_core 라이브러리를 찾을 수 없습니다.\n"
        f"빌드가 필요합니다:\n"
        f"  cd core/blake_hash/build\n"
        f"  cmake .. -G \"Ninja\" -DCMAKE_C_COMPILER=clang\n"
        f"  cmake --build .\n"
        f"검색 경로: {possible_paths}"
    )


def _load_library():
    """
    네이티브 라이브러리를 로드하고 함수 프로토타입을 설정합니다.

    Returns:
        ctypes.CDLL 인스턴스 또는 None (로드 실패 시)
    """
    try:
        lib_path = _find_library_path()
        lib = ctypes.CDLL(lib_path)

        # ── 1. 단일 해시 ──
        lib.blake3_hash_string.argtypes = [c_char_p]
        lib.blake3_hash_string.restype = c_char_p

        lib.blake3_hash_bytes.argtypes = [POINTER(c_uint8), c_size_t,
                                          POINTER(c_uint8), c_size_t]
        lib.blake3_hash_bytes.restype = None

        lib.free_hash.argtypes = [c_char_p]
        lib.free_hash.restype = None

        # ── 2. 해시 비교 ──
        lib.hash_compare.argtypes = [c_char_p, c_char_p]
        lib.hash_compare.restype = c_int

        lib.hash_hamming_distance.argtypes = [POINTER(c_uint8), POINTER(c_uint8),
                                               c_size_t]
        lib.hash_hamming_distance.restype = c_int

        # ── 3. 배치 해시 ──
        lib.batch_hash_strings.argtypes = [POINTER(c_char_p), c_int]
        lib.batch_hash_strings.restype = POINTER(c_char_p)

        lib.free_batch_hashes.argtypes = [POINTER(c_char_p), c_int]
        lib.free_batch_hashes.restype = None

        # ── 4. 배치 비교 ──
        lib.batch_compare_hash.argtypes = [c_char_p, POINTER(c_char_p),
                                            c_int, POINTER(c_int)]
        lib.batch_compare_hash.restype = POINTER(c_int)

        lib.free_match_results.argtypes = [POINTER(c_int)]
        lib.free_match_results.restype = None

        # ── 5. 유사도 검색 ──
        lib.batch_similarity_search.argtypes = [
            POINTER(c_uint8), c_size_t,
            POINTER(POINTER(c_uint8)), c_int,
            c_double, POINTER(c_int)
        ]
        lib.batch_similarity_search.restype = POINTER(SimilarityResult)

        lib.free_similarity_results.argtypes = [POINTER(SimilarityResult)]
        lib.free_similarity_results.restype = None

        return lib

    except (FileNotFoundError, OSError) as e:
        print(f"경고: detective_core 라이브러리 로드 실패: {e}")
        return None


# 전역 라이브러리 인스턴스
_lib = _load_library()


# ═══════════════════════════════════════════════
# 함수형 API
# ═══════════════════════════════════════════════

def hash_string(data: str) -> str:
    """
    문자열을 BLAKE3로 해시하여 16진수 문자열로 반환합니다.

    Args:
        data: 해시할 문자열

    Returns:
        64자 16진수 해시 문자열

    Raises:
        RuntimeError: 라이브러리 미로드 시
        TypeError: 입력이 문자열이 아닌 경우

    사용 예시:
        >>> h = hash_string("hello world")
        >>> print(h)  # "d74981..."
        >>> len(h)    # 64
    """
    if _lib is None:
        raise RuntimeError("detective_core 라이브러리가 로드되지 않았습니다.")
    if not isinstance(data, str):
        raise TypeError("입력은 문자열이어야 합니다.")

    result = _lib.blake3_hash_string(data.encode('utf-8'))
    if result is None:
        raise RuntimeError("해시 계산 실패")
    return result.decode('ascii')


def hash_bytes(data: bytes, digest_size: int = 32) -> bytes:
    """
    바이트 데이터를 BLAKE3로 해시합니다.

    Args:
        data: 해시할 바이트 데이터
        digest_size: 출력 해시 크기 (바이트, 기본 32)

    Returns:
        BLAKE3 해시 바이트

    사용 예시:
        >>> h = hash_bytes(b"binary data")
        >>> print(h.hex())  # "a8f5f1..."
    """
    if _lib is None:
        raise RuntimeError("detective_core 라이브러리가 로드되지 않았습니다.")
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("입력은 bytes 또는 bytearray여야 합니다.")

    data_array = (c_uint8 * len(data))(*data)
    out = (c_uint8 * digest_size)()
    _lib.blake3_hash_bytes(data_array, len(data), out, digest_size)
    return bytes(out)


def compare_hashes(hash1: str, hash2: str) -> bool:
    """
    두 해시 문자열이 일치하는지 비교합니다.

    Args:
        hash1: 첫 번째 해시 (16진수 문자열)
        hash2: 두 번째 해시 (16진수 문자열)

    Returns:
        True = 일치, False = 불일치

    사용 예시:
        >>> h1 = hash_string("test")
        >>> h2 = hash_string("test")
        >>> compare_hashes(h1, h2)  # True
    """
    if _lib is None:
        raise RuntimeError("detective_core 라이브러리가 로드되지 않았습니다.")

    result = _lib.hash_compare(hash1.encode('ascii'), hash2.encode('ascii'))
    return result == 0


def batch_hash(strings: List[str]) -> List[str]:
    """
    문자열 리스트를 일괄 BLAKE3 해시합니다. (C에서 고속 처리)

    Args:
        strings: 해시할 문자열 리스트

    Returns:
        해시 문자열 리스트 (입력과 동일한 순서)

    사용 예시:
        >>> hashes = batch_hash(["code1", "code2", "code3"])
        >>> len(hashes)  # 3
        >>> print(hashes[0])  # "a8f5..."
    """
    if _lib is None:
        raise RuntimeError("detective_core 라이브러리가 로드되지 않았습니다.")
    if not strings:
        return []

    count = len(strings)

    # Python 문자열 리스트 → C 문자열 배열 변환
    c_strings = (c_char_p * count)()
    for i, s in enumerate(strings):
        c_strings[i] = s.encode('utf-8')

    # C 함수 호출
    result_ptr = _lib.batch_hash_strings(c_strings, count)
    if not result_ptr:
        raise RuntimeError("배치 해시 실패")

    # 결과 추출
    results = []
    for i in range(count):
        if result_ptr[i]:
            results.append(result_ptr[i].decode('ascii'))
        else:
            results.append(None)

    # C 측 메모리 해제
    _lib.free_batch_hashes(result_ptr, count)

    return results


def batch_compare(target_hash: str, db_hashes: List[str]) -> List[int]:
    """
    대상 해시를 DB 해시 리스트에서 검색하여 일치하는 인덱스를 반환합니다.

    바이러스 시그니처 DB에서 완전 일치하는 항목을 찾을 때 사용합니다.

    Args:
        target_hash: 찾을 대상 해시
        db_hashes: DB 해시 리스트

    Returns:
        일치하는 인덱스 리스트 (없으면 빈 리스트)

    사용 예시:
        >>> db = ["hash_a", "hash_b", "hash_a", "hash_c"]
        >>> matches = batch_compare("hash_a", db)
        >>> print(matches)  # [0, 2]
    """
    if _lib is None:
        raise RuntimeError("detective_core 라이브러리가 로드되지 않았습니다.")
    if not db_hashes:
        return []

    db_count = len(db_hashes)

    # C 배열 변환
    c_db = (c_char_p * db_count)()
    for i, h in enumerate(db_hashes):
        c_db[i] = h.encode('ascii')

    match_count = c_int(0)
    result_ptr = _lib.batch_compare_hash(
        target_hash.encode('ascii'),
        c_db, db_count,
        byref(match_count)
    )

    # 결과 추출
    matches = []
    if result_ptr and match_count.value > 0:
        for i in range(match_count.value):
            matches.append(result_ptr[i])
        _lib.free_match_results(result_ptr)

    return matches


def similarity_search(target: bytes, db_hashes: List[bytes],
                      threshold: float = 0.85,
                      hash_len: int = 32) -> List[Tuple[int, float]]:
    """
    대상 해시와 DB 해시들의 유사도를 계산하여 임계값 이상인 결과를 반환합니다.

    바이러스 변종 탐지에 사용됩니다.

    Args:
        target: 대상 해시 (바이너리, 32바이트)
        db_hashes: DB 해시 리스트 (각각 바이너리)
        threshold: 유사도 임계값 (0.0 ~ 1.0, 기본 0.85)
        hash_len: 해시 길이 (바이트, 기본 32)

    Returns:
        (인덱스, 유사도) 튜플 리스트 (유사도 내림차순)

    사용 예시:
        >>> target = hash_bytes(b"suspicious code")
        >>> db = [hash_bytes(b"virus1"), hash_bytes(b"virus2")]
        >>> results = similarity_search(target, db, threshold=0.80)
        >>> for idx, score in results:
        ...     print(f"DB[{idx}]: {score:.1%}")
    """
    if _lib is None:
        raise RuntimeError("detective_core 라이브러리가 로드되지 않았습니다.")
    if not db_hashes:
        return []

    db_count = len(db_hashes)

    # 대상 해시 → C 배열
    target_array = (c_uint8 * hash_len)(*target[:hash_len])

    # DB 해시 → C 포인터 배열
    db_arrays = []
    c_db_ptrs = (POINTER(c_uint8) * db_count)()
    for i, h in enumerate(db_hashes):
        arr = (c_uint8 * hash_len)(*h[:hash_len])
        db_arrays.append(arr)  # prevent GC
        c_db_ptrs[i] = arr

    result_count = c_int(0)
    result_ptr = _lib.batch_similarity_search(
        target_array, hash_len,
        c_db_ptrs, db_count,
        c_double(threshold),
        byref(result_count)
    )

    # 결과 추출
    results = []
    if result_ptr and result_count.value > 0:
        for i in range(result_count.value):
            results.append((result_ptr[i].index, result_ptr[i].similarity))
        _lib.free_similarity_results(result_ptr)

    return results


# ═══════════════════════════════════════════════
# 클래스형 API
# ═══════════════════════════════════════════════

class DetectiveCore:
    """
    Detective-H Core 모듈의 객체지향 인터페이스.

    BLAKE3 해시 생성, 비교, 배치 처리를 제공합니다.

    사용 예시:
        >>> core = DetectiveCore()
        >>>
        >>> # 단일 해시
        >>> h = core.hash("malicious_code")
        >>> print(f"Hash: {h}")
        >>>
        >>> # 배치 해시 (Python 리스트 → C 고속 처리)
        >>> hashes = core.batch_hash(["code1", "code2", "code3"])
        >>>
        >>> # DB 매칭
        >>> matches = core.batch_compare(target_hash, db_hashes)
        >>> if matches:
        ...     print(f"바이러스 발견! 인덱스: {matches}")
        >>>
        >>> # 유사도 검색 (변종 탐지)
        >>> results = core.similarity_search(target_bytes, db_list, 0.85)
        >>> for idx, score in results:
        ...     print(f"DB[{idx}]: {score:.1%} 유사")
    """

    def __init__(self):
        """
        DetectiveCore 초기화.

        Raises:
            RuntimeError: 네이티브 라이브러리 로드 실패 시
        """
        if _lib is None:
            raise RuntimeError(
                "detective_core 네이티브 라이브러리가 로드되지 않았습니다.\n"
                "빌드가 필요합니다:\n"
                "  cd core/blake_hash/build\n"
                "  cmake .. -G \"Ninja\" -DCMAKE_C_COMPILER=clang\n"
                "  cmake --build ."
            )
        self._lib = _lib

    def hash(self, data: str) -> str:
        """
        문자열을 BLAKE3 해시합니다.

        Args:
            data: 해시할 문자열

        Returns:
            64자 16진수 해시 문자열

        사용 예시:
            >>> core = DetectiveCore()
            >>> core.hash("hello world")
            'd74981ef093...'
        """
        return hash_string(data)

    def hash_raw(self, data: bytes, digest_size: int = 32) -> bytes:
        """
        바이트 데이터를 BLAKE3 해시합니다. (바이너리 반환)

        Args:
            data: 해시할 바이트 데이터
            digest_size: 출력 크기 (기본 32바이트)

        Returns:
            BLAKE3 해시 바이트

        사용 예시:
            >>> core = DetectiveCore()
            >>> h = core.hash_raw(b"binary data")
            >>> h.hex()
            'a8f5f167...'
        """
        return hash_bytes(data, digest_size)

    def compare(self, hash1: str, hash2: str) -> bool:
        """
        두 해시의 일치 여부를 비교합니다.

        Args:
            hash1: 첫 번째 해시
            hash2: 두 번째 해시

        Returns:
            True = 일치, False = 불일치

        사용 예시:
            >>> core = DetectiveCore()
            >>> h1 = core.hash("test")
            >>> h2 = core.hash("test")
            >>> core.compare(h1, h2)  # True
        """
        return compare_hashes(hash1, hash2)

    def batch_hash(self, strings: List[str]) -> List[str]:
        """
        문자열 리스트를 일괄 BLAKE3 해시합니다.

        Python 리스트를 C로 전달하여 고속으로 해시합니다.

        Args:
            strings: 해시할 문자열 리스트

        Returns:
            해시 문자열 리스트

        사용 예시:
            >>> core = DetectiveCore()
            >>> hashes = core.batch_hash(["code1", "code2"])
            >>> len(hashes)  # 2
        """
        return batch_hash(strings)

    def batch_compare(self, target_hash: str, db_hashes: List[str]) -> List[int]:
        """
        대상 해시를 DB 해시 리스트에서 검색합니다.

        Args:
            target_hash: 찾을 대상 해시
            db_hashes: DB 해시 리스트

        Returns:
            일치하는 인덱스 리스트

        사용 예시:
            >>> core = DetectiveCore()
            >>> target = core.hash("suspicious_code")
            >>> matches = core.batch_compare(target, known_virus_hashes)
            >>> if matches:
            ...     print(f"바이러스 발견! 인덱스: {matches}")
        """
        return batch_compare(target_hash, db_hashes)

    def similarity_search(self, target: bytes, db_hashes: List[bytes],
                          threshold: float = 0.85) -> List[Tuple[int, float]]:
        """
        유사도 기반 배치 검색 (바이러스 변종 탐지)

        Args:
            target: 대상 해시 (바이너리 32바이트)
            db_hashes: DB 해시 리스트 (바이너리)
            threshold: 유사도 임계값 (0.0~1.0)

        Returns:
            (인덱스, 유사도) 리스트 (유사도 내림차순)

        사용 예시:
            >>> core = DetectiveCore()
            >>> target = core.hash_raw(b"suspicious")
            >>> results = core.similarity_search(target, db_list, 0.85)
            >>> for idx, score in results:
            ...     print(f"DB[{idx}]: {score:.1%}")
        """
        return similarity_search(target, db_hashes, threshold)


class VirusSignatureDB:
    """
    바이러스 시그니처 데이터베이스 래퍼.

    DB에서 가져온 해시 리스트를 관리하고 검색합니다.

    사용 예시:
        >>> # DB에서 가져온 바이러스 시그니처
        >>> known_hashes = ["a8f5...", "3b2c...", "7d1e..."]
        >>> db = VirusSignatureDB(known_hashes)
        >>>
        >>> # 의심 파일 검색
        >>> core = DetectiveCore()
        >>> target = core.hash(suspicious_file_content)
        >>>
        >>> # 완전 일치 검색
        >>> matches = db.search(target)
        >>> if matches:
        ...     print(f"바이러스 발견! 인덱스: {matches}")
        >>>
        >>> # 유사도 검색 (변종 탐지)
        >>> target_raw = core.hash_raw(suspicious_file_content.encode())
        >>> similar = db.similarity_search(target_raw, threshold=0.85)
        >>> for idx, score in similar:
        ...     print(f"바이러스 #{idx}: {score:.1%} 유사")
    """

    def __init__(self, hashes: Optional[List[str]] = None):
        """
        VirusSignatureDB 초기화.

        Args:
            hashes: 초기 해시 리스트 (16진수 문자열)

        사용 예시:
            >>> db = VirusSignatureDB(["hash1", "hash2"])
            >>> db = VirusSignatureDB()  # 빈 DB로 시작
        """
        self._hashes: List[str] = list(hashes) if hashes else []
        self._raw_hashes: List[bytes] = []

        # 16진수 문자열을 바이너리로도 저장 (유사도 검색용)
        for h in self._hashes:
            try:
                self._raw_hashes.append(bytes.fromhex(h))
            except ValueError:
                self._raw_hashes.append(b'')

    @property
    def count(self) -> int:
        """DB에 등록된 시그니처 수"""
        return len(self._hashes)

    def add(self, hash_str: str) -> None:
        """
        새 해시를 DB에 추가합니다.

        Args:
            hash_str: 추가할 해시 (16진수 문자열)

        사용 예시:
            >>> db = VirusSignatureDB()
            >>> db.add("a8f5f167...")
            >>> db.count  # 1
        """
        self._hashes.append(hash_str)
        try:
            self._raw_hashes.append(bytes.fromhex(hash_str))
        except ValueError:
            self._raw_hashes.append(b'')

    def add_many(self, hashes: List[str]) -> None:
        """
        여러 해시를 한 번에 DB에 추가합니다.

        Args:
            hashes: 추가할 해시 리스트

        사용 예시:
            >>> db = VirusSignatureDB()
            >>> db.add_many(["hash1", "hash2", "hash3"])
            >>> db.count  # 3
        """
        for h in hashes:
            self.add(h)

    def search(self, target_hash: str) -> List[int]:
        """
        대상 해시와 완전 일치하는 DB 항목을 검색합니다.

        Args:
            target_hash: 검색할 해시

        Returns:
            일치하는 인덱스 리스트

        사용 예시:
            >>> db = VirusSignatureDB(["hash_a", "hash_b", "hash_a"])
            >>> db.search("hash_a")  # [0, 2]
        """
        return batch_compare(target_hash, self._hashes)

    def similarity_search(self, target: bytes,
                          threshold: float = 0.85) -> List[Tuple[int, float]]:
        """
        유사도 기반으로 DB 항목을 검색합니다.

        해밍 거리 기반 비트 유사도를 계산합니다.

        Args:
            target: 대상 해시 (바이너리 32바이트)
            threshold: 유사도 임계값 (기본 0.85)

        Returns:
            (인덱스, 유사도) 리스트 (유사도 내림차순)

        사용 예시:
            >>> results = db.similarity_search(target_bytes, 0.80)
            >>> for idx, score in results:
            ...     print(f"바이러스 #{idx}: {score:.1%}")
        """
        if not self._raw_hashes:
            return []
        return similarity_search(target, self._raw_hashes, threshold)

    def get_hash(self, index: int) -> str:
        """
        인덱스로 해시를 조회합니다.

        Args:
            index: DB 인덱스

        Returns:
            해시 문자열

        사용 예시:
            >>> db = VirusSignatureDB(["hash_a", "hash_b"])
            >>> db.get_hash(0)  # "hash_a"
        """
        return self._hashes[index]

    def get_all_hashes(self) -> List[str]:
        """
        모든 해시를 반환합니다.

        Returns:
            해시 리스트 (복사본)
        """
        return list(self._hashes)
