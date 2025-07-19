"""
Blake2b 해시 함수의 C 구현에 대한 Python 바인딩
ctypes를 사용하여 C 함수를 호출합니다.
"""
import ctypes
import os
from ctypes import c_int, c_size_t, c_void_p, c_uint8, c_uint64, Structure, POINTER, byref, create_string_buffer

# blake2b_state 구조체 정의
class Blake2bState(Structure):
    _fields_ = [
        ("h", c_uint64 * 8),    # uint64_t h[8]
        ("t", c_uint64 * 2),    # uint64_t t[2]
        ("f", c_uint64 * 2),    # uint64_t f[2]
        ("buf", c_uint8 * 128), # uint8_t buf[128]
        ("buflen", c_size_t),   # size_t buflen
        ("outlen", c_size_t)    # size_t outlen
    ]

# 라이브러리 경로 찾기
def find_library_path():
    """Blake2b 라이브러리 파일 경로를 찾습니다."""
    # 상대 경로 계산
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
    
    # Windows에서는 .dll, Linux/macOS에서는 .so 또는 .dylib
    if os.name == 'nt':  # Windows
        lib_extensions = ['.dll']
        lib_name = 'blake2b'
    else:  # Linux/macOS
        lib_extensions = ['.so', '.dylib']
        lib_name = 'libblake2b'
    
    # 가능한 경로들
    possible_paths = []
    build_dirs = ['build', 'build/Debug', 'build/Release']
    
    for build_dir in build_dirs:
        for ext in lib_extensions:
            possible_paths.append(os.path.join(project_root, 'core', build_dir, lib_name + ext))
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    raise FileNotFoundError(f"Blake2b 라이브러리 파일을 찾을 수 없습니다. 다음 경로를 확인하세요: {possible_paths}")

# 전역 인스턴스
try:
    _blake2b_lib = ctypes.CDLL(find_library_path())
    
    # 함수 프로토타입 정의
    _blake2b_lib.blake2b_init.argtypes = [POINTER(Blake2bState), c_size_t]
    _blake2b_lib.blake2b_init.restype = c_int
    
    _blake2b_lib.blake2b_update.argtypes = [POINTER(Blake2bState), c_void_p, c_size_t]
    _blake2b_lib.blake2b_update.restype = c_int
    
    _blake2b_lib.blake2b_final.argtypes = [POINTER(Blake2bState), c_void_p, c_size_t]
    _blake2b_lib.blake2b_final.restype = c_int

except (FileNotFoundError, OSError) as e:
    print(f"경고: Blake2b 라이브러리를 로드할 수 없습니다: {e}")
    print("라이브러리를 빌드했는지 확인하세요. (CMake를 사용해 blake2b.dll 생성)")
    _blake2b_lib = None

def blake2b_hash(data, digest_size=64):
    """
    데이터의 Blake2b 해시를 계산합니다.
    
    Args:
        data: 해시할 바이트 데이터 (bytes 또는 bytearray)
        digest_size: 해시 결과의 바이트 크기 (최대 64)
        
    Returns:
        Blake2b 해시 값 (bytes)
    """
    if _blake2b_lib is None:
        raise RuntimeError("Blake2b 라이브러리가 로드되지 않았습니다.")
    
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("데이터는 bytes 또는 bytearray 타입이어야 합니다")
    
    if not (1 <= digest_size <= 64):
        raise ValueError("digest_size는 1에서 64 사이여야 합니다")
    
    # Blake2b 상태 초기화
    state = Blake2bState()
    result = _blake2b_lib.blake2b_init(byref(state), digest_size)
    if result != 0:
        raise RuntimeError(f"blake2b_init 실패: {result}")
    
    # 데이터 업데이트
    data_ptr = ctypes.create_string_buffer(data)
    result = _blake2b_lib.blake2b_update(byref(state), data_ptr, len(data))
    if result != 0:
        raise RuntimeError(f"blake2b_update 실패: {result}")
    
    # 해시 완료
    digest = create_string_buffer(digest_size)
    result = _blake2b_lib.blake2b_final(byref(state), digest, digest_size)
    if result != 0:
        raise RuntimeError(f"blake2b_final 실패: {result}")
    
    return bytes(digest)

def file_hash(file_path, digest_size=64, chunk_size=8192):
    """
    파일의 Blake2b 해시를 계산합니다.
    
    Args:
        file_path: 해시할 파일 경로
        digest_size: 해시 결과의 바이트 크기 (최대 64)
        chunk_size: 한 번에 읽을 바이트 크기
        
    Returns:
        Blake2b 해시 값 (bytes)
    """
    if _blake2b_lib is None:
        raise RuntimeError("Blake2b 라이브러리가 로드되지 않았습니다.")
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"파일이 존재하지 않습니다: {file_path}")
    
    # Blake2b 상태 초기화
    state = Blake2bState()
    result = _blake2b_lib.blake2b_init(byref(state), digest_size)
    if result != 0:
        raise RuntimeError(f"blake2b_init 실패: {result}")
    
    # 파일 청크별로 읽어서 해시 업데이트
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            
            chunk_buffer = create_string_buffer(chunk)
            result = _blake2b_lib.blake2b_update(byref(state), chunk_buffer, len(chunk))
            if result != 0:
                raise RuntimeError(f"blake2b_update 실패: {result}")
    
    # 해시 완료
    digest = create_string_buffer(digest_size)
    result = _blake2b_lib.blake2b_final(byref(state), digest, digest_size)
    if result != 0:
        raise RuntimeError(f"blake2b_final 실패: {result}")
    
    return bytes(digest)
