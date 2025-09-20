"""
Blake3 해시 함수의 C 구현에 대한 Python 바인딩
ctypes를 사용하여 C 함수를 호출합니다.
"""
import ctypes
import os
from ctypes import c_int, c_size_t, c_void_p, c_uint8, c_uint32, c_uint64, Structure, POINTER, byref, create_string_buffer

# blake3_chunk_state 구조체 정의
class Blake3ChunkState(Structure):
    _fields_ = [
        ("cv", c_uint32 * 8),          # uint32_t cv[8]
        ("chunk_counter", c_uint64),    # uint64_t chunk_counter
        ("buf", c_uint8 * 64),         # uint8_t buf[64]
        ("buf_len", c_uint8),          # uint8_t buf_len
        ("blocks_compressed", c_uint8), # uint8_t blocks_compressed
        ("flags", c_uint8)             # uint8_t flags
    ]

# blake3_hasher 구조체 정의
class Blake3Hasher(Structure):
    _fields_ = [
        ("key", c_uint32 * 8),         # uint32_t key[8]
        ("chunk", Blake3ChunkState),   # blake3_chunk_state chunk
        ("cv_stack_len", c_uint8),     # uint8_t cv_stack_len
        ("cv_stack", c_uint32 * (54 * 8))  # uint32_t cv_stack[54 * 8]
    ]

# 라이브러리 경로 찾기
def find_library_path():
    """Blake3 라이브러리 파일 경로를 찾습니다."""
    # 상대 경로 계산
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
    
    # Windows에서는 .dll, Linux/macOS에서는 .so 또는 .dylib
    if os.name == 'nt':  # Windows
        lib_extensions = ['.dll']
        lib_name = 'blake3'
    else:  # Linux/macOS
        lib_extensions = ['.so', '.dylib']
        lib_name = 'libblake3'
    
    # 가능한 경로들
    possible_paths = []
    build_dirs = ['build', 'build/Debug', 'build/Release']
    
    for build_dir in build_dirs:
        for ext in lib_extensions:
            possible_paths.append(os.path.join(project_root, 'core', build_dir, lib_name + ext))
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    raise FileNotFoundError(f"Blake3 라이브러리 파일을 찾을 수 없습니다. 다음 경로를 확인하세요: {possible_paths}")

# 전역 인스턴스
try:
    _blake3_lib = ctypes.CDLL(find_library_path())
    
    # 함수 프로토타입 정의
    _blake3_lib.blake3_hasher_init.argtypes = [POINTER(Blake3Hasher)]
    _blake3_lib.blake3_hasher_init.restype = None
    
    _blake3_lib.blake3_hasher_init_keyed.argtypes = [POINTER(Blake3Hasher), POINTER(c_uint8)]
    _blake3_lib.blake3_hasher_init_keyed.restype = None
    
    _blake3_lib.blake3_hasher_init_derive_key.argtypes = [POINTER(Blake3Hasher), ctypes.c_char_p]
    _blake3_lib.blake3_hasher_init_derive_key.restype = None
    
    _blake3_lib.blake3_hasher_update.argtypes = [POINTER(Blake3Hasher), c_void_p, c_size_t]
    _blake3_lib.blake3_hasher_update.restype = None
    
    _blake3_lib.blake3_hasher_finalize.argtypes = [POINTER(Blake3Hasher), c_void_p, c_size_t]
    _blake3_lib.blake3_hasher_finalize.restype = None
    
    _blake3_lib.blake3.argtypes = [c_void_p, c_size_t, c_void_p, c_size_t]
    _blake3_lib.blake3.restype = None

except (FileNotFoundError, OSError) as e:
    print(f"경고: Blake3 라이브러리를 로드할 수 없습니다: {e}")
    print("라이브러리를 빌드했는지 확인하세요. (CMake를 사용해 blake3.dll 생성)")
    _blake3_lib = None

def blake3_hash(data, digest_size=32):
    """
    데이터의 Blake3 해시를 계산합니다.
    
    Args:
        data: 해시할 바이트 데이터 (bytes 또는 bytearray)
        digest_size: 해시 결과의 바이트 크기 (기본값: 32, 임의 크기 가능)
        
    Returns:
        Blake3 해시 값 (bytes)
    """
    if _blake3_lib is None:
        raise RuntimeError("Blake3 라이브러리가 로드되지 않았습니다.")
    
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("데이터는 bytes 또는 bytearray 타입이어야 합니다")
    
    if digest_size <= 0:
        raise ValueError("digest_size는 1 이상이어야 합니다")
    
    # Blake3 해시 계산
    digest = create_string_buffer(digest_size)
    data_ptr = ctypes.create_string_buffer(data)
    _blake3_lib.blake3(data_ptr, len(data), digest, digest_size)
    
    return bytes(digest)

def blake3_hash_keyed(data, key, digest_size=32):
    """
    키를 사용한 데이터의 Blake3 해시를 계산합니다 (MAC 용도).
    
    Args:
        data: 해시할 바이트 데이터 (bytes 또는 bytearray)
        key: 32바이트 키 (bytes)
        digest_size: 해시 결과의 바이트 크기 (기본값: 32)
        
    Returns:
        Blake3 해시 값 (bytes)
    """
    if _blake3_lib is None:
        raise RuntimeError("Blake3 라이브러리가 로드되지 않았습니다.")
    
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("데이터는 bytes 또는 bytearray 타입이어야 합니다")
    
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError("키는 32바이트 bytes 또는 bytearray여야 합니다")
    
    if digest_size <= 0:
        raise ValueError("digest_size는 1 이상이어야 합니다")
    
    # Blake3 해시어 초기화
    hasher = Blake3Hasher()
    key_array = (c_uint8 * 32)(*key)
    _blake3_lib.blake3_hasher_init_keyed(byref(hasher), key_array)
    
    # 데이터 업데이트
    data_ptr = ctypes.create_string_buffer(data)
    _blake3_lib.blake3_hasher_update(byref(hasher), data_ptr, len(data))
    
    # 해시 완료
    digest = create_string_buffer(digest_size)
    _blake3_lib.blake3_hasher_finalize(byref(hasher), digest, digest_size)
    
    return bytes(digest)

def blake3_derive_key(context, key_material, digest_size=32):
    """
    키 유도 함수를 사용한 Blake3 해시를 계산합니다.
    
    Args:
        context: 키 유도 컨텍스트 문자열 (str)
        key_material: 키 자료 (bytes 또는 bytearray)
        digest_size: 해시 결과의 바이트 크기 (기본값: 32)
        
    Returns:
        Blake3 해시 값 (bytes)
    """
    if _blake3_lib is None:
        raise RuntimeError("Blake3 라이브러리가 로드되지 않았습니다.")
    
    if not isinstance(context, str):
        raise TypeError("컨텍스트는 문자열이어야 합니다")
    
    if not isinstance(key_material, (bytes, bytearray)):
        raise TypeError("키 자료는 bytes 또는 bytearray 타입이어야 합니다")
    
    if digest_size <= 0:
        raise ValueError("digest_size는 1 이상이어야 합니다")
    
    # Blake3 해시어 초기화
    hasher = Blake3Hasher()
    context_bytes = context.encode('utf-8')
    _blake3_lib.blake3_hasher_init_derive_key(byref(hasher), context_bytes)
    
    # 키 자료 업데이트
    data_ptr = ctypes.create_string_buffer(key_material)
    _blake3_lib.blake3_hasher_update(byref(hasher), data_ptr, len(key_material))
    
    # 해시 완료
    digest = create_string_buffer(digest_size)
    _blake3_lib.blake3_hasher_finalize(byref(hasher), digest, digest_size)
    
    return bytes(digest)

def file_hash(file_path, digest_size=32, chunk_size=8192):
    """
    파일의 Blake3 해시를 계산합니다.
    
    Args:
        file_path: 해시할 파일 경로
        digest_size: 해시 결과의 바이트 크기 (기본값: 32)
        chunk_size: 한 번에 읽을 바이트 크기
        
    Returns:
        Blake3 해시 값 (bytes)
    """
    if _blake3_lib is None:
        raise RuntimeError("Blake3 라이브러리가 로드되지 않았습니다.")
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"파일이 존재하지 않습니다: {file_path}")
    
    # Blake3 해시어 초기화
    hasher = Blake3Hasher()
    _blake3_lib.blake3_hasher_init(byref(hasher))
    
    # 파일 청크별로 읽어서 해시 업데이트
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            
            chunk_buffer = create_string_buffer(chunk)
            _blake3_lib.blake3_hasher_update(byref(hasher), chunk_buffer, len(chunk))
    
    # 해시 완료
    digest = create_string_buffer(digest_size)
    _blake3_lib.blake3_hasher_finalize(byref(hasher), digest, digest_size)
    
    return bytes(digest)

class Blake3Incremental:
    """
    점진적 Blake3 해시 계산을 위한 클래스
    """
    def __init__(self, key=None, context=None):
        if _blake3_lib is None:
            raise RuntimeError("Blake3 라이브러리가 로드되지 않았습니다.")
        
        self.hasher = Blake3Hasher()
        
        if key is not None:
            if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
                raise ValueError("키는 32바이트 bytes 또는 bytearray여야 합니다")
            key_array = (c_uint8 * 32)(*key)
            _blake3_lib.blake3_hasher_init_keyed(byref(self.hasher), key_array)
        elif context is not None:
            if not isinstance(context, str):
                raise TypeError("컨텍스트는 문자열이어야 합니다")
            context_bytes = context.encode('utf-8')
            _blake3_lib.blake3_hasher_init_derive_key(byref(self.hasher), context_bytes)
        else:
            _blake3_lib.blake3_hasher_init(byref(self.hasher))
    
    def update(self, data):
        """해시에 데이터를 추가합니다."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("데이터는 bytes 또는 bytearray 타입이어야 합니다")
        
        data_ptr = ctypes.create_string_buffer(data)
        _blake3_lib.blake3_hasher_update(byref(self.hasher), data_ptr, len(data))
    
    def finalize(self, digest_size=32):
        """최종 해시 값을 계산합니다."""
        if digest_size <= 0:
            raise ValueError("digest_size는 1 이상이어야 합니다")
        
        digest = create_string_buffer(digest_size)
        _blake3_lib.blake3_hasher_finalize(byref(self.hasher), digest, digest_size)
        return bytes(digest)
    
    def hexdigest(self, digest_size=32):
        """최종 해시 값을 16진수 문자열로 반환합니다."""
        return self.finalize(digest_size).hex()