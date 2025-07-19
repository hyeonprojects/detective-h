"""
바이러스 파일 비교 모듈
Blake2b 해시를 이용해 바이러스 파일의 유사도를 계산합니다.
"""
import os
import binascii
from .blake2b_wrapper import file_hash

def compare_virus_files(file_path1, file_path2, digest_size=64):
    """
    두 바이러스 파일을 비교하여 유사도를 계산합니다.
    
    Args:
        file_path1: 첫 번째 바이러스 파일 경로
        file_path2: 두 번째 바이러스 파일 경로
        digest_size: 해시 결과의 바이트 크기 (최대 64)
        
    Returns:
        (일치 여부, 유사도) 튜플
    """
    # 파일 존재 확인
    for path in [file_path1, file_path2]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"파일이 존재하지 않습니다: {path}")
    
    # 파일 해시 계산
    hash1 = file_hash(file_path1, digest_size)
    hash2 = file_hash(file_path2, digest_size)
    
    # 완전히 일치하는지 확인
    if hash1 == hash2:
        return True, 1.0
    
    # 해시 바이트 단위로 유사도 계산
    matching_bytes = sum(b1 == b2 for b1, b2 in zip(hash1, hash2))
    similarity = matching_bytes / len(hash1)
    
    return False, similarity

def hex_hash(file_path, digest_size=64):
    """
    파일의 Blake2b 해시를 16진수 문자열로 반환합니다.
    
    Args:
        file_path: 해시할 파일 경로
        digest_size: 해시 결과의 바이트 크기 (최대 64)
        
    Returns:
        16진수 문자열로 표현된 해시 값
    """
    hash_bytes = file_hash(file_path, digest_size)
    return binascii.hexlify(hash_bytes).decode('ascii')

def hamming_distance(bytes1, bytes2):
    """
    두 바이트 시퀀스 간의 해밍 거리를 계산합니다.
    해밍 거리는 같은 위치에서 서로 다른 비트의 개수입니다.
    
    Args:
        bytes1: 첫 번째 바이트 시퀀스
        bytes2: 두 번째 바이트 시퀀스
        
    Returns:
        해밍 거리 (다른 비트의 개수)
    """
    if len(bytes1) != len(bytes2):
        raise ValueError("입력 바이트 시퀀스의 길이가 다릅니다.")
    
    # XOR 연산으로 다른 비트 찾기
    xor_result = bytearray(a ^ b for a, b in zip(bytes1, bytes2))
    
    # 1인 비트 개수 세기
    bit_count = 0
    for byte in xor_result:
        # 각 바이트 내의 1 비트 개수 세기
        while byte:
            bit_count += byte & 1
            byte >>= 1
    
    return bit_count

def compare_virus_with_hamming(file_path1, file_path2, digest_size=64):
    """
    두 바이러스 파일의 해시값 간 해밍 거리를 이용한 유사도를 계산합니다.
    해밍 거리가 작을수록 유사도가 높습니다.
    
    Args:
        file_path1: 첫 번째 바이러스 파일 경로
        file_path2: 두 번째 바이러스 파일 경로
        digest_size: 해시 결과의 바이트 크기 (최대 64)
        
    Returns:
        (해밍 거리, 정규화된 유사도) 튜플
        유사도는 0~1 사이 값으로, 1에 가까울수록 유사도가 높음
    """
    # 파일 해시 계산
    hash1 = file_hash(file_path1, digest_size)
    hash2 = file_hash(file_path2, digest_size)
    
    # 해밍 거리 계산
    distance = hamming_distance(hash1, hash2)
    
    # 정규화된 유사도 계산 (해밍 거리의 최대값은 비트 수)
    total_bits = len(hash1) * 8
    similarity = 1.0 - (distance / total_bits)
    
    return distance, similarity
