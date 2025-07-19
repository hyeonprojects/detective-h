"""
바이러스 분석 모듈
"""
import os
import json
import datetime
from .virus_comparator import file_hash, hex_hash, compare_virus_with_hamming

class VirusAnalyzer:
    def __init__(self, virus_db_path=None):
        """
        바이러스 분석기 초기화
        
        Args:
            virus_db_path: 바이러스 데이터베이스 디렉토리 경로 (미지정 시 기본값 사용)
        """
        if virus_db_path is None:
            # 기본 경로 설정 (현재 스크립트 위치 기준)
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
            virus_db_path = os.path.join(project_root, 'data', 'virus_db')
        
        self.virus_db_path = virus_db_path
        self.virus_samples = {}  # 바이러스 샘플 정보 (이름:메타데이터)
        self.virus_hashes = {}   # 바이러스 해시 (이름:해시값)
        
        # DB 디렉토리가 없는 경우 생성
        if not os.path.exists(self.virus_db_path):
            os.makedirs(self.virus_db_path, exist_ok=True)
            print(f"새 바이러스 데이터베이스를 생성했습니다: {self.virus_db_path}")
        
        # 메타데이터 파일 경로
        self.metadata_file = os.path.join(self.virus_db_path, 'metadata.json')
        
        # 기존 메타데이터 로드
        self._load_metadata()
    
    def _load_metadata(self):
        """바이러스 데이터베이스 메타데이터 로드"""
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    self.virus_samples = json.load(f)
                print(f"{len(self.virus_samples)}개의 바이러스 샘플 메타데이터를 로드했습니다.")
            except (json.JSONDecodeError, IOError) as e:
                print(f"메타데이터 파일 로드 중 오류 발생: {e}")
                self.virus_samples = {}
        
        # 해시값 계산/캐싱
        for virus_name, metadata in self.virus_samples.items():
            virus_path = os.path.join(self.virus_db_path, virus_name)
            if os.path.exists(virus_path):
                # 이미 저장된 해시가 있으면 사용
                if 'hash' in metadata:
                    self.virus_hashes[virus_name] = bytes.fromhex(metadata['hash'])
                else:
                    # 해시 계산
                    try:
                        hash_bytes = file_hash(virus_path)
                        self.virus_hashes[virus_name] = hash_bytes
                        # 메타데이터 업데이트
                        metadata['hash'] = hash_bytes.hex()
                    except Exception as e:
                        print(f"바이러스 파일 '{virus_name}' 해시 계산 중 오류: {e}")
    
    def _save_metadata(self):
        """바이러스 데이터베이스 메타데이터 저장"""
        try:
            with open(self.metadata_file, 'w', encoding='utf-8') as f:
                json.dump(self.virus_samples, f, indent=2, ensure_ascii=False)
            return True
        except IOError as e:
            print(f"메타데이터 저장 중 오류 발생: {e}")
            return False
    
    def add_virus_sample(self, file_path, virus_name=None, metadata=None):
        """
        바이러스 샘플을 데이터베이스에 추가
        
        Args:
            file_path: 바이러스 파일 경로
            virus_name: 바이러스 이름 (미지정 시 파일 이름 사용)
            metadata: 추가 메타데이터 (딕셔너리)
            
        Returns:
            성공 여부 (Boolean)
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"파일이 존재하지 않습니다: {file_path}")
        
        # 이름이 지정되지 않은 경우 파일 이름 사용
        if virus_name is None:
            virus_name = os.path.basename(file_path)
        
        # 이미 같은 이름의 바이러스가 있는 경우 타임스탬프 추가
        if virus_name in self.virus_samples:
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            virus_name = f"{virus_name}_{timestamp}"
        
        # 바이러스 DB에 파일 복사
        dest_path = os.path.join(self.virus_db_path, virus_name)
        try:
            with open(file_path, 'rb') as src, open(dest_path, 'wb') as dest:
                dest.write(src.read())
        except IOError as e:
            print(f"파일 복사 중 오류 발생: {e}")
            return False
        
        # 해시 계산
        try:
            hash_bytes = file_hash(dest_path)
            hash_hex = hash_bytes.hex()
        except Exception as e:
            print(f"해시 계산 중 오류 발생: {e}")
            return False
        
        # 메타데이터 생성
        sample_metadata = {
            'added_date': datetime.datetime.now().isoformat(),
            'original_path': file_path,
            'hash': hash_hex,
            'size': os.path.getsize(file_path)
        }
        
        # 추가 메타데이터가 있으면 병합
        if metadata:
            sample_metadata.update(metadata)
        
        # 샘플 정보 저장
        self.virus_samples[virus_name] = sample_metadata
        self.virus_hashes[virus_name] = hash_bytes
        
        # 메타데이터 파일 업데이트
        self._save_metadata()
        
        print(f"바이러스 샘플 '{virus_name}'이(가) 데이터베이스에 추가되었습니다.")
        return True
    
    def analyze_file(self, file_path, similarity_threshold=0.85):
        """
        파일이 알려진 바이러스와 유사한지 분석
        
        Args:
            file_path: 분석할 파일 경로
            similarity_threshold: 유사도 임계값 (0~1, 이 값 이상이면 보고)
            
        Returns:
            (일치한 바이러스 이름, 유사도) 튜플의 리스트
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"파일이 존재하지 않습니다: {file_path}")
        
        # DB에 바이러스가 없으면 빈 결과 반환
        if not self.virus_hashes:
            print("바이러스 데이터베이스가 비어있습니다.")
            return []
        
        # 분석할 파일의 해시 계산
        target_hash = file_hash(file_path)
        results = []
        
        # 각 바이러스 샘플과 비교
        for virus_name, virus_hash in self.virus_hashes.items():
            # 해밍 거리 기반 유사도 계산
            distance, similarity = compare_virus_with_hamming(
                file_path, 
                os.path.join(self.virus_db_path, virus_name)
            )
            
            if similarity >= similarity_threshold:
                results.append((virus_name, similarity))
        
        # 유사도 기준으로 내림차순 정렬
        results.sort(key=lambda x: x[1], reverse=True)
        return results
    
    def get_virus_info(self, virus_name):
        """
        바이러스 샘플의 상세 정보 조회
        
        Args:
            virus_name: 바이러스 이름
            
        Returns:
            바이러스 정보 딕셔너리 (없으면 None)
        """
        return self.virus_samples.get(virus_name)
    
    def get_all_viruses(self):
        """
        모든 바이러스 샘플 목록 반환
        
        Returns:
            바이러스 이름 리스트
        """
        return list(self.virus_samples.keys())
