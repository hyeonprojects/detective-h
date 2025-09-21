# CLI Module - 바이러스 추적기

Detective-H 프로젝트의 명령줄 인터페이스 모듈입니다. Python 기반으로 구현되어 있으며, Blake3 해시를 활용한 바이러스 감지 및 분석 기능을 제공합니다.

## 📁 디렉토리 구조

```
cli/
├── README.md              # 이 문서
├── setup.py               # Python 패키지 설정
└── virus_tracker/         # 메인 패키지
    ├── __init__.py        # 패키지 초기화
    ├── __main__.py        # CLI 진입점 및 명령어 파싱
    ├── blake3_wrapper.py  # Blake3 C 라이브러리 Python 바인딩
    ├── virus_analyzer.py  # 바이러스 분석 엔진 및 데이터베이스 관리
    └── virus_comparator.py # 파일 비교 및 유사도 계산
```

## 🚀 설치 및 실행

### 개발 모드 설치
```bash
cd cli
pip install -e .
```

### CLI 명령어 실행
```bash
# 도움말 확인
virus-tracker --help

# 또는 Python 모듈로 실행
python -m virus_tracker --help
```

## 📋 주요 기능

### 1. 바이러스 분석 (`analyze`)
파일이 알려진 바이러스와 유사한지 분석합니다.

```bash
virus-tracker analyze suspicious_file.exe --threshold 0.85
```

**옵션:**
- `--threshold`: 유사도 임계값 (0-1, 기본값: 0.85)
- `--db`: 사용자 정의 바이러스 데이터베이스 경로

### 2. 바이러스 샘플 추가 (`add`)
새로운 바이러스 샘플을 데이터베이스에 등록합니다.

```bash
virus-tracker add malware.exe --name "트로이목마_v1" --type "트로이목마"
```

**옵션:**
- `--name`: 바이러스 이름 (미지정 시 파일 이름 사용)
- `--type`: 바이러스 유형
- `--description`: 바이러스 설명
- `--db`: 사용자 정의 바이러스 데이터베이스 경로

### 3. 등록된 바이러스 목록 (`list`)
데이터베이스에 등록된 모든 바이러스 샘플을 조회합니다.

```bash
virus-tracker list
```

### 4. Blake3 해시 계산 (`hash`)
파일의 Blake3 해시 값을 계산합니다.

```bash
virus-tracker hash document.pdf --size 32
```

**옵션:**
- `--size`: 해시 크기 (바이트 단위, 기본값: 32)

### 5. 파일 비교 (`compare`)
두 파일 간의 유사도를 해밍 거리로 계산합니다.

```bash
virus-tracker compare file1.exe file2.exe
```

## 🏗️ 아키텍처

### Blake3 해시 엔진
- **고성능**: Blake2b보다 빠른 처리 속도
- **병렬 처리**: 내재적 멀티코어 지원
- **유연한 출력**: 임의 크기 해시 생성 (기본: 32바이트)

### 바이러스 데이터베이스
- **JSON 메타데이터**: 구조화된 바이러스 정보 저장
- **자동 해시 캐싱**: 빠른 비교를 위한 해시 사전 계산
- **격리된 저장소**: `data/virus_db/` 디렉토리에 안전하게 보관

### 유사도 알고리즘
- **해밍 거리**: 비트 단위 차이 계산
- **정규화된 유사도**: 0~1 범위의 백분율 결과
- **임계값 기반**: 사용자 정의 감지 민감도

## 🔧 기술 세부사항

### Blake3 Python 바인딩
- **ctypes 활용**: C 라이브러리와 seamless 통합
- **크로스 플랫폼**: Windows(.dll), Linux(.so), macOS(.dylib) 지원
- **에러 처리**: 라이브러리 미설치 시 graceful degradation

### 데이터베이스 스키마
```json
{
  "virus_name": {
    "added_date": "2025-02-02T10:30:00",
    "original_path": "/path/to/original/file",
    "hash": "blake3_hash_hex_string",
    "size": 1024,
    "type": "트로이목마",
    "description": "사용자 정의 설명"
  }
}
```

## 🛠️ 개발 가이드

### 의존성 요구사항
- **Python**: 3.6 이상
- **Blake3 C 라이브러리**: `core/clang_module/` 빌드 필요
- **표준 라이브러리**: ctypes, json, os, datetime

### 빌드 전제조건
Blake3 C 라이브러리가 먼저 빌드되어야 합니다:

```bash
cd ../core/clang_module
mkdir build && cd build
cmake ..
cmake --build .
```

### 테스트 실행
현재 수동 테스트로 진행됩니다:

```bash
# 기본 기능 테스트
virus-tracker hash README.md
virus-tracker compare README.md setup.py
```

## 🔒 보안 고려사항

- **샘플 격리**: 바이러스 파일은 전용 디렉토리에 격리 보관
- **해시 기반**: 실제 파일 실행 없이 해시로만 비교
- **권한 관리**: 최소 권한으로 파일 접근
- **입력 검증**: 파일 존재 및 타입 검증

## 📝 향후 계획

- **성능 최적화**: 대용량 파일 처리 개선
- **GUI 인터페이스**: 웹 기반 관리 도구
- **자동 업데이트**: 바이러스 시그니처 자동 갱신
- **ML 통합**: 머신러닝 기반 탐지 엔진

## 🤝 기여 방법

1. 이슈 리포트: 버그나 개선사항 제안
2. 코드 기여: Pull Request 제출
3. 문서 개선: README 및 주석 보완
4. 테스트 케이스: 추가 테스트 시나리오 작성