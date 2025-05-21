"""
바이러스 추적기 명령줄 인터페이스
"""
import os
import sys
import argparse
from .virus_analyzer import VirusAnalyzer
from .virus_comparator import hex_hash

def main():
    parser = argparse.ArgumentParser(description='바이러스 분석 및 추적 도구')
    subparsers = parser.add_subparsers(dest='command', help='실행할 명령')
    
    # analyze 명령
    analyze_parser = subparsers.add_parser('analyze', help='파일 분석')
    analyze_parser.add_argument('file', help='분석할 파일 경로')
    analyze_parser.add_argument('--db', help='바이러스 데이터베이스 경로')
    analyze_parser.add_argument('--threshold', type=float, default=0.85, 
                               help='유사도 임계값 (0-1 사이, 기본값: 0.85)')
    
    # add 명령
    add_parser = subparsers.add_parser('add', help='바이러스 샘플 추가')
    add_parser.add_argument('file', help='추가할 바이러스 파일 경로')
    add_parser.add_argument('--name', help='바이러스 이름 (미지정 시 파일 이름 사용)')
    add_parser.add_argument('--db', help='바이러스 데이터베이스 경로')
    add_parser.add_argument('--type', help='바이러스 유형')
    add_parser.add_argument('--description', help='바이러스 설명')
    
    # list 명령
    list_parser = subparsers.add_parser('list', help='등록된 바이러스 목록 조회')
    list_parser.add_argument('--db', help='바이러스 데이터베이스 경로')
    
    # hash 명령
    hash_parser = subparsers.add_parser('hash', help='파일의 Blake2b 해시 계산')
    hash_parser.add_argument('file', help='해시를 계산할 파일 경로')
    hash_parser.add_argument('--size', type=int, default=64, 
                            help='해시 크기 (바이트 단위, 기본값: 64)')
    
    # compare 명령
    compare_parser = subparsers.add_parser('compare', help='두 파일 비교')
    compare_parser.add_argument('file1', help='첫 번째 파일 경로')
    compare_parser.add_argument('file2', help='두 번째 파일 경로')
    
    # 명령행 인수 파싱
    args = parser.parse_args()
    
    # 명령이 지정되지 않은 경우 도움말 출력
    if not args.command:
        parser.print_help()
        return
    
    try:
        # 바이러스 분석기 초기화
        db_path = args.db if hasattr(args, 'db') and args.db else None
        analyzer = VirusAnalyzer(db_path)
        
        # 명령 처리
        if args.command == 'analyze':
            results = analyzer.analyze_file(args.file, args.threshold)
            
            if not results:
                print(f"파일 '{args.file}'은(는) 알려진 바이러스와 일치하지 않습니다.")
            else:
                print(f"파일 '{args.file}'의 바이러스 분석 결과:")
                for virus_name, similarity in results:
                    print(f"- {virus_name}: {similarity:.2%} 일치")
        
        elif args.command == 'add':
            metadata = {}
            if hasattr(args, 'type') and args.type:
                metadata['type'] = args.type
            if hasattr(args, 'description') and args.description:
                metadata['description'] = args.description
            
            analyzer.add_virus_sample(args.file, args.name, metadata)
        
        elif args.command == 'list':
            viruses = analyzer.get_all_viruses()
            
            if not viruses:
                print("등록된 바이러스 샘플이 없습니다.")
            else:
                print(f"등록된 바이러스 샘플 목록 ({len(viruses)}개):")
                for virus in viruses:
                    info = analyzer.get_virus_info(virus)
                    added_date = info.get('added_date', '날짜 정보 없음')
                    virus_type = info.get('type', '유형 정보 없음')
                    print(f"- {virus} (유형: {virus_type}, 추가일: {added_date})")
        
        elif args.command == 'hash':
            hash_val = hex_hash(args.file, args.size)
            print(f"파일 '{args.file}'의 Blake2b 해시 (크기: {args.size} 바이트):")
            print(hash_val)
        
        elif args.command == 'compare':
            from .virus_comparator import compare_virus_with_hamming
            distance, similarity = compare_virus_with_hamming(args.file1, args.file2)
            print(f"파일 비교 결과:")
            print(f"- 파일1: {args.file1}")
            print(f"- 파일2: {args.file2}")
            print(f"- 해밍 거리: {distance}")
            print(f"- 유사도: {similarity:.2%}")
            
            if similarity >= 0.95:
                conclusion = "매우 유사함 (동일 바이러스로 판단)"
            elif similarity >= 0.85:
                conclusion = "상당히 유사함 (동일 바이러스의 변종일 가능성 높음)"
            elif similarity >= 0.70:
                conclusion = "부분적으로 유사함 (관련 바이러스일 가능성 있음)"
            else:
                conclusion = "유사성 낮음 (다른 바이러스로 판단)"
            
            print(f"- 결론: {conclusion}")
    
    except Exception as e:
        print(f"오류 발생: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
