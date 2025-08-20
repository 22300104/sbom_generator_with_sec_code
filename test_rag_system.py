import sys
from rag.improved_rag_search import ImprovedRAGSearch

def run_test():
    """
    RAG 시스템의 핵심 검색 기능을 테스트합니다.
    - 특정 취약점 유형에 대해 KISIA 가이드라인 근거를 제대로 찾아오는지 확인합니다.
    - 추출된 내용의 일부를 출력하여 데이터가 올바른지 검증합니다.
    """
    print("="*60)
    print("🧪 RAG 시스템 테스트를 시작합니다...")
    print("="*60)

    # 테스트할 주요 취약점 유형 목록
    # LLM이 생성할만한 다양한 표현을 테스트해볼 수 있습니다.
    test_vulnerabilities = [
        "Hardcoded Secret",
        "SQL Injection",
        "Insecure Session Management",
        "Cross-Site Scripting",
        "Command Injection",
        "Weak Authentication", # '취약한 패스워드 허용'과 매칭되어야 함
    ]

    try:
        # RAG 검색 시스템 초기화
        searcher = ImprovedRAGSearch()
        print("\n✅ RAG 검색 시스템이 성공적으로 초기화되었습니다.\n")
    except Exception as e:
        print(f"❌ RAG 시스템 초기화 실패: {e}")
        print("   'data/vector_db_v2' 경로에 ChromaDB 파일이 있는지 확인해주세요.")
        print("   '05_build_improved_vector_db.py' 스크립트를 먼저 실행해야 할 수 있습니다.")
        return

    for vuln_type in test_vulnerabilities:
        print(f"\n--- 🗣️ 검색어: '{vuln_type}' ---")
        
        try:
            # RAG 검색 실행
            results = searcher.search_vulnerability_evidence(vuln_type)

            if results and results.get('vulnerability'):
                metadata = results['vulnerability'].get('metadata', {})
                content = results['vulnerability'].get('content', '')
                
                # 페이지 번호 추출
                start_page = metadata.get('start_page', 'N/A')
                end_page = metadata.get('end_page', 'N/A')
                page_info = f"{start_page}-{end_page}" if start_page != end_page else str(start_page)

                print(f"✅ [매칭 성공] '{metadata.get('korean_name', '이름 없음')}'")
                print(f"   📄 페이지: {page_info}")
                
                # 내용 일부 출력 (검증용)
                print("\n   [내용 일부]")
                print(f"   {content[:200].replace('\n', ' ')}...")
                
                # 코드 예제 유무 확인
                unsafe_count = len(results.get('unsafe_codes', []))
                safe_count = len(results.get('safe_codes', []))
                print(f"\n   [코드 예제]")
                if unsafe_count > 0:
                    print(f"   - ❌ 안전하지 않은 코드: {unsafe_count}개 발견")
                    # 첫 번째 코드 일부 출력
                    print(f"     ㄴ {results['unsafe_codes'][0]['code'][:100].replace('\n', ' ')}...")
                else:
                    print("   - ❌ 안전하지 않은 코드: 없음")

                if safe_count > 0:
                    print(f"   - ✅ 안전한 코드: {safe_count}개 발견")
                    print(f"     ㄴ {results['safe_codes'][0]['code'][:100].replace('\n', ' ')}...")
                else:
                    print("   - ✅ 안전한 코드: 없음")

            else:
                print("❌ [매칭 실패] 해당 취약점에 대한 가이드라인을 찾을 수 없습니다.")
        
        except Exception as e:
            print(f"❌ 검색 중 오류 발생: {e}")

    print("\n" + "="*60)
    print("✅ 테스트가 종료되었습니다.")
    print("="*60)

if __name__ == "__main__":
    # 프로젝트 루트 디렉터리를 경로에 추가
    sys.path.append('.')
    run_test()