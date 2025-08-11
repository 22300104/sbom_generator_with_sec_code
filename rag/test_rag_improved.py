"""
개선된 RAG 시스템 테스트
"""
import time

# 상대 import 사용 (패키지로 실행할 때)
try:
    from .simple_rag import SimpleRAG
except ImportError:
    # 직접 실행할 때
    from simple_rag import SimpleRAG

def test_basic():
    """기본 테스트"""
    print("\n🧪 RAG 시스템 기본 테스트")
    print("=" * 70)
    
    try:
        rag = SimpleRAG()
        
        # DB 상태 확인
        stats = rag.get_stats()
        print(f"📊 벡터 DB 상태:")
        print(f"   - 총 문서 수: {stats['total_documents']}")
        print(f"   - 컬렉션명: {stats['collection_name']}")
        print()
        
        # 테스트 질문들
        test_questions = [
            "SQL 인젝션이란 무엇이고 어떻게 방어하나요?",
            "Python에서 안전한 패스워드 저장 방법은?",
            "XSS 공격을 방지하는 방법을 알려주세요",
            "LDAP 인젝션은 무엇인가요?",
            "파일 업로드 시 주의사항은?",
        ]
        
        for i, question in enumerate(test_questions, 1):
            print(f"\n{'='*70}")
            print(f"질문 {i}: {question}")
            print("-" * 70)
            
            start_time = time.time()
            answer = rag.ask(question)
            elapsed_time = time.time() - start_time
            
            print(f"답변:\n{answer}")
            print(f"\n⏱️ 응답 시간: {elapsed_time:.2f}초")
            
            if i < len(test_questions):
                time.sleep(1)  # API 제한 방지
        
    except Exception as e:
        print(f"❌ 오류 발생: {e}")

def test_search_quality():
    """검색 품질 상세 테스트"""
    print("\n🔍 검색 품질 상세 테스트")
    print("=" * 70)
    
    try:
        rag = SimpleRAG()
        
        test_queries = [
            ("SQL", "SQL 관련 내용"),
            ("패스워드", "패스워드/암호화 관련"),
            ("XSS", "크로스사이트 스크립트 관련"),
            ("파일", "파일 처리 관련"),
            ("입력값 검증", "입력 검증 관련"),
        ]
        
        for query, description in test_queries:
            print(f"\n검색어: '{query}' ({description})")
            print("-" * 40)
            
            results = rag.search_similar(query, top_k=3)
            
            if results['documents'][0]:
                for j, doc in enumerate(results['documents'][0], 1):
                    # 문서 미리보기 (처음 200자)
                    preview = doc[:200].replace('\n', ' ')
                    if len(doc) > 200:
                        preview += "..."
                    
                    # 메타데이터 확인
                    metadata = results['metadatas'][0][j-1] if results['metadatas'] else {}
                    
                    print(f"\n  [{j}] 페이지 {metadata.get('page', '?')}, 타입: {metadata.get('type', '?')}")
                    print(f"      {preview}")
            else:
                print("  검색 결과 없음")
    
    except Exception as e:
        print(f"❌ 오류 발생: {e}")

def main():
    print("\n" + "="*70)
    print("     Python 시큐어코딩 가이드 RAG 시스템 테스트")
    print("="*70)
    
    while True:
        print("\n테스트 모드 선택:")
        print("1. 기본 Q&A 테스트")
        print("2. 검색 품질 상세 테스트")
        print("3. 종료")
        
        choice = input("\n선택 (1-3): ").strip()
        
        if choice == '1':
            test_basic()
        elif choice == '2':
            test_search_quality()
        elif choice == '3':
            print("\n👋 테스트를 종료합니다.")
            break
        else:
            print("⚠️ 올바른 번호를 선택해주세요.")

if __name__ == "__main__":
    main()