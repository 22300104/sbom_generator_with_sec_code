# test_rag_page_extraction.py


"""
RAG 검색 시 페이지 정보 추출 문제 진단
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag.simple_rag import SimpleRAG
import json

# .env 파일 로드
from dotenv import load_dotenv
load_dotenv()
def test_rag_search_and_metadata():
    """RAG 검색과 메타데이터 추출 테스트"""
    print("="*80)
    print("🔍 RAG 검색 및 메타데이터 추출 테스트")
    print("="*80)
    
    # SimpleRAG 초기화
    rag = SimpleRAG()
    
    # 테스트 쿼리들
    test_queries = [
        "SQL 인젝션",
        "XSS 공격",
        "경로 조작",
        "안전하지 않은 역직렬화"
    ]
    
    for query in test_queries:
        print(f"\n📌 테스트 쿼리: '{query}'")
        print("-"*60)
        
        # search_similar 호출
        results = rag.search_similar(query, top_k=3)
        
        print(f"검색 결과 수: {len(results.get('documents', [[]])[0])}개")
        
        # 메타데이터 상세 확인
        if results.get('metadatas') and results['metadatas'][0]:
            for i, metadata in enumerate(results['metadatas'][0][:3], 1):
                print(f"\n  [결과 {i}]")
                print(f"  전체 메타데이터 키: {list(metadata.keys())}")
                
                # 각 키와 값 출력
                for key, value in metadata.items():
                    print(f"    • {key}: {value} (타입: {type(value).__name__})")
                
                # 페이지 정보 특별 확인
                page = metadata.get('page')
                page_start = metadata.get('page_start')
                page_end = metadata.get('page_end')
                
                print(f"\n  📄 페이지 정보 추출:")
                print(f"    - page: {page} (타입: {type(page).__name__})")
                print(f"    - page_start: {page_start} (타입: {type(page_start).__name__})")
                print(f"    - page_end: {page_end} (타입: {type(page_end).__name__})")
                
                # 페이지 범위 결정 로직 (simple_rag.py와 동일)
                if page_start and page_end and page_start != page_end:
                    page_info = f"{page_start}-{page_end}"
                else:
                    page_info = str(page) if page else str(page_start) if page_start else "?"
                
                print(f"    → 최종 페이지 정보: {page_info}")
        else:
            print("  ❌ 메타데이터가 없습니다")

def test_improved_llm_analyzer():
    """ImprovedSecurityAnalyzer의 _add_rag_evidence 테스트"""
    print("\n" + "="*80)
    print("🤖 ImprovedSecurityAnalyzer RAG 증거 추가 테스트")
    print("="*80)
    
    from core.improved_llm_analyzer import ImprovedSecurityAnalyzer
    
    # 분석기 초기화
    analyzer = ImprovedSecurityAnalyzer(use_claude=False)
    
    # 테스트 취약점
    test_vulnerabilities = [
        {'type': 'SQL Injection', 'description': 'SQL 인젝션 취약점'},
        {'type': 'XSS', 'description': 'Cross-Site Scripting 취약점'},
        {'type': 'Path Traversal', 'description': '경로 조작 취약점'}
    ]
    
    # RAG 증거 추가
    vulns_with_evidence = analyzer._add_rag_evidence(test_vulnerabilities)
    
    for vuln in vulns_with_evidence:
        print(f"\n📌 취약점: {vuln['type']}")
        
        if 'evidence' in vuln:
            evidence = vuln['evidence']
            print("  ✅ RAG 증거 발견:")
            print(f"    - page: {evidence.get('page')}")
            print(f"    - page_start: {evidence.get('page_start')}")
            print(f"    - page_end: {evidence.get('page_end')}")
            print(f"    - collection: {evidence.get('collection')}")
            
            # 실제 값 타입 확인
            for key in ['page', 'page_start', 'page_end']:
                if key in evidence:
                    value = evidence[key]
                    print(f"    - {key} 타입: {type(value).__name__}, 값: {value}")
        else:
            print("  ❌ RAG 증거 없음")

def debug_metadata_extraction():
    """메타데이터 추출 과정 상세 디버깅"""
    print("\n" + "="*80)
    print("🐛 메타데이터 추출 과정 디버깅")
    print("="*80)
    
    import chromadb
    from pathlib import Path
    
    # ChromaDB 직접 접근
    client = chromadb.PersistentClient(path="data/vector_db")
    collection = client.get_collection("kisia_vulnerabilities")
    
    # 직접 쿼리
    query_text = "SQL 인젝션"
    results = collection.query(
        query_texts=[query_text],
        n_results=1
    )
    
    print(f"쿼리: '{query_text}'")
    print(f"\n1. ChromaDB 원본 결과:")
    print(f"   results.keys(): {results.keys()}")
    
    if results['metadatas'] and results['metadatas'][0]:
        metadata = results['metadatas'][0][0]
        print(f"\n2. 첫 번째 메타데이터:")
        print(f"   전체 내용: {json.dumps(metadata, indent=2, ensure_ascii=False)}")
        
        print(f"\n3. 페이지 관련 필드:")
        for key in metadata.keys():
            if 'page' in key.lower():
                value = metadata[key]
                print(f"   - {key}: {value} (타입: {type(value).__name__})")

if __name__ == "__main__":
    # 1. RAG 검색 테스트
    test_rag_search_and_metadata()
    
    # 2. ImprovedSecurityAnalyzer 테스트
    test_improved_llm_analyzer()
    
    # 3. 상세 디버깅
    debug_metadata_extraction()