# test_rag_improvements.py
"""
RAG 개선 사항 테스트
- 페이지 번호 정확성
- 취약점 타입 매핑
- 관련성 검증
"""
# .env 파일 로드
from dotenv import load_dotenv
load_dotenv()
import os
import sys
from pathlib import Path

# 프로젝트 루트 경로 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.improved_llm_analyzer import ImprovedSecurityAnalyzer
from rag.simple_rag import SimpleRAG
from rag.vulnerability_type_mapper import VulnerabilityTypeMapper
import json

def test_page_info_extraction():
    """페이지 정보 추출 테스트"""
    print("\n" + "="*80)
    print("📄 테스트 1: 페이지 정보 추출")
    print("="*80)
    
    rag = SimpleRAG()
    
    # 다양한 검색어로 테스트
    test_queries = [
        "SQL 인젝션 방어",
        "하드코딩된 비밀번호",
        "환경변수 사용",
        "XSS 방어",
        "파라미터 바인딩"
    ]
    
    for query in test_queries:
        print(f"\n🔍 검색어: {query}")
        results = rag.search_similar(query, top_k=3)
        
        if results['metadatas'] and results['metadatas'][0]:
            for i, metadata in enumerate(results['metadatas'][0][:2], 1):
                print(f"\n  결과 {i}:")
                
                # 페이지 정보 확인
                page_start = metadata.get('page_start', 'None')
                page_end = metadata.get('page_end', 'None')
                page = metadata.get('page', 'None')
                
                print(f"    - page_start: {page_start} (타입: {type(page_start).__name__})")
                print(f"    - page_end: {page_end} (타입: {type(page_end).__name__})")
                print(f"    - page: {page} (타입: {type(page).__name__})")
                
                # 페이지 범위 계산
                if page_start and page_end and page_start != 'None' and page_end != 'None':
                    if page_start == page_end:
                        page_info = str(page_start)
                    else:
                        page_info = f"{page_start}-{page_end}"
                    print(f"    ✅ 계산된 페이지: {page_info}")
                else:
                    print(f"    ❌ 페이지 정보 없음")
                
                # 기타 메타데이터
                if 'vulnerability_types' in metadata:
                    print(f"    - 취약점 타입: {metadata['vulnerability_types']}")
                if 'title' in metadata:
                    print(f"    - 제목: {metadata['title']}")


def test_vulnerability_type_mapping():
    """취약점 타입 매핑 테스트"""
    print("\n" + "="*80)
    print("🔄 테스트 2: 취약점 타입 매핑")
    print("="*80)
    
    mapper = VulnerabilityTypeMapper()
    
    # AI가 생성할 수 있는 다양한 취약점 타입
    test_types = [
        "Hardcoded Secret",
        "Hardcoded Password",
        "SQL Injection",
        "Command Injection",
        "XSS",
        "Cross-Site Scripting",
        "Path Traversal",
        "Insecure Deserialization",
        "Weak Cryptography",
        "Missing Authentication"
    ]
    
    for vuln_type in test_types:
        standard_type = mapper.normalize_vuln_type(vuln_type)
        search_query = mapper.get_search_query(standard_type, vuln_type)
        
        print(f"\n원본: {vuln_type}")
        print(f"  → 표준: {standard_type}")
        print(f"  → 검색 쿼리: {search_query}")


def test_hardcoded_secret_rag():
    """Hardcoded Secret 취약점에 대한 RAG 검색 테스트"""
    print("\n" + "="*80)
    print("🔐 테스트 3: Hardcoded Secret RAG 검색")
    print("="*80)
    
    # 테스트용 취약한 코드
    vulnerable_code = """
import os
from flask import Flask

app = Flask(__name__)
app.secret_key = 'hardcoded-secret-key-123'  # 취약점

DATABASE_PASSWORD = 'admin123'  # 취약점
API_KEY = 'sk-1234567890'  # 취약점

@app.route('/')
def index():
    return 'Hello World'
"""
    
    print("분석할 코드:")
    print(vulnerable_code)
    print("\n" + "-"*40)
    
    # AI 분석기 생성
    analyzer = ImprovedSecurityAnalyzer(use_claude=False)  # GPT 사용
    
    # 분석 실행
    print("\n🤖 AI 보안 분석 시작...")
    result = analyzer.analyze_security(vulnerable_code)
    
    if result.get('success') and result.get('vulnerabilities'):
        print(f"\n✅ {len(result['vulnerabilities'])}개 취약점 발견")
        
        # Hardcoded Secret 관련 취약점 찾기
        for vuln in result['vulnerabilities']:
            if 'secret' in vuln.get('type', '').lower() or 'hardcod' in vuln.get('type', '').lower():
                print(f"\n📌 취약점: {vuln['type']}")
                print(f"   심각도: {vuln.get('severity', 'UNKNOWN')}")
                
                # RAG 증거 확인
                if vuln.get('evidence'):
                    evidence = vuln['evidence']
                    print(f"\n   📚 RAG 증거:")
                    print(f"      - 페이지: {evidence.get('page', '?')}")
                    print(f"      - 페이지 시작: {evidence.get('page_start', '?')}")
                    print(f"      - 페이지 끝: {evidence.get('page_end', '?')}")
                    print(f"      - 섹션: {evidence.get('section_title', 'Unknown')}")
                    print(f"      - 문서 취약점 타입: {evidence.get('vulnerability_types', '')}")
                    
                    # 관련성 점수 확인
                    if 'relevance_score' in evidence:
                        score = evidence['relevance_score']
                        print(f"      - 관련성 점수: {score:.2f}")
                        if score < 0.3:
                            print(f"        ⚠️ 낮은 관련성!")
                    
                    # 내용 일부 출력
                    content = evidence.get('content', '')[:200]
                    print(f"      - 내용: {content}...")
                    
                    # 올바른 가이드라인인지 확인
                    if any(word in content.lower() for word in ['환경변수', 'environment', '.env', '설정']):
                        print(f"        ✅ 환경변수 관련 가이드라인 (적절함)")
                    elif any(word in content.lower() for word in ['rsa', '암호화 키', '2048']):
                        print(f"        ❌ RSA/암호화 키 관련 가이드라인 (부적절함)")
                    else:
                        print(f"        ❓ 기타 가이드라인")
                else:
                    print(f"   ❌ RAG 증거 없음")
    else:
        print("❌ 분석 실패 또는 취약점 없음")


def test_multiple_vulnerability_types():
    """여러 취약점 타입에 대한 RAG 매칭 테스트"""
    print("\n" + "="*80)
    print("🔍 테스트 4: 다중 취약점 RAG 매칭")
    print("="*80)
    
    # 여러 취약점이 있는 코드
    vulnerable_code = """
import sqlite3
import os
import pickle

def get_user(user_id):
    # SQL 인젝션 취약점
    conn = sqlite3.connect('db.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def execute_command(cmd):
    # 명령어 삽입 취약점
    os.system(cmd)

def load_data(data):
    # 안전하지 않은 역직렬화
    return pickle.loads(data)

# 하드코딩된 시크릿
API_KEY = "sk-1234567890"
"""
    
    print("분석할 코드 (여러 취약점 포함):")
    print(vulnerable_code[:300] + "...")
    print("\n" + "-"*40)
    
    # 분석 실행
    analyzer = ImprovedSecurityAnalyzer(use_claude=False)
    result = analyzer.analyze_security(vulnerable_code)
    
    if result.get('success') and result.get('vulnerabilities'):
        print(f"\n✅ {len(result['vulnerabilities'])}개 취약점 발견")
        
        # 각 취약점의 RAG 매칭 확인
        for i, vuln in enumerate(result['vulnerabilities'], 1):
            print(f"\n[{i}] {vuln.get('type', 'Unknown')}")
            
            if vuln.get('evidence'):
                evidence = vuln['evidence']
                page = evidence.get('page', '?')
                vuln_types = evidence.get('vulnerability_types', '')
                relevance = evidence.get('relevance_score', 0)
                
                print(f"    RAG 매칭: 페이지 {page}, 타입 {vuln_types}, 관련성 {relevance:.2f}")
                
                # 매칭 적절성 평가
                vuln_type_lower = vuln['type'].lower()
                if 'sql' in vuln_type_lower and 'SQL' in vuln_types:
                    print(f"    ✅ 적절한 매칭")
                elif 'command' in vuln_type_lower and 'Command' in vuln_types:
                    print(f"    ✅ 적절한 매칭")
                elif 'deserial' in vuln_type_lower and 'Deserial' in vuln_types:
                    print(f"    ✅ 적절한 매칭")
                elif vuln_types == 'General':
                    print(f"    ⚠️ 일반 가이드라인 매칭")
                else:
                    print(f"    ❌ 부적절한 매칭")
            else:
                print(f"    ❌ RAG 증거 없음")


def test_rag_with_metadata_filter():
    """메타데이터 필터를 사용한 RAG 검색 테스트"""
    print("\n" + "="*80)
    print("🔍 테스트 5: 메타데이터 필터링 RAG 검색")
    print("="*80)
    
    rag = SimpleRAG()
    
    # 1. 필터 없이 검색
    print("\n1️⃣ 필터 없이 검색:")
    results_no_filter = rag.search_similar("보안 취약점", top_k=3)
    
    if results_no_filter['metadatas'] and results_no_filter['metadatas'][0]:
        for i, meta in enumerate(results_no_filter['metadatas'][0], 1):
            vuln_types = meta.get('vulnerability_types', 'None')
            page = meta.get('page_start', '?')
            print(f"  {i}. 타입: {vuln_types}, 페이지: {page}")
    
    # 2. SQL_Injection 필터로 검색
    print("\n2️⃣ SQL_Injection 필터로 검색:")
    sql_filter = {
        "vulnerability_types": {"$contains": "SQL_Injection"}
    }
    results_with_filter = rag.search_similar("보안 취약점", top_k=3, filter_metadata=sql_filter)
    
    if results_with_filter['metadatas'] and results_with_filter['metadatas'][0]:
        for i, meta in enumerate(results_with_filter['metadatas'][0], 1):
            vuln_types = meta.get('vulnerability_types', 'None')
            page = meta.get('page_start', '?')
            print(f"  {i}. 타입: {vuln_types}, 페이지: {page}")
            
            # SQL_Injection이 포함되어 있는지 확인
            if 'SQL_Injection' in vuln_types:
                print(f"     ✅ SQL_Injection 포함")
            else:
                print(f"     ❌ SQL_Injection 미포함 (필터 오류)")


def run_all_tests():
    """모든 테스트 실행"""
    print("\n" + "🚀 RAG 개선 사항 종합 테스트 시작 " + "="*50)
    
    # API 키 확인
    if not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"):
        print("⚠️ API 키가 설정되지 않았습니다. 일부 테스트가 실패할 수 있습니다.")
    
    tests = [
        ("페이지 정보 추출", test_page_info_extraction),
        ("취약점 타입 매핑", test_vulnerability_type_mapping),
        ("Hardcoded Secret RAG", test_hardcoded_secret_rag),
        ("다중 취약점 매칭", test_multiple_vulnerability_types),
        ("메타데이터 필터링", test_rag_with_metadata_filter)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            print(f"\n\n{'='*80}")
            print(f"🧪 {test_name} 테스트 시작")
            print('='*80)
            test_func()
            results.append((test_name, "✅ 성공"))
        except Exception as e:
            print(f"\n❌ 테스트 실패: {e}")
            results.append((test_name, f"❌ 실패: {str(e)[:50]}"))
    
    # 결과 요약
    print("\n\n" + "="*80)
    print("📊 테스트 결과 요약")
    print("="*80)
    
    for test_name, result in results:
        print(f"  {test_name}: {result}")
    
    success_count = sum(1 for _, r in results if "✅" in r)
    total_count = len(results)
    
    print(f"\n총 {total_count}개 중 {success_count}개 성공")
    
    if success_count == total_count:
        print("🎉 모든 테스트 통과!")
    else:
        print(f"⚠️ {total_count - success_count}개 테스트 실패")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="RAG 개선 사항 테스트")
    parser.add_argument('--test', type=int, help='특정 테스트만 실행 (1-5)')
    parser.add_argument('--all', action='store_true', help='모든 테스트 실행')
    
    args = parser.parse_args()
    
    if args.test:
        if args.test == 1:
            test_page_info_extraction()
        elif args.test == 2:
            test_vulnerability_type_mapping()
        elif args.test == 3:
            test_hardcoded_secret_rag()
        elif args.test == 4:
            test_multiple_vulnerability_types()
        elif args.test == 5:
            test_rag_with_metadata_filter()
        else:
            print("❌ 잘못된 테스트 번호입니다. 1-5 중 선택하세요.")
    else:
        run_all_tests()