# test_rag_usage.py
"""
RAG 시스템이 실제로 어떻게 사용되는지 테스트
"""
import sys
sys.path.append('.')

from dotenv import load_dotenv
load_dotenv()

from rag.simple_rag import SimpleRAG
from core.llm_analyzer import LLMSecurityAnalyzer
import json

def test_current_rag_usage():
    """현재 RAG 사용 실태 점검"""
    print("=" * 70)
    print("📚 현재 RAG 사용 실태 분석")
    print("=" * 70)
    
    # 1. RAG 시스템 확인
    print("\n1️⃣ RAG 시스템 상태:")
    try:
        rag = SimpleRAG()
        stats = rag.get_stats()
        print(f"  ✅ 벡터 DB 로드 성공")
        print(f"  • 문서 수: {stats['total_documents']}")
    except Exception as e:
        print(f"  ❌ RAG 로드 실패: {e}")
        return
    
    # 2. 취약한 코드 예시
    test_code = """
import mysql.connector
import pickle

def login(username, password):
    # 사용자 입력을 직접 쿼리에 삽입
    query = "SELECT * FROM users WHERE username='%s' AND password='%s'" % (username, password)
    cursor.execute(query)
    
def load_user_data(data):
    # 안전하지 않은 역직렬화
    return pickle.loads(data)
    
def process_file(filename):
    # 경로 검증 없이 파일 처리
    with open(f"/uploads/{filename}", 'r') as f:
        return f.read()
"""
    
    print("\n2️⃣ 테스트 코드:")
    print("```python")
    for line in test_code.split('\n')[:8]:
        if line.strip():
            print(line)
    print("...")
    print("```")
    
    # 3. 현재 LLM 분석기가 RAG를 어떻게 사용하는지 확인
    print("\n3️⃣ 현재 analyze_code_security 함수 분석:")
    
    analyzer = LLMSecurityAnalyzer()
    
    # 코드 확인 - RAG 사용 부분 찾기
    import inspect
    source = inspect.getsource(analyzer.analyze_code_security)
    
    rag_usage_count = source.count('self.rag')
    rag_search_count = source.count('search_similar')
    
    print(f"  • self.rag 참조: {rag_usage_count}회")
    print(f"  • search_similar 호출: {rag_search_count}회")
    
    if rag_usage_count < 3:
        print("  ⚠️ RAG가 거의 사용되지 않음!")
    
    # 4. 실제 분석 실행해서 RAG 활용도 확인
    print("\n4️⃣ 실제 분석 실행:")
    
    # 분석 실행
    result = analyzer.analyze_code_security(test_code, {'packages': [], 'summary': {}})
    
    if result.get('success'):
        analysis = result['analysis']
        vulns = analysis.get('code_vulnerabilities', [])
        
        print(f"\n  📊 분석 결과:")
        print(f"  • 발견된 취약점: {len(vulns)}개")
        
        # 패턴 매칭으로 찾은 것 vs LLM이 찾은 것 구분
        pattern_vulns = [v for v in vulns if v.get('pattern_matched')]
        llm_vulns = [v for v in vulns if not v.get('pattern_matched')]
        
        print(f"  • 패턴 매칭으로 발견: {len(pattern_vulns)}개")
        print(f"  • LLM/RAG로 발견: {len(llm_vulns)}개")
        
        if len(pattern_vulns) > len(llm_vulns):
            print("\n  ⚠️ 패턴 매칭이 주가 되고 있음! RAG/LLM이 제대로 활용 안 됨")
    
    # 5. RAG 직접 테스트
    print("\n5️⃣ RAG 직접 검색 테스트:")
    
    test_queries = [
        "SQL 인젝션 취약점",
        "pickle 역직렬화 보안",
        "경로 조작 취약점",
        "% 포맷팅 SQL"
    ]
    
    for query in test_queries:
        results = rag.search_similar(query, top_k=1)
        if results['documents'][0]:
            doc = results['documents'][0][0][:200]
            print(f"\n  🔍 '{query}' 검색 결과:")
            print(f"     {doc}...")
        else:
            print(f"\n  ❌ '{query}' 검색 결과 없음")

def test_improved_rag_analysis():
    """개선된 RAG 기반 분석"""
    print("\n" + "=" * 70)
    print("🚀 개선된 RAG 기반 분석 테스트")
    print("=" * 70)
    
    rag = SimpleRAG()
    
    test_code = """
import mysql.connector

def search_user(user_input):
    db = mysql.connector.connect(host="localhost", user="root", password="password")
    cursor = db.cursor()
    query = "SELECT * FROM users WHERE name LIKE '%" + user_input + "%'"
    cursor.execute(query)
    return cursor.fetchall()
"""
    
    print("\n📝 분석할 코드:")
    print("```python")
    print(test_code)
    print("```")
    
    # 1. 코드에서 의심스러운 패턴 추출
    print("\n1️⃣ 코드 분석 중...")
    
    suspicious_patterns = []
    lines = test_code.split('\n')
    
    for i, line in enumerate(lines, 1):
        if 'SELECT' in line or 'INSERT' in line or 'UPDATE' in line or 'DELETE' in line:
            suspicious_patterns.append(f"라인 {i}: SQL 쿼리 발견")
        if '+' in line and ('query' in line.lower() or 'sql' in line.lower()):
            suspicious_patterns.append(f"라인 {i}: 문자열 연결로 SQL 구성")
        if '%' in line and 'LIKE' in line:
            suspicious_patterns.append(f"라인 {i}: LIKE 연산자와 % 사용")
    
    print(f"  발견된 의심 패턴: {len(suspicious_patterns)}개")
    for pattern in suspicious_patterns:
        print(f"    • {pattern}")
    
    # 2. 각 패턴에 대해 RAG 검색
    print("\n2️⃣ KISIA 가이드라인에서 관련 내용 검색:")
    
    guideline_contexts = []
    
    for pattern in suspicious_patterns:
        # 패턴에서 키워드 추출
        if "SQL" in pattern:
            query = "SQL 삽입 취약점 방어"
        elif "문자열 연결" in pattern:
            query = "문자열 연결 SQL 인젝션"
        elif "LIKE" in pattern:
            query = "LIKE 연산자 보안"
        else:
            continue
        
        results = rag.search_similar(query, top_k=2)
        if results['documents'][0]:
            print(f"\n  📚 '{query}' 관련 가이드라인:")
            for doc in results['documents'][0][:1]:
                print(f"     {doc[:300]}...")
                guideline_contexts.append(doc)
    
    # 3. RAG 컨텍스트를 포함한 LLM 분석
    print("\n3️⃣ RAG 컨텍스트 기반 LLM 분석:")
    
    if guideline_contexts:
        from openai import OpenAI
        import os
        
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        
        context = "\n\n".join(guideline_contexts[:3])
        
        prompt = f"""
        당신은 KISIA Python 시큐어코딩 가이드 전문가입니다.
        
        [KISIA 가이드라인]
        {context}
        
        [분석할 코드]
        ```python
        {test_code}
        ```
        
        위 가이드라인을 바탕으로 코드의 보안 취약점을 분석하세요.
        가이드라인에서 언급된 구체적인 내용을 인용하며 설명하세요.
        
        JSON 형식으로 응답:
        {{
            "vulnerabilities": [
                {{
                    "type": "취약점 종류",
                    "line": 라인번호,
                    "severity": "CRITICAL/HIGH/MEDIUM/LOW",
                    "description": "설명",
                    "guideline_reference": "가이드라인 인용",
                    "fix": "수정 방법"
                }}
            ]
        }}
        """
        
        try:
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "보안 전문가. JSON만 응답"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1000
            )
            
            result_text = response.choices[0].message.content
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0]
            
            result = json.loads(result_text.strip())
            
            print(f"\n  ✅ RAG 기반 분석 완료!")
            print(f"  • 발견된 취약점: {len(result.get('vulnerabilities', []))}개")
            
            for vuln in result.get('vulnerabilities', []):
                print(f"\n  🔴 {vuln['type']} (라인 {vuln.get('line', '?')})")
                print(f"     심각도: {vuln['severity']}")
                print(f"     설명: {vuln['description']}")
                if vuln.get('guideline_reference'):
                    print(f"     📚 가이드라인: {vuln['guideline_reference'][:100]}...")
                
        except Exception as e:
            print(f"  ❌ LLM 분석 실패: {e}")
    else:
        print("  ⚠️ RAG에서 관련 가이드라인을 찾지 못함")

def main():
    print("🔍 RAG 활용도 분석 테스트\n")
    
    print("테스트 선택:")
    print("1. 현재 RAG 사용 실태 점검")
    print("2. 개선된 RAG 기반 분석 테스트")
    print("3. 둘 다 실행")
    
    choice = input("\n선택 (1-3): ").strip()
    
    if choice == '1':
        test_current_rag_usage()
    elif choice == '2':
        test_improved_rag_analysis()
    elif choice == '3':
        test_current_rag_usage()
        test_improved_rag_analysis()
    else:
        print("잘못된 선택입니다.")

if __name__ == "__main__":
    main()