# test_gpt_analyzer.py
"""
GPT 중심 보안 분석기 테스트
"""
import sys
import os
sys.path.append('.')

from dotenv import load_dotenv
load_dotenv()

from core.llm_analyzer import LLMSecurityAnalyzer
import json
import time
from typing import Dict, List  # 타입 힌트 import 추가

def test_vulnerable_code():
    """다양한 취약점이 있는 코드 테스트"""
    print("=" * 70)
    print("🔍 GPT 중심 보안 분석 테스트")
    print("=" * 70)
    
    vulnerable_code = """
import sqlite3
import pickle
import hashlib
import os
from flask import Flask, request, render_template_string

app = Flask(__name__)

# 하드코딩된 비밀 정보
DB_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

def get_user(user_id):
    # SQL 인젝션 취약점
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def authenticate(username, password):
    # 약한 해시 알고리즘
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    # SQL 인젝션 (또 다른 형태)
    query = "SELECT * FROM users WHERE username='%s' AND password='%s'" % (username, password_hash)
    return execute_query(query)

@app.route('/search')
def search():
    # XSS 취약점
    keyword = request.args.get('q', '')
    return render_template_string(f"<h1>검색 결과: {keyword}</h1>")

def load_data(data_bytes):
    # 안전하지 않은 역직렬화
    return pickle.loads(data_bytes)

def process_file(filename):
    # 경로 조작 취약점
    filepath = f"/uploads/{filename}"
    with open(filepath, 'r') as f:
        return f.read()

def execute_command(cmd):
    # 명령어 삽입
    os.system(f"echo Processing: {cmd}")

# 잘못된 예외 처리
def divide(a, b):
    try:
        return a / b
    except:
        pass  # 모든 예외 무시
"""
    
    print("\n📝 분석할 코드 (여러 취약점 포함)")
    print(f"   총 {len(vulnerable_code.split(chr(10)))}줄")
    print("   포함된 취약점 유형:")
    print("   - SQL Injection (2곳)")
    print("   - Hardcoded Secrets")
    print("   - Weak Cryptography")
    print("   - XSS")
    print("   - Insecure Deserialization")
    print("   - Path Traversal")
    print("   - Command Injection")
    print("   - Poor Error Handling")
    
    # 분석기 초기화
    print("\n🚀 GPT 보안 분석기 초기화...")
    try:
        analyzer = LLMSecurityAnalyzer()
        print("✅ 초기화 성공")
        print(f"   - GPT 모델: {analyzer.model}")
        print(f"   - RAG 사용 가능: {'예' if analyzer.rag_available else '아니오'}")
    except Exception as e:
        print(f"❌ 초기화 실패: {e}")
        return
    
    # 분석 실행
    print("\n🔍 보안 분석 실행 중...")
    start_time = time.time()
    
    result = analyzer.analyze_code_security(vulnerable_code)
    
    elapsed_time = time.time() - start_time
    print(f"✅ 분석 완료 (소요 시간: {elapsed_time:.2f}초)")
    
    if result.get('success'):
        display_results(result['analysis'], result.get('metadata', {}))
    else:
        print(f"❌ 분석 실패: {result.get('error')}")
    
    return result

def test_safe_code():
    """안전한 코드 테스트"""
    print("\n" + "=" * 70)
    print("🔍 안전한 코드 분석 테스트")
    print("=" * 70)
    
    safe_code = """
import sqlite3
import hashlib
import secrets
import os
from flask import Flask, request, render_template

app = Flask(__name__)

# 환경 변수에서 설정 로드
DB_PASSWORD = os.environ.get('DB_PASSWORD')
API_KEY = os.environ.get('API_KEY')

def get_user(user_id):
    # 파라미터화된 쿼리 사용
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()

def authenticate(username, password):
    # 강력한 해시 알고리즘
    salt = secrets.token_bytes(32)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    
    # 파라미터화된 쿼리
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    return execute_query(query, (username, password_hash))

@app.route('/search')
def search():
    # 템플릿 엔진으로 안전하게 렌더링
    keyword = request.args.get('q', '')
    return render_template('search.html', keyword=keyword)
"""
    
    print("\n📝 분석할 코드 (안전한 코드)")
    print(f"   총 {len(safe_code.split(chr(10)))}줄")
    
    # 분석 실행
    try:
        analyzer = LLMSecurityAnalyzer()
        print("\n🔍 보안 분석 실행 중...")
        
        result = analyzer.analyze_code_security(safe_code)
        
        if result.get('success'):
            analysis = result['analysis']
            print(f"\n✅ 분석 완료")
            print(f"🎯 보안 점수: {analysis['security_score']}/100")
            
            if analysis['code_vulnerabilities']:
                print(f"⚠️ 발견된 이슈: {len(analysis['code_vulnerabilities'])}개")
            else:
                print("✅ 보안 취약점이 발견되지 않았습니다!")
                
            print(f"\n📌 요약: {analysis['summary']}")
    except Exception as e:
        print(f"❌ 분석 실패: {e}")

def display_results(analysis: Dict, metadata: Dict):
    """분석 결과 표시"""
    print("\n" + "=" * 70)
    print("📊 분석 결과")
    print("=" * 70)
    
    # 요약
    print(f"\n📌 요약: {analysis['summary']}")
    print(f"🎯 보안 점수: {analysis['security_score']}/100")
    
    # 메타데이터
    if metadata:
        print(f"\n📋 분석 정보:")
        print(f"   - 사용 모델: {metadata.get('gpt_model', 'unknown')}")
        print(f"   - RAG 사용: {metadata.get('rag_available', False)}")
        print(f"   - 총 취약점: {metadata.get('total_vulnerabilities', 0)}개")
    
    # 취약점 상세
    vulns = analysis.get('code_vulnerabilities', [])
    if vulns:
        print(f"\n⚠️ 발견된 취약점 ({len(vulns)}개):")
        
        # 심각도별 그룹화
        by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for vuln in vulns:
            severity = vuln.get('severity', 'MEDIUM')
            by_severity[severity].append(vuln)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if by_severity[severity]:
                print(f"\n{'🔴' if severity == 'CRITICAL' else '🟠' if severity == 'HIGH' else '🟡' if severity == 'MEDIUM' else '🟢'} {severity} ({len(by_severity[severity])}개):")
                
                for vuln in by_severity[severity]:
                    lines = vuln.get('line_numbers', [])
                    line_str = f"라인 {lines[0]}" if lines else "위치 불명"
                    
                    print(f"\n   [{line_str}] {vuln['type']}")
                    print(f"   📝 설명: {vuln.get('description', '')[:100]}...")
                    
                    # 설명 출처 표시
                    if 'explanation' in vuln:
                        source = vuln.get('explanation_source', 'unknown')
                        if source == 'KISIA 가이드라인':
                            print(f"   📚 {source}: {vuln['explanation'][:150]}...")
                        else:
                            print(f"   🤖 {source}: {vuln['explanation'][:100]}...")
                    
                    # 수정 방법
                    if vuln.get('recommended_fix'):
                        print(f"   ✅ 권장 수정: {vuln['recommended_fix'][:100]}...")
                    
                    # 취약한 코드
                    if vuln.get('vulnerable_code'):
                        print(f"   💻 취약한 코드: {vuln['vulnerable_code'][:50]}...")
    
    # 즉시 조치사항
    actions = analysis.get('immediate_actions', [])
    if actions:
        print(f"\n🚨 즉시 필요한 조치:")
        for action in actions:
            print(f"   • {action}")
    
    # 모범 사례
    practices = analysis.get('best_practices', [])
    if practices:
        print(f"\n💡 권장 보안 사례:")
        for practice in practices:
            print(f"   • {practice}")

def save_results(result: Dict, filename: str = "gpt_analysis_result.json"):
    """결과 저장"""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n💾 결과 저장됨: {filename}")

def main():
    print("🚀 GPT 중심 보안 분석기 테스트\n")
    
    # API 키 확인
    if not os.getenv("OPENAI_API_KEY"):
        print("❌ OPENAI_API_KEY가 설정되지 않았습니다.")
        print("💡 .env 파일에 API 키를 설정해주세요.")
        return
    
    print("테스트 선택:")
    print("1. 취약한 코드 분석")
    print("2. 안전한 코드 분석")
    print("3. 둘 다 테스트")
    
    choice = input("\n선택 (1-3): ").strip()
    
    results = []
    
    if choice == '1':
        result = test_vulnerable_code()
        if result:
            results.append(result)
    elif choice == '2':
        test_safe_code()
    elif choice == '3':
        result = test_vulnerable_code()
        if result:
            results.append(result)
        test_safe_code()
    else:
        print("잘못된 선택입니다.")
        return
    
    # 결과 저장 옵션
    if results:
        save_option = input("\n💾 분석 결과를 저장하시겠습니까? (y/n): ").strip().lower()
        if save_option == 'y':
            for i, result in enumerate(results):
                filename = f"gpt_analysis_result_{i+1}.json" if len(results) > 1 else "gpt_analysis_result.json"
                save_results(result, filename)

if __name__ == "__main__":
    main()