# test.py
"""
통합 테스트 파일
여러 테스트 모듈을 선택해서 실행
"""
import sys
import os
sys.path.append('.')

# .env 파일 로드
from dotenv import load_dotenv
load_dotenv()

def test_environment_scan():
    """환경 스캔 테스트"""
    from core.environment_scanner import EnvironmentScanner
    from core.analyzer import SBOMAnalyzer
    
    print("=" * 70)
    print("🔍 환경 스캔 테스트")
    print("=" * 70)
    
    scanner = EnvironmentScanner()
    packages = scanner.scan_installed_packages()
    print(f"\n✅ 발견된 패키지: {len(packages)}개")
    
    # 주요 패키지 표시
    for i, (name, info) in enumerate(list(packages.items())[:5], 1):
        print(f"  {i}. {name} v{info['version']}")
    
    print("\n테스트 완료!")

def test_vulnerability_scan():
    """취약점 스캔 테스트"""
    from core.analyzer import SBOMAnalyzer
    from security.vulnerability import check_vulnerabilities_enhanced
    
    print("=" * 70)
    print("🛡️ 취약점 스캔 테스트")
    print("=" * 70)
    
    test_code = """
import pandas as pd
import numpy as np
import requests
import flask
"""
    
    analyzer = SBOMAnalyzer()
    result = analyzer.analyze(test_code, "", scan_environment=True)
    
    print(f"\n📦 패키지 분석:")
    print(f"  • 직접 패키지: {len(result['packages'])}개")
    print(f"  • 간접 종속성: {len(result.get('indirect_dependencies', []))}개")
    
    print("\n🔍 취약점 검사 중...")
    enhanced_result = check_vulnerabilities_enhanced(
        result['packages'],
        result.get('indirect_dependencies', []),
        result
    )
    
    stats = enhanced_result.get('vulnerability_scan', {}).get('statistics', {})
    print(f"\n📊 결과:")
    print(f"  • 검사한 패키지: {stats.get('total_checked', 0)}개")
    print(f"  • 발견된 취약점: {stats.get('total_vulnerabilities', 0)}개")

def test_llm_analysis():
    """LLM 보안 분석 테스트 (개선 버전)"""
    from core.llm_analyzer import LLMSecurityAnalyzer
    import json
    
    print("=" * 70)
    print("🤖 코드 보안 분석 테스트")
    print("=" * 70)
    
    # 취약한 코드 예시
    vulnerable_code = """
import sqlite3
import hashlib
import os

def get_user(user_id):
    # SQL 인젝션 취약점
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = sqlite3.connect('db.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()

def hash_password(password):
    # 약한 암호화
    return hashlib.md5(password.encode()).hexdigest()

# 하드코딩된 비밀
API_KEY = "sk-1234567890"
PASSWORD = "admin123"

def run_command(cmd):
    # 명령어 삽입
    os.system(f"echo {cmd}")
"""
    
    print("\n📝 테스트 코드 (취약점 포함):")
    lines = vulnerable_code.split('\n')
    for i, line in enumerate(lines[:10], 1):
        if line.strip():
            print(f"  {i:2}: {line}")
    print("  ... (생략)")
    
    # API 키 확인
    has_api_key = os.getenv("OPENAI_API_KEY") and len(os.getenv("OPENAI_API_KEY", "")) > 10
    
    print(f"\n🔑 API 키 상태: {'✅ 설정됨' if has_api_key else '⚠️ 없음 (패턴 분석만 실행)'}")
    
    try:
        if not has_api_key:
            # API 키 없이 패턴 분석만
            os.environ["OPENAI_API_KEY"] = "dummy-key"
            analyzer = LLMSecurityAnalyzer()
            os.environ.pop("OPENAI_API_KEY", None)
            
            print("\n🔍 패턴 기반 분석 실행...")
            pattern_vulns = analyzer.analyze_code_patterns(vulnerable_code)
            ast_vulns = analyzer.analyze_ast_patterns(vulnerable_code)
            
            all_vulns = pattern_vulns + ast_vulns
            unique_vulns = []
            seen = set()
            
            for vuln in all_vulns:
                key = (vuln['type'], vuln['line_numbers'][0] if vuln['line_numbers'] else 0)
                if key not in seen:
                    seen.add(key)
                    unique_vulns.append(vuln)
            
            print(f"\n✅ 분석 완료!")
            print(f"  • 발견된 취약점: {len(unique_vulns)}개")
            
            for vuln in unique_vulns[:5]:
                line = vuln['line_numbers'][0] if vuln.get('line_numbers') else '?'
                print(f"    - 라인 {line}: {vuln['type']} ({vuln['severity']})")
        else:
            # 전체 분석 (LLM 포함)
            analyzer = LLMSecurityAnalyzer()
            print("\n🔍 LLM + 패턴 분석 실행...")
            
            result = analyzer.analyze_code_security(vulnerable_code, {'packages': [], 'summary': {}})
            
            if result.get('success'):
                analysis = result['analysis']
                print(f"\n✅ 분석 완료!")
                print(f"  • 보안 점수: {analysis.get('security_score', 0)}/100")
                print(f"  • 발견된 취약점: {len(analysis.get('code_vulnerabilities', []))}개")
                
                for vuln in analysis.get('code_vulnerabilities', [])[:5]:
                    line = vuln.get('line_numbers', [0])[0] if vuln.get('line_numbers') else '?'
                    print(f"    - 라인 {line}: {vuln['type']} ({vuln.get('severity', 'MEDIUM')})")
    
    except Exception as e:
        print(f"\n❌ 오류: {e}")
        print("💡 OpenAI API 키를 .env 파일에 설정하세요.")

def main():
    print("🚀 SBOM Security Analyzer 통합 테스트\n")
    
    # API 키 상태 확인
    has_api_key = os.getenv("OPENAI_API_KEY") and len(os.getenv("OPENAI_API_KEY", "")) > 10
    if has_api_key:
        print("✅ OpenAI API 키 감지됨\n")
    else:
        print("⚠️ OpenAI API 키 없음 - 일부 기능 제한됨")
        print("💡 .env 파일에 OPENAI_API_KEY를 설정하세요.\n")
    
    print("테스트 선택:")
    print("1. 환경 스캔 테스트")
    print("2. 취약점 스캔 테스트")
    print("3. 코드 보안 분석 테스트")
    print("4. 전체 테스트")
    
    choice = input("\n선택 (1-4): ").strip()
    
    print("")
    
    if choice == '1':
        test_environment_scan()
    elif choice == '2':
        test_vulnerability_scan()
    elif choice == '3':
        test_llm_analysis()
    elif choice == '4':
        test_environment_scan()
        print("\n")
        test_vulnerability_scan()
        print("\n")
        test_llm_analysis()
    else:
        print("잘못된 선택입니다.")

if __name__ == "__main__":
    main()