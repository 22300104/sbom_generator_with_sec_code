# prompts/security_prompts.py
"""
보안 분석용 프롬프트 모음
쉽게 수정 가능하도록 별도 파일로 관리
"""

# 시스템 프롬프트
SYSTEM_PROMPT = """You are a senior Python security expert with deep knowledge of:
- OWASP Top 10
- CWE (Common Weakness Enumeration)
- KISIA Python Secure Coding Guidelines
- Modern security best practices

Provide accurate, actionable security analysis in Korean.
Always respond with valid JSON only."""

# 메인 분석 프롬프트 - 더 명확한 설명 요구
CODE_ANALYSIS_PROMPT = """Python 코드의 보안 취약점을 정확히 분석하세요.

[분석할 코드]
```python
{code_with_lines}
```

[분석 요구사항]
1. 실제 존재하는 취약점만 탐지
2. 각 취약점에 대해 구체적이고 실용적인 설명
3. 명확한 수정 코드 제시

[체크리스트]
✓ SQL/NoSQL/LDAP 인젝션
✓ Command/Code 인젝션  
✓ Path Traversal
✓ XSS/CSRF/XXE
✓ 안전하지 않은 역직렬화
✓ 약한 암호화/해시 (MD5, SHA1)
✓ 하드코딩된 비밀정보
✓ 취약한 인증/인가
✓ 민감정보 노출
✓ 리소스 관리 문제

JSON 형식 응답:
{{
    "vulnerabilities": [
        {{
            "type": "SQL Injection",
            "type_korean": "SQL 삽입",
            "severity": "CRITICAL",
            "line_numbers": [8],
            "vulnerable_code": "query = f'SELECT * FROM users WHERE id = {{user_id}}'",
            "description": "사용자 입력을 f-string으로 직접 SQL 쿼리에 삽입하여 SQL 인젝션 공격에 취약",
            "impact": "공격자가 데이터베이스 전체 조회, 수정, 삭제 가능",
            "recommended_fix": {{
                "original_code": "query = f'SELECT * FROM users WHERE id = {{user_id}}'\\ncursor.execute(query)",
                "fixed_code": "query = 'SELECT * FROM users WHERE id = ?'\\ncursor.execute(query, (user_id,))",
                "description": "파라미터 바인딩 사용으로 SQL 인젝션 방지"
            }},
            "cwe_id": "CWE-89",
            "confidence": 0.95
        }}
    ]
}}

[중요]
- description: 이 코드가 왜 취약한지 구체적으로 설명
- impact: 실제 공격 시 어떤 피해가 발생하는지
- fixed_code: 즉시 적용 가능한 수정 코드"""

# RAG 검색용 프롬프트 - 더 정확하고 간결하게
RAG_EXPLANATION_PROMPT = """다음 취약점에 대해 KISIA 가이드라인을 참고하여 설명하세요.

[취약점 종류]
{vulnerability_type}

[참고할 가이드라인]
{rag_context}

[작성 지침]

1. 이 특정 취약점에 대한 내용만 추출
2. 다른 취약점 설명은 제외
3. 최대 3문장, 150자 이내
4. 다음 구조로 작성:
   - (1문장) 왜 위험한지
   - (1문장) 어떤 공격이 가능한지  
   - (1문장) 핵심 방어 방법
5. 각 문장은 완전한 문장을 작성하고 적절한 문장부호로 끝내세요. 문장간의 흐름이 자연스러워야 합니다.


[금지사항]
- 관련 없는 다른 취약점 언급 금지
- 코드 예시 포함 금지
- 페이지 번호나 라인 번호 언급 금지

간결하고 정확한 설명만 작성하세요."""

# 빠른 수정 제안 프롬프트
QUICK_FIX_PROMPT = """다음 보안 취약점을 즉시 수정하세요.

취약점: {vuln_type}
코드: {vulnerable_code}

최소한의 변경으로 안전하게 수정한 코드만 제시하세요.
주석이나 설명 없이 코드만 응답하세요."""

# 배치 분석 프롬프트 (여러 취약점 한번에)
BATCH_ANALYSIS_PROMPT = """다음 코드의 모든 보안 취약점을 한 번에 분석하세요.

[코드]
```python
{code}
```

각 취약점에 대해 간단명료하게:
1. 취약점 종류와 위치
2. 한 줄 설명
3. 수정 코드

JSON 배열로 응답하세요."""

# 취약점 타입 매핑 (영문 → 한글)
VULNERABILITY_TYPE_MAPPING = {
    'SQL Injection': 'SQL 삽입',
    'Command Injection': '명령어 삽입',
    'Code Injection': '코드 삽입',
    'Path Traversal': '경로 조작',
    'Directory Traversal': '디렉토리 탐색',
    'XSS': '크로스사이트 스크립팅',
    'Cross-Site Scripting': '크로스사이트 스크립팅',
    'CSRF': '크로스사이트 요청 위조',
    'XXE': 'XML 외부 개체 참조',
    'Insecure Deserialization': '안전하지 않은 역직렬화',
    'Weak Cryptography': '취약한 암호화',
    'Weak Encryption': '취약한 암호화',
    'Weak Hashing': '취약한 해시',
    'Hardcoded Secret': '하드코딩된 비밀정보',
    'Hardcoded Password': '하드코딩된 패스워드',
    'Hardcoded Credentials': '하드코딩된 인증정보',
    'Information Disclosure': '정보 노출',
    'Sensitive Data Exposure': '민감정보 노출',
    'Broken Authentication': '취약한 인증',
    'Broken Access Control': '취약한 접근 제어',
    'Security Misconfiguration': '보안 설정 오류',
    'Resource Management': '리소스 관리 문제',
    'Race Condition': '경쟁 조건',
    'Time-of-check Time-of-use': 'TOCTOU',
    'Buffer Overflow': '버퍼 오버플로우',
    'Integer Overflow': '정수 오버플로우',
    'Denial of Service': '서비스 거부',
    'Memory Leak': '메모리 누수'
}

# 심각도별 설명
SEVERITY_DESCRIPTIONS = {
    'CRITICAL': '즉시 수정 필요 - 시스템 전체 침해 가능',
    'HIGH': '빠른 수정 필요 - 중요 데이터 침해 가능',
    'MEDIUM': '계획적 수정 - 제한적 영향',
    'LOW': '개선 권장 - 낮은 위험도'
}

# 일반적인 수정 패턴
COMMON_FIXES = {
    'SQL Injection': {
        'pattern': "f-string 또는 문자열 결합",
        'fix': "파라미터 바인딩 (?, %s)",
        'example': "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
    },
    'Command Injection': {
        'pattern': "os.system() 또는 shell=True",
        'fix': "subprocess.run()에 리스트 인자 사용",
        'example': "subprocess.run(['echo', user_input], shell=False)"
    },
    'Path Traversal': {
        'pattern': "사용자 입력을 경로에 직접 사용",
        'fix': "os.path.basename() 또는 pathlib 검증",
        'example': "safe_path = os.path.join(base_dir, os.path.basename(user_input))"
    },
    'XSS': {
        'pattern': "사용자 입력을 HTML에 직접 삽입",
        'fix': "템플릿 엔진의 자동 이스케이프 사용",
        'example': "return render_template('page.html', data=user_input)"
    },
    'Weak Cryptography': {
        'pattern': "MD5, SHA1 사용",
        'fix': "bcrypt, scrypt, 또는 pbkdf2 사용",
        'example': "bcrypt.hashpw(password.encode(), bcrypt.gensalt())"
    },
    'Hardcoded Secret': {
        'pattern': "코드에 직접 작성된 비밀정보",
        'fix': "환경변수 또는 설정 파일 사용",
        'example': "API_KEY = os.environ.get('API_KEY')"
    }
}

def get_analysis_prompt(code_with_lines: str) -> str:
    """코드 분석 프롬프트 생성"""
    return CODE_ANALYSIS_PROMPT.format(code_with_lines=code_with_lines)

def get_rag_prompt(rag_context: str, vulnerability_type: str) -> str:
    """RAG 설명 프롬프트 생성"""
    return RAG_EXPLANATION_PROMPT.format(
        rag_context=rag_context,
        vulnerability_type=vulnerability_type
    )

def get_fix_prompt(vuln_type: str, vulnerable_code: str) -> str:
    """수정 코드 프롬프트 생성"""
    return QUICK_FIX_PROMPT.format(
        vuln_type=vuln_type,
        vulnerable_code=vulnerable_code
    )

def translate_vulnerability_type(eng_type: str) -> str:
    """영문 취약점 타입을 한글로 변환"""
    return VULNERABILITY_TYPE_MAPPING.get(eng_type, eng_type)

def get_common_fix(vuln_type: str) -> dict:
    """일반적인 수정 패턴 반환"""
    return COMMON_FIXES.get(vuln_type, {})