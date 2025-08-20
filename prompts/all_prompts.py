# prompts/all_prompts.py
"""
모든 프롬프트 중앙 관리 파일
Version: 1.0
Last Updated: 2024
"""

from typing import Dict, List, Optional

# ============================================================================
# SYSTEM PROMPTS - AI 모델의 기본 역할 정의
# ============================================================================

SYSTEM_PROMPTS = {
    "security_expert": """You are a senior security expert who understands the fundamental principles of vulnerabilities.
You analyze code by understanding HOW and WHY vulnerabilities occur, not just pattern matching.
Always verify if the code has proper safeguards before marking it as vulnerable.
Respond in Korean with JSON format.""",
    
    "json_api": "You are a JSON API. Respond only with valid JSON. No explanations.",
    
    "json_analyzer": """You are a JSON API that analyzes Python code for vulnerabilities. 
Respond only with valid JSON. No markdown, no explanations.""",
    
    "rag_assistant": """당신은 한국정보보호산업협회(KISIA)의 Python 시큐어 코딩 가이드 전문가입니다.
아래 제공된 가이드라인을 참고하여 정확하고 실용적인 답변을 제공해주세요.""",
    
    "rag_strict": """당신은 KISIA Python 시큐어코딩 가이드 전문가입니다.
반드시 제공된 문서를 근거로 답변하세요.
추측하지 말고, 문서에 없는 내용은 '가이드라인에 명시되지 않음'이라고 하세요.""",
    
    "python_security": "당신은 Python 보안 전문가입니다. KISIA Python 시큐어코딩 가이드를 기반으로 정확한 답변을 제공합니다."
}

# ============================================================================
# SECURITY ANALYSIS PROMPTS - 보안 취약점 분석
# ============================================================================

SECURITY_PROMPTS = {
    "role_based_discovery": """당신은 3명의 보안 전문가입니다. 각 역할로 코드를 철저히 분석하세요:

👹 **블랙햇 해커 관점**
- 이 코드를 어떻게 악용할 것인가?
- 데이터 탈취, 시스템 장악, 서비스 거부 공격
- 여러 취약점을 연계한 체인 공격
- 소셜 엔지니어링과 결합 가능한 취약점

🔍 **보안 감사관 관점**  
- OWASP Top 10, CWE Top 25 기준 위반
- 한국 개인정보보호법, GDPR, PCI-DSS 준수 여부
- 보안 코딩 표준 및 베스트 프랙티스 위반
- 로깅 및 모니터링 부재

🛠️ **시니어 개발자 관점**
- 실수하기 쉬운 코드 패턴
- 엣지 케이스와 예외 처리 누락
- 레이스 컨디션, 데드락 가능성
- 유지보수 시 발생할 보안 문제

{file_info}

분석할 코드:
{code}

각 역할에서 발견한 모든 문제를 JSON 형식으로 보고하세요.
창의적이고 깊이 있게 분석하세요.

{{
    "vulnerabilities": [
        {{
            "type": "MUST BE IN ENGLISH (e.g., "SQL Injection", "XSS", "Command Injection")",  
            "severity": "CRITICAL/HIGH/MEDIUM/LOW",
            "role": "발견한역할(해커/감사관/개발자)",
            "confidence": "HIGH/MEDIUM/LOW",
            "location": {{
                "file": "파일명",
                "line": 숫자,
                "function": "함수명",
                "code_snippet": "문제코드"
            }},
            "description": "한국어설명",
            "vulnerable_code": "취약한코드",
            "fixed_code": "수정된코드",
            "fix_explanation": "수정설명",
            "exploit_scenario": "공격시나리오",
            "recommendation": "권장사항"
        }}
    ]
}}""",

    "comprehensive_checklist": """이전 분석에 추가로, 다음의 포괄적인 보안 체크리스트를 확인하세요:

## 🔴 인젝션 취약점
1. SQL Injection - 문자열 연결, f-string, format, %
2. NoSQL Injection - MongoDB, Redis 쿼리 조작
3. Command Injection - os.system, subprocess, eval, exec
4. LDAP Injection - LDAP 쿼리 조작
5. XPath Injection - XML 경로 조작
6. Template Injection - Jinja2, Django 템플릿
7. Code Injection - eval(), exec(), compile()
8. Header Injection - HTTP 헤더 조작
9. Log Injection - 로그 파일 조작

## 🟠 인증/인가 취약점
10. Broken Authentication - 약한 인증 메커니즘
11. Session Fixation - 세션 ID 고정
12. Insufficient Authorization - 권한 검사 누락
13. Privilege Escalation - 권한 상승
14. JWT 취약점 - 서명 검증 누락, None 알고리즘
15. OAuth 취약점 - Redirect URI 검증 누락
16. 2FA Bypass - 2단계 인증 우회
17. Password Reset Poisoning - 패스워드 재설정 취약점
18. Account Takeover - 계정 탈취 가능성

## 🟡 데이터 노출
19. Hardcoded Secrets - API키, 패스워드, 토큰
20. Information Disclosure - 스택트레이스, 디버그 정보
21. Directory Traversal - ../.. 경로 조작
22. Sensitive Data in URL - GET 파라미터에 민감정보
23. Sensitive Data in Logs - 로그에 패스워드 등 기록
24. Error Message Leakage - 상세한 에러 메시지
25. Source Code Disclosure - .git, .env 노출
26. Backup File Exposure - .bak, .old 파일
27. API Key in Client Code - 프론트엔드에 API키

## 🟢 암호화 취약점
28. Weak Encryption - DES, RC4, MD5, SHA1
29. Insufficient Key Length - 짧은 암호키
30. Hardcoded Encryption Keys - 하드코딩된 암호키
31. Predictable Random - random 모듈 사용
32. Missing Encryption - 평문 저장/전송
33. Weak Password Storage - 단순 해시, Salt 없음
34. ECB Mode Usage - ECB 모드 사용
35. IV Reuse - 초기화 벡터 재사용

## 🔵 입력 검증
36. XSS - Reflected, Stored, DOM-based
37. XXE - XML External Entity
38. SSRF - Server-Side Request Forgery
39. CSRF - Cross-Site Request Forgery
40. File Upload - 악성 파일 업로드
41. Zip Bomb - 압축 폭탄
42. ReDoS - 정규식 서비스 거부
43. Integer Overflow - 정수 오버플로우
44. Buffer Overflow - 버퍼 오버플로우
45. Format String - 포맷 스트링 취약점

## 🟣 비즈니스 로직
46. Race Condition - 경쟁 상태
47. Time-of-check Time-of-use (TOCTOU)
48. Business Logic Bypass - 비즈니스 로직 우회
49. Insufficient Rate Limiting - 속도 제한 부재
50. Price Manipulation - 가격 조작
51. Quantity Manipulation - 수량 조작
52. Workflow Bypass - 프로세스 우회
53. Forced Browsing - 강제 브라우징

## ⚫ 설정 및 배포
54. Debug Mode Enabled - 디버그 모드 활성화
55. Default Credentials - 기본 자격증명
56. Unnecessary Services - 불필요한 서비스
57. Misconfigured CORS - CORS 설정 오류
58. Missing Security Headers - 보안 헤더 누락
59. Insecure Cookies - Secure, HttpOnly 플래그 누락
60. Unencrypted Communication - HTTP 사용

## 🔶 기타 취약점
61. Insecure Deserialization - pickle, yaml 취약점
62. Prototype Pollution - 프로토타입 오염
63. Clickjacking - 클릭재킹
64. Open Redirect - 오픈 리다이렉트
65. DNS Rebinding - DNS 리바인딩
66. WebSocket 취약점 - WS 보안 문제
67. GraphQL Injection - GraphQL 쿼리 조작
68. Server-Side Includes (SSI) Injection
69. CSV Injection - CSV 수식 주입
70. Memory Leak - 메모리 누수

이전에 발견하지 못한 취약점이 있다면 모두 추가로 보고하세요.
각 취약점에 대해 실제 코드에서 해당 패턴을 찾아 보고하세요.""",

    "vulnerability_discovery": """Python 보안 전문가로서 코드를 분석하고 JSON으로만 응답하세요.

{file_info}

분석할 코드:
{code}

모든 보안 취약점을 찾아 JSON 형식으로 보고하세요.
창의적으로 분석하되, 일반적인 취약점도 놓치지 마세요.

{{
    "vulnerabilities": [
        {{
            "type": "MUST BE IN ENGLISH (e.g., "SQL Injection", "XSS", "Command Injection")", 
            "severity": "CRITICAL/HIGH/MEDIUM/LOW",
            "confidence": "HIGH/MEDIUM/LOW",
            "location": {{
                "file": "파일명",
                "line": 숫자,
                "function": "함수명",
                "code_snippet": "문제코드"
            }},
            "description": "한국어설명",
            "vulnerable_code": "취약한코드",
            "fixed_code": "수정된코드",
            "fix_explanation": "수정설명",
            "data_flow": "데이터흐름",
            "exploit_scenario": "공격시나리오",
            "recommendation": "권장사항"
        }}
    ]
}}""",

    "validation": """
다음 취약점 판단이 맞는지 검증하세요:

[코드]
{code}

[판단된 취약점]
- 종류: {vuln_type}
- 이유: {reasoning}

[검증 질문]
1. 이 코드에 실제 안전장치가 있는가?
2. 정말로 공격 가능한가?
3. 오탐(False Positive)은 아닌가?

검증 결과:
{{
    "is_valid": true/false,
    "reason": "설명",
    "actual_risk_level": "HIGH/MEDIUM/LOW/NONE"
}}


⚠️ 중요 규칙:
- type 필드는 반드시 영어로 작성 (예: "SQL Injection", "XSS", "Path Traversal", "Command Injection", "Hardcoded Secret")
- description과 다른 필드는 한국어로 작성
- 표준 영어 취약점 명칭 사용:
  * SQL Injection (SQL 인젝션)
  * XSS 또는 Cross-Site Scripting (크로스 사이트 스크립팅)  
  * Command Injection (명령어 삽입)
  * Path Traversal (경로 조작)
  * Hardcoded Secret (하드코딩된 시크릿)
  * Weak Cryptography (약한 암호화)
  * Insecure Deserialization (안전하지 않은 역직렬화)
  * Information Disclosure (정보 노출)
  * Race Condition (경쟁 상태)
  * CSRF (Cross-Site Request Forgery)
  * XXE (XML External Entity)
  * SSRF (Server-Side Request Forgery)
  * 기타 영어 표준 명칭

주의: JSON만 출력. 다른 텍스트 없음.

"""
}

# ============================================================================
# RAG Q&A PROMPTS - 가이드라인 기반 질의응답
# ============================================================================


# RAG_PROMPTS 딕셔너리에 추가/수정

RAG_PROMPTS = {
    # 수정: RAG 컨텍스트가 있을 때 (보조 역할 명시)
    "qa_with_rag_context": """Python 보안 전문가로서 답변해주세요.

아래 참고 자료가 있다면 활용하되, 자료에 없는 내용은 일반 보안 지식으로 답변하세요.

[참고 자료]
{context}

[질문]
{question}

[답변]""",
    
    # 수정: RAG 없을 때 (AI 독립 답변)
    "qa_without_rag": """Python 보안 전문가로서 답변해주세요.

[질문]
{question}

[답변 지침]
1. 명확하고 실용적인 답변
2. 보안 취약점과 해결 방법 제시
3. 코드 예시 포함 (가능한 경우)
4. OWASP, CWE 기준 참조
5. 한국어로 답변

[답변]""",
    
    # 추가: 통합 프롬프트 (RAG 선택적)
    "qa_unified": """Python 보안 전문가로서 답변해주세요.
{rag_section}
[질문]
{question}

[답변 지침]
- 정확하고 실용적인 답변 제공
- 코드 예시 포함
- 보안 모범 사례 설명
{source_note}

[답변]""",

    "qa_smart_context": """당신은 보안 분석 도구의 AI 어시스턴트입니다.
사용자의 코드를 분석했고, 그 결과를 바탕으로 도움을 주고 있습니다.

[분석 정보]
{analysis_info}

[발견된 취약점 상세]
{vulnerabilities_detail}

[분석한 코드]
{code_context}

[SBOM 정보]
{sbom_info}

[이전 대화 전체]
{conversation_history}

[현재 질문]
{question}

위 모든 정보를 활용하여 구체적이고 정확한 답변을 제공하세요.
- 취약점이 있다면 수정 코드를 제시하세요
- 파일명과 라인 번호를 정확히 참조하세요
- 이전 대화의 맥락을 이어가세요
{rag_note}

[답변]"""
}



# ============================================================================
# VULNERABILITY PRINCIPLES - 취약점 원리 설명
# ============================================================================

VULNERABILITY_PRINCIPLES = {
    "SQL Injection": {
        "principle": "사용자 입력이 SQL 쿼리 구조를 변경할 수 있을 때 발생",
        "safe_patterns": ["파라미터 바인딩 (?, %s)", "ORM 사용", "Stored Procedure"],
        "unsafe_patterns": ["문자열 연결 (+)", "f-string", "% formatting", ".format()"],
        "check_points": [
            "쿼리와 데이터가 분리되어 있는가?",
            "사용자 입력이 쿼리 구조를 바꿀 수 있는가?"
        ]
    },
    "XSS": {
        "principle": "사용자 입력이 이스케이프 없이 HTML/JS로 렌더링될 때 발생",
        "safe_patterns": ["템플릿 엔진 자동 이스케이프", "DOMPurify", "bleach"],
        "unsafe_patterns": ["innerHTML 직접 조작", "document.write", "eval()"],
        "check_points": [
            "템플릿 엔진이 자동 이스케이프를 하는가?",
            "사용자 입력이 HTML로 해석될 수 있는가?"
        ]
    },
    "Hardcoded Secret": {
        "principle": "민감한 정보가 소스코드에 노출되어 유출 위험",
        "safe_patterns": ["환경변수", "설정 파일", "Secret Manager"],
        "unsafe_patterns": ["코드에 직접 작성", "주석에 포함"],
        "check_points": [
            "실제 운영환경 시크릿인가?",
            "개발/테스트용 더미 값인가?"
        ]
    },
    "Weak Cryptography": {
        "principle": "깨지기 쉬운 암호화 알고리즘 사용",
        "safe_patterns": ["bcrypt", "argon2", "scrypt", "pbkdf2", "AES-256"],
        "unsafe_patterns": ["MD5", "SHA1", "DES", "단순 base64"],
        "check_points": [
            "암호화 목적이 무엇인가?",
            "레인보우 테이블 공격에 안전한가?"
        ]
    }
}

# ============================================================================
# PROMPT BUILDERS - 프롬프트 생성 함수
# ============================================================================

def build_security_analysis_prompt(code: str, file_list: List[Dict] = None) -> str:
    """보안 분석 프롬프트 생성"""
    
    file_info = ""
    if file_list:
        file_info = f"\n분석 대상: {len(file_list)}개 파일\n"
        for f in file_list[:5]:
            file_info += f"- {f['path']} ({f['lines']}줄)\n"
    
    # 코드 길이 제한
    max_code_length = 25000
    if len(code) > max_code_length:
        code = code[:max_code_length] + "\n# ... (코드가 잘렸습니다)"
    
    return SECURITY_PROMPTS["vulnerability_discovery"].format(
        file_info=file_info,
        code=code
    )

def build_principle_based_prompt(code: str) -> str:
    """원리 기반 분석 프롬프트 생성"""
    # 라인 번호 추가
    lines = code.split('\n')
    code_with_lines = '\n'.join([f"{i+1:3}: {line}" for i, line in enumerate(lines)])
    
    # principle_based_analysis가 없으면 vulnerability_discovery 사용
    if "principle_based_analysis" in SECURITY_PROMPTS:
        return SECURITY_PROMPTS["principle_based_analysis"].replace(
            "{code_with_lines}", code_with_lines
        )
    else:
        return SECURITY_PROMPTS["vulnerability_discovery"].format(
            file_info="",
            code=code_with_lines
        )

def build_validation_prompt(code: str, vuln_type: str, reasoning: str) -> str:
    """취약점 검증 프롬프트 생성"""
    if "validation" in SECURITY_PROMPTS:
        return SECURITY_PROMPTS["validation"].format(
            code=code,
            vuln_type=vuln_type,
            reasoning=reasoning
        )
    else:
        # validation이 없으면 기본 프롬프트 반환
        return f"Validate: {vuln_type} in {code[:100]}..."

def build_rag_qa_prompt(question: str, rag_evidences: str) -> str:
    """RAG Q&A 프롬프트 생성"""
    return RAG_PROMPTS["qa_with_context"].format(
        question=question,
        rag_evidences=rag_evidences
    )

def build_rag_system_prompt(question: str, context: str) -> str:
    """RAG 시스템 프롬프트 생성"""
    return RAG_PROMPTS["qa_system"].format(
        question=question,
        context=context
    )

def get_system_prompt(prompt_type: str) -> str:
    """시스템 프롬프트 가져오기"""
    return SYSTEM_PROMPTS.get(prompt_type, SYSTEM_PROMPTS["security_expert"])

def get_vulnerability_principle(vuln_type: str) -> Dict:
    """취약점 타입별 원리 반환"""
    return VULNERABILITY_PRINCIPLES.get(vuln_type, {
        "principle": "알려지지 않은 취약점",
        "safe_patterns": [],
        "unsafe_patterns": [],
        "check_points": []
    })

# ============================================================================
# PARSE ERROR PROMPTS - 파싱 오류 처리
# ============================================================================

def create_parse_error_response(error_msg: str, response_snippet: str) -> List[Dict]:
    """파싱 에러 객체 생성"""
    return [{
        "type": "Parse Error",
        "severity": "ERROR",
        "confidence": "HIGH",
        "location": {"file": "unknown", "line": 0, "function": "parse_error"},
        "description": f"JSON 파싱 실패: {error_msg}",
        "vulnerable_code": f"응답 일부:\n{response_snippet}",
        "fixed_code": "재시도 필요",
        "fix_explanation": "AI가 올바른 JSON 형식으로 응답하지 않았습니다.",
        "recommendation": "1. 코드를 줄여보세요\n2. 다른 AI 모델을 시도해보세요\n3. 다시 분석을 시도해보세요",
        "parse_error": True
    }]

# ============================================================================
# SPECIAL PATTERNS - 특수 패턴 프롬프트
# ============================================================================

RAG_SPECIAL_PATTERNS = """
다음 코드에서 KISIA 가이드라인 기준 특수한 취약점을 찾으세요:

[코드]
{code}

[KISIA 가이드라인 참고 내용]
{rag_context}

특히 다음을 확인하세요:
1. 한국 개인정보 패턴 (주민번호, 여권번호, 운전면허번호)
2. 한국 금융 관련 규정 위반
3. 정보통신망법 관련 이슈
4. KISA 권고사항 위반

발견된 특수 취약점만 보고하세요.
"""

# ============================================================================
# VERSION INFO
# ============================================================================

PROMPT_VERSION = "1.0.0"
LAST_UPDATED = "2024-12-XX"

def get_prompt_info():
    """프롬프트 버전 정보 반환"""
    return {
        "version": PROMPT_VERSION,
        "last_updated": LAST_UPDATED,
        "total_prompts": len(SYSTEM_PROMPTS) + len(SECURITY_PROMPTS) + len(RAG_PROMPTS),
        "categories": ["system", "security", "rag", "principles"]
    }