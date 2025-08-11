"""
개선된 보안 분석 프롬프트
원리 기반 추론을 유도하여 오탐을 줄이고 정확도를 높임
"""

# 시스템 프롬프트 - 추론 능력 강화
SYSTEM_PROMPT = """You are a senior security expert who understands the fundamental principles of vulnerabilities.
You analyze code by understanding HOW and WHY vulnerabilities occur, not just pattern matching.
Always verify if the code has proper safeguards before marking it as vulnerable.
Respond in Korean with JSON format."""

# 메인 분석 프롬프트 - 원리 기반 분석
SECURITY_ANALYSIS_PROMPT = """
아래 Python 코드의 보안 취약점을 분석하세요. 
단순 패턴 매칭이 아닌, 실제 악용 가능성을 기준으로 판단하세요.

[분석할 코드]
```python
{code_with_lines}
```

[분석 원칙]

1. **취약점 판단 기준**
   - 실제로 공격 가능한가?
   - 안전장치가 있는가?
   - 악용 시 실제 피해가 발생하는가?

2. **주요 확인 사항**
   - SQL 인젝션: 파라미터 바인딩(?, %s with tuple) 사용 시 안전
   - XSS: 템플릿 엔진의 자동 이스케이프 확인
   - 암호화: bcrypt, argon2, pbkdf2는 안전
   - 시크릿: 환경변수 사용 시 안전

3. **각 취약점에 대해 반드시 포함**
   - reasoning: 왜 취약한지 원리 설명
   - attack_scenario: 구체적인 공격 시나리오
   - confidence: HIGH/MEDIUM/LOW

JSON 형식:
{{
    "vulnerabilities": [
        {{
            "type": "취약점 종류",
            "severity": "CRITICAL/HIGH/MEDIUM/LOW",
            "line_numbers": [라인 번호],
            "vulnerable_code": "해당 코드",
            "reasoning": "이 코드가 취약한 이유 (원리 설명)",
            "attack_scenario": "실제 공격 방법",
            "confidence": "HIGH/MEDIUM/LOW",
            "has_safeguard": true/false,
            "safeguard_description": "안전장치 설명 (있는 경우)",
            "recommendation": "개선 방법"
        }}
    ],
    "safe_practices_found": [
        {{
            "practice": "발견된 안전한 코딩 practice",
            "line_numbers": [라인 번호],
            "description": "왜 안전한지 설명"
        }}
    ],
    "summary": {{
        "total_vulnerabilities": 0,
        "critical_count": 0,
        "has_sql_injection": false,
        "has_xss": false,
        "uses_parameter_binding": false,
        "uses_environment_variables": false
    }}
}}

[중요 지침]
- 파라미터 바인딩을 사용하는 SQL은 안전합니다 (?, %s with tuple)
- f-string이나 + 연산자로 SQL을 조합하는 것만 위험합니다
- 'dev', 'test' 같은 개발용 시크릿은 LOW severity로 분류
- 추론 과정을 명확히 설명하세요
"""

# RAG 검색용 프롬프트 - 한국 특화
RAG_SPECIAL_PATTERNS_PROMPT = """
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

# 검증용 프롬프트 - 오탐 체크
VALIDATION_PROMPT = """
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
"""

# Q&A용 RAG 통합 프롬프트
QA_WITH_RAG_PROMPT = """
당신은 Python 시큐어코딩 전문가입니다.
KISIA 가이드라인을 기반으로 정확한 답변을 제공합니다.

[KISIA 가이드라인 근거]
{rag_evidences}

[사용자 질문]
{question}

[답변 규칙]
1. 반드시 제공된 가이드라인을 근거로 답변
2. 근거가 없는 내용은 추측하지 말 것
3. 각 주장마다 출처 명시
4. 실용적인 코드 예시 포함

답변:
"""

# 취약점 타입별 원리 설명
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

def get_analysis_prompt(code: str) -> str:
    """코드 분석 프롬프트 생성"""
    # 라인 번호 추가
    lines = code.split('\n')
    code_with_lines = '\n'.join([f"{i+1:3}: {line}" for i, line in enumerate(lines)])
    
    return SECURITY_ANALYSIS_PROMPT.format(code_with_lines=code_with_lines)

def get_validation_prompt(code: str, vuln_type: str, reasoning: str) -> str:
    """취약점 검증 프롬프트 생성"""
    return VALIDATION_PROMPT.format(
        code=code,
        vuln_type=vuln_type,
        reasoning=reasoning
    )

def get_rag_integration_prompt(code: str, rag_context: str) -> str:
    """RAG 컨텍스트 통합 프롬프트 생성"""
    return RAG_SPECIAL_PATTERNS_PROMPT.format(
        code=code,
        rag_context=rag_context
    )

def get_qa_prompt(question: str, rag_evidences: str) -> str:
    """Q&A 프롬프트 생성"""
    return QA_WITH_RAG_PROMPT.format(
        question=question,
        rag_evidences=rag_evidences
    )

def get_principle_for_vuln(vuln_type: str) -> dict:
    """취약점 타입별 원리 반환"""
    return VULNERABILITY_PRINCIPLES.get(vuln_type, {
        "principle": "알려지지 않은 취약점",
        "safe_patterns": [],
        "unsafe_patterns": [],
        "check_points": []
    })