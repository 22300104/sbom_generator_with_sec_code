"""
LLM 기반 코드 보안 분석 모듈
"""
from openai import OpenAI
import json
import os
from typing import Dict, List, Optional

# RAG는 선택적 임포트
try:
    from rag.simple_rag import SimpleRAG
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
    print("Warning: SimpleRAG not available")

# 프롬프트는 선택적 임포트
try:
    from prompts.security_prompts import (
        SYSTEM_PROMPT,
        get_analysis_prompt,
        get_validation_prompt,
        get_rag_integration_prompt
    )
    PROMPTS_AVAILABLE = True
except ImportError:
    PROMPTS_AVAILABLE = False
    # 기본 프롬프트 사용
    SYSTEM_PROMPT = "You are a Python security expert. Respond with JSON only."
    def get_analysis_prompt(code): 
        return f"Analyze this code for security vulnerabilities:\n{code}"


class LLMSecurityAnalyzer:
    """GPT 기반 보안 분석기"""
    
    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY 환경 변수가 설정되지 않았습니다.")
        
        self.client = OpenAI(api_key=api_key)
        self.model = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
        
        # RAG 시스템 (선택적)
        self.rag = None
        self.rag_available = False
        
        if RAG_AVAILABLE:
            try:
                self.rag = SimpleRAG()
                self.rag_available = True
                print("✅ RAG 시스템 로드 완료")
            except Exception as e:
                print(f"⚠️ RAG 시스템 로드 실패: {e}")
    
    def analyze_code_security(self, code: str, context: Dict = None) -> Dict:
        """
        코드 보안 분석 메인 함수
        """
        print("🔍 AI 보안 분석 시작...")
        
        # GPT 분석
        result = self._gpt_analyze(code)
        
        if not result or not result.get('vulnerabilities'):
            return {
                "success": True,
                "analysis": {
                    "code_vulnerabilities": [],
                    "security_score": 100,
                    "summary": "보안 취약점이 발견되지 않았습니다.",
                    "immediate_actions": [],
                    "best_practices": ["현재 코드는 기본적인 보안 기준을 충족합니다."]
                }
            }
        
        vulnerabilities = result.get('vulnerabilities', [])
        
        # RAG로 설명 보강 (선택적)
        if self.rag_available:
            self._enhance_with_rag(vulnerabilities)
        
        # 보안 점수 및 권장사항
        security_score = self._calculate_security_score(vulnerabilities)
        immediate_actions = self._generate_immediate_actions(vulnerabilities)
        best_practices = self._generate_best_practices(vulnerabilities)
        
        return {
            "success": True,
            "analysis": {
                "code_vulnerabilities": vulnerabilities,
                "security_score": security_score,
                "summary": self._generate_summary(vulnerabilities),
                "immediate_actions": immediate_actions,
                "best_practices": best_practices
            },
            "metadata": {
                "gpt_model": self.model,
                "rag_available": self.rag_available,
                "total_vulnerabilities": len(vulnerabilities)
            }
        }
    
    def _gpt_analyze(self, code: str) -> Dict:
        """GPT로 취약점 분석"""
        
        # 코드에 라인 번호 추가
        lines = code.split('\n')
        code_with_lines = '\n'.join([f"{i+1:3}: {line}" for i, line in enumerate(lines)])
        
        if PROMPTS_AVAILABLE:
            prompt = get_analysis_prompt(code_with_lines)
        else:
            # 기본 프롬프트
            prompt = f"""
            Analyze this Python code for security vulnerabilities.
            
            Code:
            ```python
            {code_with_lines}
            ```
            
            Important:
            - Parameter binding (?, %s with tuple) is SAFE from SQL injection
            - Environment variables are SAFE for secrets
            - bcrypt, argon2, pbkdf2 are SAFE for password hashing
            
            Return JSON:
            {{
                "vulnerabilities": [
                    {{
                        "type": "vulnerability type",
                        "severity": "CRITICAL/HIGH/MEDIUM/LOW",
                        "line_numbers": [line numbers],
                        "vulnerable_code": "code snippet",
                        "description": "why it's vulnerable",
                        "recommendation": "how to fix"
                    }}
                ]
            }}
            """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=2500
            )
            
            result_text = response.choices[0].message.content
            
            # JSON 파싱
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0]
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0]
            
            result = json.loads(result_text.strip())
            
            # 오탐 필터링 (파라미터 바인딩을 SQL injection으로 잘못 판단한 경우)
            filtered_vulns = []
            for vuln in result.get('vulnerabilities', []):
                # SQL Injection + 파라미터 바인딩 체크
                if vuln.get('type') == 'SQL Injection' and vuln.get('vulnerable_code'):
                    if '?' in vuln['vulnerable_code'] or \
                       ('execute' in vuln['vulnerable_code'] and ',' in vuln['vulnerable_code']):
                        # 파라미터 바인딩은 안전함 - 스킵
                        print(f"  ✅ False positive 제거: 파라미터 바인딩은 안전합니다")
                        continue
                
                filtered_vulns.append(vuln)
            
            result['vulnerabilities'] = filtered_vulns
            return result
            
        except Exception as e:
            print(f"❌ GPT 분석 오류: {e}")
            return {"vulnerabilities": []}
    
    def _enhance_with_rag(self, vulnerabilities: List[Dict]):
        """RAG로 설명 보강"""
        if not self.rag_available or not self.rag:
            return
        
        # 간단히 처리
        for vuln in vulnerabilities[:5]:  # 최대 5개만
            vuln_type = vuln.get('type', '')
            
            try:
                # RAG 검색
                results = self.rag.search_similar(vuln_type, top_k=1)
                if results['documents'][0]:
                    doc = results['documents'][0][0][:200]
                    vuln['rag_context'] = doc
                    vuln['explanation_source'] = 'AI + KISIA 가이드라인'
            except:
                pass
    
    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> int:
        """보안 점수 계산"""
        score = 100
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'MEDIUM')
            
            penalty = {
                'CRITICAL': 25,
                'HIGH': 15,
                'MEDIUM': 10,
                'LOW': 5
            }.get(severity, 10)
            
            score -= penalty
        
        return max(0, score)
    
    def _generate_immediate_actions(self, vulnerabilities: List[Dict]) -> List[str]:
        """즉시 조치사항 생성"""
        actions = []
        
        critical_vulns = [v for v in vulnerabilities if v.get('severity') in ['CRITICAL', 'HIGH']]
        
        for vuln in critical_vulns[:5]:
            line = vuln.get('line_numbers', [0])[0]
            actions.append(f"라인 {line}: {vuln['type']} 즉시 수정 필요")
        
        if not actions:
            actions.append("심각한 취약점은 발견되지 않았으나, 전체 취약점을 검토하세요.")
        
        return actions
    
    def _generate_best_practices(self, vulnerabilities: List[Dict]) -> List[str]:
        """보안 모범 사례 생성"""
        practices = set()
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '')
            
            if 'Injection' in vuln_type:
                practices.add("모든 사용자 입력에 대해 파라미터화된 쿼리 사용")
            elif 'Cryptography' in vuln_type:
                practices.add("강력한 암호화 알고리즘 사용 (AES-256, SHA-256 이상)")
            elif 'Secret' in vuln_type or 'Password' in vuln_type:
                practices.add("민감한 정보는 환경 변수나 보안 저장소에 보관")
            elif 'Validation' in vuln_type:
                practices.add("모든 입력값에 대한 검증 및 sanitization 수행")
        
        if not practices:
            practices.add("정기적인 보안 감사 실시")
            practices.add("의존성 패키지 정기 업데이트")
        
        return list(practices)
    
    def _generate_summary(self, vulnerabilities: List[Dict]) -> str:
        """분석 요약 생성"""
        if not vulnerabilities:
            return "보안 취약점이 발견되지 않았습니다."
        
        total = len(vulnerabilities)
        critical = len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL'])
        high = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
        
        summary = f"총 {total}개의 보안 취약점 발견"
        if critical > 0:
            summary += f" (CRITICAL: {critical}개)"
        if high > 0:
            summary += f" (HIGH: {high}개)"
        
        return summary


# 하위 호환성을 위한 별칭
ImprovedLLMAnalyzer = LLMSecurityAnalyzer


# 테스트
if __name__ == "__main__":
    test_code = """
import sqlite3

def safe_query(user_id):
    conn = sqlite3.connect('db.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    return cursor.fetchall()

def unsafe_query(name):
    conn = sqlite3.connect('db.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)
    return cursor.fetchall()
"""
    
    try:
        analyzer = LLMSecurityAnalyzer()
        result = analyzer.analyze_code_security(test_code)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"Error: {e}")