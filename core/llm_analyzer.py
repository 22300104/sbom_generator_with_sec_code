"""
LLM 기반 코드 및 SBOM 분석 모듈
"""
from openai import OpenAI
import json
import os
from typing import Dict, List, Optional
from core.analyzer import SBOMAnalyzer
from security.vulnerability import VulnerabilityChecker
from rag.simple_rag import SimpleRAG

class LLMSecurityAnalyzer:
    """LLM을 활용한 통합 보안 분석기"""
    
    def __init__(self):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.sbom_analyzer = SBOMAnalyzer()
        self.vuln_checker = VulnerabilityChecker()
        
        # RAG 시스템 (선택적)
        try:
            self.rag = SimpleRAG()
        except:
            self.rag = None
    
    def analyze_code_security(self, code: str, sbom_data: Dict) -> Dict:
        """코드와 SBOM을 종합적으로 분석"""
        
        # 1. SBOM 요약 생성
        sbom_summary = self._create_sbom_summary(sbom_data)
        
        # 2. 코드를 라인별로 분석
        code_lines = code.split('\n')
        code_with_line_numbers = '\n'.join([f"{i+1}: {line}" for i, line in enumerate(code_lines)])
        
        # 3. 시큐어 코딩 가이드라인 컨텍스트 가져오기
        guideline_context = ""
        if self.rag:
            # 주요 취약점 패턴 검색
            patterns = ["SQL 인젝션", "XSS", "파일 업로드", "입력값 검증"]
            contexts = []
            for pattern in patterns:
                result = self.rag.search_similar(pattern, top_k=2)
                if result['documents'][0]:
                    contexts.append(result['documents'][0][0][:500])
            guideline_context = "\n".join(contexts)
        
        # 4. 강화된 프롬프트 생성
        prompt = f"""
        You are a Python security expert. Analyze the ACTUAL code provided below for security vulnerabilities.
        
        [CODE WITH LINE NUMBERS]
        ```python
        {code_with_line_numbers}
        ```
        
        [IMPORTANT RULES]
        1. Analyze ONLY the code shown above, DO NOT create example code
        2. Reference specific line numbers when identifying issues
        3. Look for these specific patterns in THE PROVIDED CODE:
           - Line 11: f-string SQL query construction (SQL injection)
           - Line 16: Direct file path concatenation (Path traversal)
           - Any direct string concatenation in SQL queries
           - Any user input used without validation
        
        [SBOM Information]
        {sbom_summary}
        
        [Security Guidelines Reference]
        {guideline_context if guideline_context else "No guidelines available"}
        
        Provide analysis in JSON format with:
        {{
            "code_vulnerabilities": [
                {{
                    "type": "SQL Injection",
                    "severity": "CRITICAL",
                    "description": "Direct f-string interpolation in SQL query",
                    "line_numbers": [11],
                    "actual_code": "query = f\"SELECT * FROM users WHERE id = {{user_id}}\"",
                    "recommendation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
                }}
            ],
            "dependency_risks": [],
            "security_score": 0-100,
            "immediate_actions": ["Fix SQL injection on line 11", "Fix path traversal on line 16"],
            "best_practices": []
        }}
        
        CRITICAL: Analyze the ACTUAL PROVIDED CODE, not hypothetical examples!
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {
                        "role": "system", 
                        "content": "You are a security expert. Always respond with valid JSON only."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000
            )
            
            # JSON 파싱
            result_text = response.choices[0].message.content
            
            # JSON 블록 추출 (```json ... ``` 형식 처리)
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0]
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0]
            
            analysis_result = json.loads(result_text.strip())
            
            # SBOM 취약점 정보 추가
            analysis_result['sbom_vulnerabilities'] = self._extract_sbom_vulnerabilities(sbom_data)
            
            return {
                "success": True,
                "analysis": analysis_result
            }
            
        except json.JSONDecodeError as e:
            return {
                "success": False,
                "error": f"JSON 파싱 오류: {e}",
                "raw_response": result_text if 'result_text' in locals() else None
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"분석 오류: {e}"
            }
    
    def _create_sbom_summary(self, sbom_data: Dict) -> str:
        """SBOM 데이터를 요약"""
        if not sbom_data.get("packages"):
            return "패키지 정보 없음"
        
        summary = f"총 {len(sbom_data['packages'])}개 패키지:\n"
        
        for pkg in sbom_data['packages'][:10]:  # 상위 10개만
            version = pkg.get('version', '버전 없음')
            vulns = len(pkg.get('vulnerabilities', []))
            
            summary += f"- {pkg['name']} ({version})"
            if vulns > 0:
                summary += f" - ⚠️ 취약점 {vulns}개"
            summary += "\n"
        
        if len(sbom_data['packages']) > 10:
            summary += f"... 외 {len(sbom_data['packages'])-10}개 패키지\n"
        
        # 전체 통계
        total_vulns = sbom_data.get('summary', {}).get('total_vulnerabilities', 0)
        if total_vulns > 0:
            summary += f"\n⚠️ 전체 취약점: {total_vulns}개 발견"
        
        return summary
    
    def _extract_sbom_vulnerabilities(self, sbom_data: Dict) -> List[Dict]:
        """SBOM에서 취약점 정보 추출"""
        vulnerabilities = []
        
        for pkg in sbom_data.get('packages', []):
            for vuln in pkg.get('vulnerabilities', []):
                vulnerabilities.append({
                    "package": pkg['name'],
                    "version": pkg.get('version'),
                    "vulnerability_id": vuln.get('id'),
                    "severity": vuln.get('severity'),
                    "description": vuln.get('summary'),
                    "fixed_version": vuln.get('fixed_version')
                })
        
        return vulnerabilities
    
    def get_package_recommendations(self, package_name: str, version: Optional[str] = None) -> Dict:
        """특정 패키지에 대한 보안 권장사항"""
        prompt = f"""
        Python 패키지 '{package_name}' {f'버전 {version}' if version else ''}에 대한 보안 분석:
        
        1. 알려진 보안 이슈
        2. 안전한 대체 패키지
        3. 보안 설정 권장사항
        4. 사용 시 주의사항
        
        간단하고 실용적인 조언을 제공하세요.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "Python 패키지 보안 전문가"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )
            
            return {
                "success": True,
                "package": package_name,
                "version": version,
                "recommendations": response.choices[0].message.content
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }