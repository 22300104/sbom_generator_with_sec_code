# core/llm_analyzer.py
"""
LLM 기반 코드 보안 분석 모듈 - GPT 우선 버전
패턴 매칭 제거, GPT가 메인 탐지, RAG는 설명 보강용
"""
from openai import OpenAI
import json
import os
from typing import Dict, List, Optional
from rag.simple_rag import SimpleRAG

class LLMSecurityAnalyzer:
    """GPT 중심 보안 분석기"""
    
    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY 환경 변수가 설정되지 않았습니다.")
        
        self.client = OpenAI(api_key=api_key)
        self.model = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
        
        # RAG 시스템 (설명 보강용)
        try:
            self.rag = SimpleRAG()
            self.rag_available = True
        except:
            self.rag = None
            self.rag_available = False
            print("⚠️ RAG 시스템 로드 실패 - GPT 설명만 사용됩니다.")
    
    def analyze_code_security(self, code: str, context: Dict = None) -> Dict:
        """
        코드 보안 분석 메인 함수
        1. GPT가 취약점 탐지
        2. RAG로 공식 설명 검색
        3. 없으면 GPT가 설명 생성
        """
        
        # 1단계: GPT로 취약점 탐지
        print("🔍 GPT 보안 분석 시작...")
        vulnerabilities = self._gpt_detect_vulnerabilities(code)
        
        if not vulnerabilities:
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
        
        # 2단계: 각 취약점에 대한 설명 추가
        print(f"📚 {len(vulnerabilities)}개 취약점에 대한 설명 생성 중...")
        enhanced_vulnerabilities = self._add_explanations(vulnerabilities, code)
        
        # 3단계: 보안 점수 계산 및 권장사항 생성
        security_score = self._calculate_security_score(enhanced_vulnerabilities)
        immediate_actions = self._generate_immediate_actions(enhanced_vulnerabilities)
        best_practices = self._generate_best_practices(enhanced_vulnerabilities)
        
        return {
            "success": True,
            "analysis": {
                "code_vulnerabilities": enhanced_vulnerabilities,
                "security_score": security_score,
                "summary": self._generate_summary(enhanced_vulnerabilities),
                "immediate_actions": immediate_actions,
                "best_practices": best_practices
            },
            "metadata": {
                "gpt_model": self.model,
                "rag_available": self.rag_available,
                "total_vulnerabilities": len(enhanced_vulnerabilities)
            }
        }
    
    def _gpt_detect_vulnerabilities(self, code: str) -> List[Dict]:
        """GPT를 사용한 취약점 탐지 (메인 엔진)"""
        
        # 코드에 라인 번호 추가
        lines = code.split('\n')
        code_with_lines = '\n'.join([f"{i+1:3}: {line}" for i, line in enumerate(lines)])
        
        prompt = f"""
        당신은 Python 보안 전문가입니다. 아래 코드를 분석하여 보안 취약점을 찾아주세요.
        
        [분석할 코드]
        ```python
        {code_with_lines}
        ```
        
        다음과 같은 취약점을 중점적으로 확인하세요:
        1. 인젝션 공격 (SQL, Command, Code, Path 등)
        2. 인증/인가 문제
        3. 암호화 관련 문제 (약한 알고리즘, 하드코딩된 키)
        4. 입력값 검증 부재
        5. 민감 정보 노출
        6. 안전하지 않은 역직렬화
        7. XXE, XSS, CSRF 등 웹 취약점
        8. 경쟁 조건, 리소스 관리 문제
        9. 에러 처리 미흡
        10. 기타 보안 문제
        
        각 취약점에 대해 정확한 라인 번호를 포함해서 JSON 형식으로 응답하세요:
        {{
            "vulnerabilities": [
                {{
                    "type": "취약점 종류 (예: SQL Injection)",
                    "severity": "CRITICAL/HIGH/MEDIUM/LOW",
                    "line_numbers": [라인번호들],
                    "vulnerable_code": "취약한 코드 부분",
                    "description": "취약점에 대한 간단한 설명",
                    "cwe_id": "CWE-XX (해당하는 경우)",
                    "confidence": "HIGH/MEDIUM/LOW (탐지 확신도)"
                }}
            ]
        }}
        
        취약점이 없으면 빈 배열을 반환하세요.
        반드시 유효한 JSON만 응답하세요.
        """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system", 
                        "content": "You are a security expert specializing in Python code analysis. Always respond with valid JSON."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,  # 낮은 temperature로 일관성 있는 결과
                max_tokens=2000
            )
            
            result_text = response.choices[0].message.content
            
            # JSON 파싱
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0]
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0]
            
            result = json.loads(result_text.strip())
            return result.get("vulnerabilities", [])
            
        except json.JSONDecodeError as e:
            print(f"❌ JSON 파싱 오류: {e}")
            return []
        except Exception as e:
            print(f"❌ GPT 분석 오류: {e}")
            return []
    
    def _add_explanations(self, vulnerabilities: List[Dict], code: str) -> List[Dict]:
        """각 취약점에 대한 설명 추가 (RAG 우선, 없으면 GPT)"""
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '')
            
            # RAG에서 공식 가이드라인 검색
            if self.rag_available:
                rag_explanation = self._search_rag_explanation(vuln_type)
                if rag_explanation:
                    vuln['explanation'] = rag_explanation
                    vuln['explanation_source'] = 'KISIA 가이드라인'
                    
                    # RAG에서 수정 방법도 검색
                    rag_fix = self._search_rag_fix(vuln_type)
                    if rag_fix:
                        vuln['recommended_fix'] = rag_fix
                    else:
                        vuln['recommended_fix'] = self._gpt_generate_fix(vuln, code)
                else:
                    # RAG에 없으면 GPT가 설명 생성
                    vuln['explanation'] = self._gpt_generate_explanation(vuln)
                    vuln['explanation_source'] = 'AI 생성'
                    vuln['recommended_fix'] = self._gpt_generate_fix(vuln, code)
            else:
                # RAG 없으면 GPT만 사용
                vuln['explanation'] = self._gpt_generate_explanation(vuln)
                vuln['explanation_source'] = 'AI 생성'
                vuln['recommended_fix'] = self._gpt_generate_fix(vuln, code)
        
        return vulnerabilities
    
    def _search_rag_explanation(self, vuln_type: str) -> Optional[str]:
        """RAG에서 취약점 설명 검색하고 GPT로 정제"""
        if not self.rag_available:
            return None
        
        # 취약점 타입을 한글로 매핑
        type_mapping = {
            'SQL Injection': 'SQL 삽입',
            'Command Injection': '명령어 삽입',
            'Path Traversal': '경로 조작',
            'XSS': '크로스사이트 스크립팅',
            'Weak Cryptography': '취약한 암호화',
            'Hardcoded Secret': '하드코딩된 패스워드',
            'Insecure Deserialization': '안전하지 않은 역직렬화'
        }
        
        korean_type = type_mapping.get(vuln_type, vuln_type)
        search_query = f"{korean_type} 취약점 보안약점"
        
        try:
            results = self.rag.search_similar(search_query, top_k=2)
            if results['documents'][0]:
                # RAG 문서를 컨텍스트로 사용
                rag_context = '\n'.join(results['documents'][0][:2])
                
                # GPT가 RAG 지식을 바탕으로 깔끔하게 설명
                prompt = f"""
                KISIA Python 시큐어코딩 가이드의 내용을 바탕으로 {vuln_type} 취약점을 설명하세요.
                
                [가이드라인 내용]
                {rag_context}
                
                위 내용을 참고하여 다음을 포함해 150자 이내로 깔끔하게 설명:
                1. 취약점이 무엇인지
                2. 왜 위험한지
                3. 핵심 방어 방법
                
                페이지 번호나 코드 라인 번호는 제외하고 설명만 작성하세요.
                """
                
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "KISIA 시큐어코딩 가이드 전문가. 간결하고 명확하게 설명."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                    max_tokens=300
                )
                
                return response.choices[0].message.content.strip()
        except:
            pass
        
        return None
    
    def _search_rag_fix(self, vuln_type: str) -> Optional[str]:
        """RAG에서 수정 방법 검색하고 GPT로 정제"""
        if not self.rag_available:
            return None
        
        search_query = f"{vuln_type} 안전한 코드 수정 방법"
        
        try:
            results = self.rag.search_similar(search_query, top_k=2)
            if results['documents'][0]:
                rag_context = '\n'.join(results['documents'][0][:2])
                
                # GPT가 RAG 지식을 바탕으로 실용적인 수정 방법 제시
                prompt = f"""
                KISIA 가이드라인을 바탕으로 {vuln_type} 취약점의 수정 방법을 제시하세요.
                
                [가이드라인 참고 내용]
                {rag_context}
                
                위 내용을 참고하여 실제 적용 가능한 수정 방법을 3줄 이내로 제시:
                1. 구체적인 파이썬 코드나 함수명 언급
                2. 즉시 적용 가능한 해결책
                
                불필요한 설명 없이 핵심 해결 방법만 제시하세요.
                """
                
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "Python 보안 전문가. 실용적인 코드 수정 방법 제시."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                    max_tokens=200
                )
                
                return response.choices[0].message.content.strip()
        except:
            pass
        
        return None
    
    def _gpt_generate_explanation(self, vuln: Dict) -> str:
        """GPT로 취약점 설명 생성"""
        prompt = f"""
        다음 보안 취약점에 대해 간단하고 명확하게 설명하세요:
        - 종류: {vuln['type']}
        - 설명: {vuln['description']}
        
        100자 이내로 핵심만 설명하세요.
        """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "보안 전문가로서 간단명료하게 설명"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=200
            )
            return response.choices[0].message.content.strip()
        except:
            return vuln.get('description', '설명 생성 실패')
    
    def _gpt_generate_fix(self, vuln: Dict, code: str) -> str:
        """GPT로 수정 방법 생성"""
        vulnerable_code = vuln.get('vulnerable_code', '')
        
        prompt = f"""
        다음 취약한 코드를 안전하게 수정하는 방법을 제시하세요:
        
        취약점: {vuln['type']}
        취약한 코드: {vulnerable_code}
        
        구체적인 수정 코드를 제시하세요. 최대 3줄 이내로.
        """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "Python 보안 전문가"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=200
            )
            return response.choices[0].message.content.strip()
        except:
            return "수정 방법을 생성할 수 없습니다."
    
    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> int:
        """보안 점수 계산"""
        score = 100
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'MEDIUM')
            confidence = vuln.get('confidence', 'MEDIUM')
            
            # 심각도별 감점
            severity_penalty = {
                'CRITICAL': 25,
                'HIGH': 15,
                'MEDIUM': 10,
                'LOW': 5
            }.get(severity, 10)
            
            # 확신도에 따른 조정
            if confidence == 'LOW':
                severity_penalty = severity_penalty * 0.5
            elif confidence == 'HIGH':
                severity_penalty = severity_penalty * 1.2
            
            score -= severity_penalty
        
        return max(0, int(score))
    
    def _generate_immediate_actions(self, vulnerabilities: List[Dict]) -> List[str]:
        """즉시 조치사항 생성"""
        actions = []
        
        # CRITICAL/HIGH 우선
        critical_vulns = [v for v in vulnerabilities if v.get('severity') in ['CRITICAL', 'HIGH']]
        
        for vuln in critical_vulns[:5]:  # 최대 5개
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