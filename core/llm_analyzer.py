# core/llm_analyzer.py
"""
LLM 기반 코드 보안 분석 모듈 - 프롬프트 분리 버전
"""
from openai import OpenAI
import json
import os
from typing import Dict, List, Optional
from rag.simple_rag import SimpleRAG

# 프롬프트 임포트
try:
    from prompts.security_prompts import (
        SYSTEM_PROMPT,
        get_analysis_prompt,
        get_rag_prompt,
        translate_vulnerability_type,
        get_common_fix,
        SEVERITY_DESCRIPTIONS
    )
except ImportError:
    # 프롬프트 파일이 없으면 기본값 사용
    SYSTEM_PROMPT = "You are a Python security expert. Respond with JSON only."
    def get_analysis_prompt(code): return f"Analyze this code:\n{code}"
    def translate_vulnerability_type(t): return t
    def get_common_fix(t): return {}
    SEVERITY_DESCRIPTIONS = {}

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
        코드 보안 분석 메인 함수 - 최적화 버전
        1. GPT가 취약점 탐지
        2. 설명과 수정을 한 번에 생성
        """
        
        # 1단계: GPT로 취약점 탐지 + 수정까지 한번에
        print("🔍 AI 보안 분석 시작...")
        result = self._gpt_analyze_all_at_once(code)
        
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
        
        vulnerabilities = result['vulnerabilities']
        
        # 2단계: RAG로 설명 보강 (선택적, 빠르게)
        if self.rag_available:
            self._enhance_with_rag(vulnerabilities)
        
        # 3단계: 보안 점수 및 권장사항
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
    
    def _gpt_analyze_all_at_once(self, code: str) -> Dict:
        """GPT로 탐지, 설명, 수정을 한 번에 처리 (프롬프트 파일 사용)"""
        
        # 코드에 라인 번호 추가
        lines = code.split('\n')
        code_with_lines = '\n'.join([f"{i+1:3}: {line}" for i, line in enumerate(lines)])
        
        # 프롬프트 파일에서 가져오기
        prompt = get_analysis_prompt(code_with_lines)
        
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
            
            # 후처리: 한글 번역 및 설명 개선
            for vuln in result.get('vulnerabilities', []):
                # 취약점 타입 한글 추가
                if 'type' in vuln:
                    vuln['type_korean'] = translate_vulnerability_type(vuln['type'])
                
                # 설명이 너무 짧으면 보강
                if vuln.get('description', '') and len(vuln['description']) < 20:
                    common_fix = get_common_fix(vuln['type'])
                    if common_fix:
                        vuln['description'] = f"{vuln['description']}. {common_fix.get('pattern', '')}을 사용하면 위험합니다."
                
                # 영향도 설명 추가
                if not vuln.get('impact'):
                    severity = vuln.get('severity', 'MEDIUM')
                    vuln['impact'] = SEVERITY_DESCRIPTIONS.get(severity, '')
                
                vuln['explanation_source'] = 'AI 분석'
            
            return result
            
        except Exception as e:
            print(f"❌ GPT 분석 오류: {e}")
            return {"vulnerabilities": []}
    
    def _enhance_with_rag(self, vulnerabilities: List[Dict]):
        """RAG로 설명 보강 - 간결하고 정확하게"""
        
        if not self.rag_available:
            return
        
        # 타입별로 한 번만 검색
        searched_types = {}
        
        for vuln in vulnerabilities[:5]:  # 최대 5개만 RAG 검색
            vuln_type = vuln.get('type', '')
            
            if vuln_type not in searched_types:
                # RAG 검색 및 정제
                rag_result = self._search_and_refine_rag(vuln_type)
                if rag_result:
                    searched_types[vuln_type] = rag_result
            
            # RAG 설명이 있으면 추가 (대체가 아닌 보강)
            if vuln_type in searched_types:
                # AI 설명은 그대로 유지
                ai_description = vuln.get('description', '')
                rag_enhancement = searched_types[vuln_type]
                
                # RAG 설명을 별도 필드로 저장 (UI에서 구분 표시)
                vuln['ai_description'] = ai_description
                vuln['rag_explanation'] = rag_enhancement
                vuln['explanation_source'] = 'AI 분석 + KISIA 가이드라인'
                
                # 전체 설명은 간결하게 유지
                vuln['explanation'] = ai_description  # 기본은 AI 설명만
    
    def _search_and_refine_rag(self, vuln_type: str) -> Optional[str]:
        """RAG 검색 후 GPT로 정제 - 관련 내용만 추출"""
        if not self.rag_available:
            return None
        
        try:
            # 한글 변환
            korean_type = translate_vulnerability_type(vuln_type)
            
            # 더 정확한 검색 쿼리
            search_queries = [
                f"{korean_type} 취약점",
                f"{korean_type} 공격",
                f"{korean_type} 방어"
            ]
            
            relevant_docs = []
            for query in search_queries:
                results = self.rag.search_similar(query, top_k=1)
                if results['documents'][0]:
                    doc = results['documents'][0][0]
                    # 관련성 체크 - 해당 취약점 키워드가 있는 문서만
                    if korean_type in doc or vuln_type.lower() in doc.lower():
                        relevant_docs.append(doc[:300])  # 300자만
            
            if not relevant_docs:
                return None
            
            # 가장 관련성 높은 문서만 사용
            rag_context = relevant_docs[0] if relevant_docs else ""
            
            # GPT로 정제 - 관련 내용만 추출
            prompt = f"""다음 텍스트에서 {korean_type} 취약점에 대한 설명만 추출하세요.

[텍스트]
{rag_context}

[요구사항]
- {korean_type}에 대한 내용만 추출
- 다른 취약점 설명 제외
- 최대 2문장, 100자 이내
- 핵심만 간결하게

설명:"""
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "보안 전문가. 요청된 취약점 정보만 정확히 추출."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,  # 더 정확한 추출을 위해 낮춤
                max_tokens=150
            )
            
            refined_explanation = response.choices[0].message.content.strip()
            
            # 너무 짧거나 관련 없는 내용이면 무시
            if len(refined_explanation) < 20 or korean_type not in refined_explanation:
                return None
                
            return refined_explanation
                
        except Exception as e:
            print(f"RAG 검색 오류: {e}")
        
        return None
    
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
        """각 취약점에 대한 설명 추가 - 배치 처리로 속도 개선"""
        
        if not vulnerabilities:
            return vulnerabilities
        
        # RAG 사용 가능하면 먼저 일괄 검색
        rag_explanations = {}
        if self.rag_available:
            print(f"📚 RAG에서 {len(vulnerabilities)}개 취약점 설명 검색...")
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', '')
                if vuln_type not in rag_explanations:
                    rag_explanations[vuln_type] = self._search_rag_explanation(vuln_type)
        
        # 배치로 수정 코드 생성 (한 번의 GPT 호출로 모든 수정 생성)
        if len(vulnerabilities) <= 3:
            # 3개 이하면 개별 처리 (더 정확)
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', '')
                
                # RAG 설명 사용 또는 GPT 생성
                if vuln_type in rag_explanations and rag_explanations[vuln_type]:
                    vuln['explanation'] = rag_explanations[vuln_type]
                    vuln['explanation_source'] = 'KISIA 가이드라인'
                else:
                    vuln['explanation'] = self._gpt_generate_explanation(vuln)
                    vuln['explanation_source'] = 'AI 생성'
                
                # 수정 코드 생성
                vuln['recommended_fix'] = self._gpt_generate_fix(vuln, code)
        else:
            # 4개 이상이면 배치 처리 (빠름)
            print(f"⚡ {len(vulnerabilities)}개 취약점 배치 처리...")
            
            # 설명은 RAG 또는 간단 생성
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', '')
                if vuln_type in rag_explanations and rag_explanations[vuln_type]:
                    vuln['explanation'] = rag_explanations[vuln_type]
                    vuln['explanation_source'] = 'KISIA 가이드라인'
                else:
                    vuln['explanation'] = vuln.get('description', '')  # 기본 설명 사용
                    vuln['explanation_source'] = 'AI 생성'
            
            # 수정 코드는 배치로 생성
            fixes = self._batch_generate_fixes(vulnerabilities, code)
            for i, vuln in enumerate(vulnerabilities):
                vuln['recommended_fix'] = fixes[i] if i < len(fixes) else None
        
        return vulnerabilities
    
    def _batch_generate_fixes(self, vulnerabilities: List[Dict], code: str) -> List[Dict]:
        """여러 취약점의 수정 코드를 한 번에 생성 (속도 개선)"""
        
        # 취약점 요약
        vuln_summary = []
        for i, vuln in enumerate(vulnerabilities[:10]):  # 최대 10개만
            vuln_summary.append(f"{i+1}. {vuln['type']} (라인 {vuln.get('line_numbers', ['?'])[0]}): {vuln.get('vulnerable_code', '')[:50]}")
        
        prompt = f"""
        다음 Python 코드의 여러 취약점을 수정하세요.
        
        취약점 목록:
        {chr(10).join(vuln_summary)}
        
        각 취약점에 대해 간단한 수정 코드를 제시하세요.
        JSON 배열 형식으로 응답:
        [
            {{
                "original_code": "취약한 코드",
                "fixed_code": "수정된 코드",
                "description": "변경 설명"
            }},
            ...
        ]
        """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "Python 보안 전문가. 간결한 수정 코드 제공."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=1500
            )
            
            result_text = response.choices[0].message.content
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0]
            
            fixes = json.loads(result_text.strip())
            
            # Dict 형태로 변환
            return [
                {
                    "original_code": fix.get("original_code", ""),
                    "fixed_code": fix.get("fixed_code", ""),
                    "description": fix.get("description", ""),
                    "imports": [],
                    "confidence": 0.7
                }
                for fix in fixes
            ]
            
        except Exception as e:
            print(f"배치 수정 생성 실패: {e}")
            # 실패시 빈 수정 반환
            return [{"fixed_code": "# 자동 수정 실패", "description": "수동 수정 필요"} for _ in vulnerabilities]
    
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
    
    def _gpt_generate_fix(self, vuln: Dict, code: str) -> Dict:
        """GPT로 실제 수정 코드 생성"""
        vulnerable_code = vuln.get('vulnerable_code', '')
        line_numbers = vuln.get('line_numbers', [])
        
        # 코드 컨텍스트 추출 (취약한 라인 전후 포함)
        code_lines = code.split('\n')
        context_start = max(0, line_numbers[0] - 3) if line_numbers else 0
        context_end = min(len(code_lines), line_numbers[0] + 2) if line_numbers else len(code_lines)
        code_context = '\n'.join(code_lines[context_start:context_end])
        
        prompt = f"""
        다음 Python 코드의 보안 취약점을 수정하세요.
        
        취약점 종류: {vuln['type']}
        취약한 코드 라인: {vulnerable_code}
        
        코드 컨텍스트:
        ```python
        {code_context}
        ```
        
        JSON 형식으로 응답:
        {{
            "original_code": "취약한 원본 코드 (해당 라인만)",
            "fixed_code": "수정된 코드 (동일한 기능 유지)",
            "changes_description": "무엇을 어떻게 바꿨는지 간단 설명",
            "additional_imports": ["필요한 추가 import 문"],
            "confidence": 0.0-1.0
        }}
        
        중요: 
        - 원본 기능은 그대로 유지하면서 보안 취약점만 수정
        - 실제로 실행 가능한 코드 제공
        - 필요한 import 문도 명시
        """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "Python 보안 전문가. 실제 동작하는 수정 코드를 JSON으로 제공."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=500
            )
            
            result_text = response.choices[0].message.content
            
            # JSON 파싱
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0]
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0]
            
            import json
            fix_data = json.loads(result_text.strip())
            
            return {
                "original_code": fix_data.get("original_code", vulnerable_code),
                "fixed_code": fix_data.get("fixed_code", "# 수정 코드 생성 실패"),
                "description": fix_data.get("changes_description", ""),
                "imports": fix_data.get("additional_imports", []),
                "confidence": fix_data.get("confidence", 0.5)
            }
            
        except Exception as e:
            # 실패 시 기본 제안
            return {
                "original_code": vulnerable_code,
                "fixed_code": "# 자동 수정 실패 - 수동 수정 필요",
                "description": f"수정 코드 생성 실패: {str(e)}",
                "imports": [],
                "confidence": 0.0
            }
    
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