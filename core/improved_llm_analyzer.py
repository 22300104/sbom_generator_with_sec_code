# core/improved_llm_analyzer.py
"""
개선된 LLM 보안 분석기
- LLM이 자유롭게 취약점 발견
- RAG로 공식 가이드라인 근거 제시
"""
import os
import json
from typing import Dict, List, Optional, Tuple
from openai import OpenAI
from anthropic import Anthropic

class ImprovedSecurityAnalyzer:
    """AI 기반 보안 분석기 - 패턴 매칭 없이 자유로운 분석"""
    
    def __init__(self, use_claude: bool = True):
        """
        Args:
            use_claude: Claude를 우선 사용할지 여부
        """
        self.use_claude = use_claude
        self.claude_client = None
        self.openai_client = None
        
        # Claude 초기화
        if use_claude and os.getenv("ANTHROPIC_API_KEY"):
            try:
                self.claude_client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
                print("✅ Claude API 초기화 성공")
            except Exception as e:
                print(f"⚠️ Claude 초기화 실패: {e}")
        
        # OpenAI 초기화
        if os.getenv("OPENAI_API_KEY"):
            try:
                self.openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
                print("✅ OpenAI API 초기화 성공")
            except Exception as e:
                print(f"⚠️ OpenAI 초기화 실패: {e}")
        
        # RAG 시스템 초기화 (선택적)
        self.rag = None
        try:
            from rag.simple_rag import SimpleRAG
            self.rag = SimpleRAG()
            print("✅ RAG 시스템 로드 성공")
        except Exception as e:
            print(f"⚠️ RAG 시스템 로드 실패: {e}")
    
    def analyze_security(self, code: str, file_list: List[Dict] = None) -> Dict:
        """
        코드 보안 분석 - 자유로운 AI 분석
        
        Args:
            code: 분석할 Python 코드
            file_list: 파일 목록 정보
        
        Returns:
            분석 결과 딕셔너리
        """
        print("🔍 AI 보안 분석 시작...")
        
        # 1단계: AI가 자유롭게 취약점 발견
        vulnerabilities = self._discover_vulnerabilities(code, file_list)
        
        if not vulnerabilities:
            return {
                'success': True,
                'vulnerabilities': [],
                'security_score': 100,
                'summary': '취약점이 발견되지 않았습니다.',
                'analyzed_by': 'AI'
            }
        
        # 2단계: RAG로 각 취약점에 대한 근거 찾기
        if self.rag:
            vulnerabilities = self._add_rag_evidence(vulnerabilities)
        
        # 3단계: 보안 점수 계산
        security_score = self._calculate_security_score(vulnerabilities)
        
        # 4단계: 요약 생성
        summary = self._generate_summary(vulnerabilities)
        
        return {
            'success': True,
            'vulnerabilities': vulnerabilities,
            'security_score': security_score,
            'summary': summary,
            'analyzed_by': 'Claude' if self.use_claude and self.claude_client else 'GPT'
        }
    
    def _discover_vulnerabilities(self, code: str, file_list: List[Dict] = None) -> List[Dict]:
        """AI가 자유롭게 취약점 발견"""
        
        # 프롬프트 - 패턴 매칭이 아닌 추론 유도
        prompt = self._build_discovery_prompt(code, file_list)
        
        # Claude 우선 시도
        if self.use_claude and self.claude_client:
            try:
                return self._analyze_with_claude(prompt)
            except Exception as e:
                print(f"⚠️ Claude 분석 실패, GPT로 전환: {e}")
        
        # GPT로 분석
        if self.openai_client:
            try:
                return self._analyze_with_gpt(prompt)
            except Exception as e:
                print(f"❌ GPT 분석 실패: {e}")
        
        return []
    
    def _build_discovery_prompt(self, code: str, file_list: List[Dict] = None) -> str:
        """취약점 발견을 위한 프롬프트 생성"""
        
        # 파일 정보 추가
        file_info = ""
        if file_list:
            file_info = f"\n분석 대상: {len(file_list)}개 파일\n"
            for f in file_list[:5]:  # 상위 5개만
                file_info += f"- {f['path']} ({f['lines']}줄)\n"
        
        prompt = f"""
당신은 숙련된 보안 전문가입니다.
다음 Python 코드를 분석하여 보안 취약점을 찾아주세요.

{file_info}

**중요한 분석 지침:**
1. 미리 정의된 패턴을 찾지 말고, 코드의 실제 동작을 이해하세요
2. 데이터 흐름을 추적하세요: 외부 입력 → 처리 → 출력/저장
3. 각 함수가 무엇을 하는지, 어떤 위험이 있는지 추론하세요
4. 컨텍스트를 고려하세요: 같은 코드라도 상황에 따라 위험도가 다릅니다

**분석 방법:**
Step 1: 외부 입력점 식별 (user input, file, network, env)
Step 2: 각 입력이 어떻게 처리되는지 추적
Step 3: 위험한 작업으로 흐르는지 확인 (DB, file, system, network)
Step 4: 검증/이스케이프 과정이 있는지 확인
Step 5: 실제 악용 가능한지 판단

**코드:**
```python
{code[:30000]}  # 토큰 제한
```

발견한 모든 취약점을 JSON 형식으로 보고하세요:
{{
    "vulnerabilities": [
        {{
            "type": "취약점 유형 (예: SQL Injection, XSS 등)",
            "severity": "CRITICAL/HIGH/MEDIUM/LOW",
            "confidence": "HIGH/MEDIUM/LOW (확신도)",
            "location": {{
                "file": "파일명",
                "line": 라인번호,
                "function": "함수명"
            }},
            "description": "취약점 설명",
            "data_flow": "데이터가 어떻게 흘러서 위험해지는지",
            "exploit_scenario": "실제 공격 시나리오",
            "recommendation": "개선 방법"
        }}
    ]
}}

추론 과정을 보여주되, 최종 응답은 반드시 JSON만 포함하세요.
- JSON 키(key)는 영어 유지
- JSON 값(value) 중 설명, 이유, 시나리오, 권장사항 등 모든 텍스트는 한국어로 작성
"""
        return prompt
    
    # core/improved_llm_analyzer.py
    # _analyze_with_claude() 함수 수정 (라인 246 근처)

    def _analyze_with_claude(self, prompt: str) -> List[Dict]:
        """Claude로 분석"""
        response = self.claude_client.messages.create(
            model="claude-opus-4-20250514",  # 오타 수정: 202402299 → 20240229
            max_tokens=4000,
            temperature=0.3,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
    # ... 나머지 코드
        
        # JSON 파싱
        result_text = response.content[0].text
        
        # JSON 부분만 추출
        if "```json" in result_text:
            result_text = result_text.split("```json")[1].split("```")[0]
        elif "{" in result_text:
            # JSON 시작 위치 찾기
            start = result_text.find("{")
            end = result_text.rfind("}") + 1
            if start >= 0 and end > start:
                result_text = result_text[start:end]
        
        try:
            result = json.loads(result_text.strip())
            return result.get('vulnerabilities', [])
        except json.JSONDecodeError as e:
            print(f"JSON 파싱 오류: {e}")
            return []
    
    def _analyze_with_gpt(self, prompt: str) -> List[Dict]:
        """GPT로 분석"""
        response = self.openai_client.chat.completions.create(
            model="gpt-4" if "gpt-4" in os.getenv("OPENAI_MODEL", "") else "gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": "You are a security expert. Analyze code for vulnerabilities. Respond with JSON only."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
            max_tokens=2000
        )
        
        result_text = response.choices[0].message.content
        
        # JSON 파싱
        if "```json" in result_text:
            result_text = result_text.split("```json")[1].split("```")[0]
        
        try:
            result = json.loads(result_text.strip())
            return result.get('vulnerabilities', [])
        except json.JSONDecodeError as e:
            print(f"JSON 파싱 오류: {e}")
            return []
    
    def _add_rag_evidence(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """각 취약점에 RAG 근거 추가"""
        if not self.rag:
            return vulnerabilities
        
        print("📚 RAG로 공식 가이드라인 근거 찾는 중...")
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '')
            
            # RAG에서 관련 가이드라인 검색
            search_query = f"{vuln_type} 방어 방법 보안 가이드라인"
            results = self.rag.search_similar(search_query, top_k=2)
            
            if results['documents'] and results['documents'][0]:
                # 가장 관련성 높은 문서
                evidence = results['documents'][0][0]
                
                # 메타데이터가 있으면 페이지 정보 추가
                if results.get('metadatas') and results['metadatas'][0]:
                    page = results['metadatas'][0][0].get('page', '?')
                    vuln['evidence'] = {
                        'source': 'KISIA Python 시큐어코딩 가이드',
                        'page': page,
                        'content': evidence[:500] + "..." if len(evidence) > 500 else evidence
                    }
                else:
                    vuln['evidence'] = {
                        'source': 'KISIA 가이드라인',
                        'content': evidence[:500] + "..." if len(evidence) > 500 else evidence
                    }
        
        return vulnerabilities
    
    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> int:
        """보안 점수 계산"""
        if not vulnerabilities:
            return 100
        
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
            
            # 확신도에 따른 가중치
            confidence_weight = {
                'HIGH': 1.0,
                'MEDIUM': 0.7,
                'LOW': 0.4
            }.get(confidence, 0.7)
            
            score -= int(severity_penalty * confidence_weight)
        
        return max(0, score)
    
    def _generate_summary(self, vulnerabilities: List[Dict]) -> str:
        """분석 요약 생성"""
        if not vulnerabilities:
            return "코드 분석 결과 보안 취약점이 발견되지 않았습니다."
        
        total = len(vulnerabilities)
        critical = sum(1 for v in vulnerabilities if v.get('severity') == 'CRITICAL')
        high = sum(1 for v in vulnerabilities if v.get('severity') == 'HIGH')
        
        summary = f"총 {total}개의 보안 취약점이 발견되었습니다"
        
        if critical > 0:
            summary += f" (CRITICAL: {critical}개)"
        if high > 0:
            summary += f" (HIGH: {high}개)"
        
        # 주요 취약점 타입
        vuln_types = list(set(v.get('type', 'Unknown') for v in vulnerabilities))
        if vuln_types:
            summary += f". 주요 유형: {', '.join(vuln_types[:3])}"
        
        return summary


# 간단한 사용 헬퍼 함수
def analyze_code_with_ai(code: str, file_list: List[Dict] = None, use_claude: bool = True) -> Dict:
    """
    코드를 AI로 분석하는 헬퍼 함수
    
    Args:
        code: 분석할 Python 코드
        file_list: 파일 목록
        use_claude: Claude 우선 사용 여부
    
    Returns:
        분석 결과
    """
    analyzer = ImprovedSecurityAnalyzer(use_claude=use_claude)
    return analyzer.analyze_security(code, file_list)