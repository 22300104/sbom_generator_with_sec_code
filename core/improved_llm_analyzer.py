# core/improved_llm_analyzer.py
"""
개선된 LLM 보안 분석기
- LLM이 자유롭게 취약점 발견
- RAG로 공식 가이드라인 근거 제시
"""
import os
import json
import re
from typing import Dict, List, Optional, Tuple
from openai import OpenAI
from anthropic import Anthropic
from prompts.all_prompts import build_security_analysis_prompt

class ImprovedSecurityAnalyzer:
    """AI 기반 보안 분석기 - Claude 우선"""
    
    def __init__(self, use_claude: bool = True):
        """
        Args:
            use_claude: Claude를 우선 사용할지 여부 (기본값: True)
        """
        self.use_claude = use_claude
        self.claude_client = None
        self.openai_client = None
        
        # Claude 초기화 (우선순위 1)
        if os.getenv("ANTHROPIC_API_KEY"):
            try:
                self.claude_client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
                print("✅ Claude API 초기화 성공 (메인 엔진)")
            except Exception as e:
                print(f"⚠️ Claude 초기화 실패: {e}")
        
        # OpenAI 초기화 (우선순위 2 - 폴백)
        if os.getenv("OPENAI_API_KEY"):
            try:
                self.openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
                print("✅ OpenAI API 초기화 성공 (폴백 엔진)")
            except Exception as e:
                print(f"⚠️ OpenAI 초기화 실패: {e}")
        
        # API 가용성 확인
        if not self.claude_client and not self.openai_client:
            raise ValueError("❌ Claude와 OpenAI API 모두 사용 불가능합니다.")
        
        # RAG 시스템 초기화 (선택적)
        self.rag = None
        try:
            from rag.improved_rag_search import ImprovedRAGSearch
            self.rag = ImprovedRAGSearch()
            print("✅ RAG 시스템 로드 성공")
        except Exception as e:
            print(f"⚠️ RAG 시스템 로드 실패: {e}")
    
    def analyze_security(self, code: str, file_list: List[Dict] = None) -> Dict:
        """코드 보안 분석 - 오류 처리 개선"""
        
        print("🔍 AI 보안 분석 시작...")
        
        # 1단계: AI가 취약점 발견 및 수정 코드 생성
        vulnerabilities = self._discover_vulnerabilities(code, file_list)
        
        # 오류 체크
        has_error = False
        error_message = ""
        
        if vulnerabilities:
            # 파싱 오류나 토큰 오류 체크
            for vuln in vulnerabilities:
                if vuln.get('parse_error') or vuln.get('token_error'):
                    has_error = True
                    error_message = vuln.get('description', 'AI 분석 오류')
                    break
        
        if has_error:
            return {
                'success': False,
                'vulnerabilities': vulnerabilities,
                'security_score': 0,
                'summary': f'⚠️ 분석 오류: {error_message}',
                'analyzed_by': 'Error',
                'has_error': True,
                'error_type': vulnerabilities[0].get('type', 'Unknown Error')
            }
        
        # 정상 처리
        if not vulnerabilities:
            return {
                'success': True,
                'vulnerabilities': [],
                'security_score': 100,
                'summary': '취약점이 발견되지 않았습니다.',
                'analyzed_by': 'AI',
                'has_error': False
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
            'analyzed_by': 'Claude' if self.use_claude and self.claude_client else 'GPT',
            'has_error': False
        }
    


    def _discover_vulnerabilities(self, code: str, file_list: List[Dict] = None) -> List[Dict]:
        """AI를 사용하여 취약점 발견 - use_claude 파라미터 적용"""
        
        prompt = self._build_discovery_prompt(code, file_list)
        print(f"📝 프롬프트 길이: {len(prompt)} 문자")
        print(f"📝 프롬프트 처음 500자:\\n{prompt[:500]}\\n")  # 프롬프트 내용 확인
        vulnerabilities = []
        
        # use_claude 설정에 따라 순서 결정
        if self.use_claude:
            # 1. Claude 우선 모드
            if self.claude_client:
                try:
                    print("🎭 Claude 분석 시작 (우선 엔진)...")
                    vulnerabilities = self._analyze_with_claude(prompt)
                    
                    if vulnerabilities and not any(v.get('parse_error') for v in vulnerabilities):
                        print(f"✅ Claude 분석 성공: {len(vulnerabilities)}개 취약점")
                        return vulnerabilities
                    elif vulnerabilities:
                        print("⚠️ Claude 파싱 오류, GPT로 폴백")
                except Exception as e:
                    print(f"⚠️ Claude 분석 실패: {e}, GPT로 폴백")
            else:
                print("⚠️ Claude API 없음, GPT로 전환")
            
            # Claude 실패 시 GPT 폴백
            if self.openai_client and not (vulnerabilities and not any(v.get('parse_error') for v in vulnerabilities)):
                try:
                    print("🤖 GPT 분석 시작 (폴백)...")
                    vulnerabilities = self._analyze_with_gpt(prompt)
                    
                    if vulnerabilities and not any(v.get('parse_error') for v in vulnerabilities):
                        print(f"✅ GPT 분석 성공: {len(vulnerabilities)}개 취약점")
                        return vulnerabilities
                except Exception as e:
                    print(f"❌ GPT 분석도 실패: {e}")
        
        else:
            # 2. GPT 전용 모드 (use_claude=False)
            if self.openai_client:
                try:
                    print("🤖 GPT 분석 시작 (전용 모드)...")
                    vulnerabilities = self._analyze_with_gpt(prompt)
                    
                    if vulnerabilities and not any(v.get('parse_error') for v in vulnerabilities):
                        print(f"✅ GPT 분석 성공: {len(vulnerabilities)}개 취약점")
                        return vulnerabilities
                except Exception as e:
                    print(f"❌ GPT 분석 실패: {e}")
                    # GPT 실패 시 Claude 시도 (있다면)
                    if self.claude_client:
                        try:
                            print("🎭 Claude로 재시도...")
                            vulnerabilities = self._analyze_with_claude(prompt)
                            
                            if vulnerabilities and not any(v.get('parse_error') for v in vulnerabilities):
                                print(f"✅ Claude 분석 성공: {len(vulnerabilities)}개 취약점")
                                return vulnerabilities
                        except Exception as e2:
                            print(f"❌ Claude도 실패: {e2}")
            else:
                print("❌ OpenAI API 없음")
        
        # 3. 모두 실패 시 에러 반환
        if not vulnerabilities:
            vulnerabilities = [{
                "type": "Analysis Failed",
                "severity": "ERROR",
                "confidence": "HIGH",
                "location": {"file": "unknown", "line": 0, "function": "unknown"},
                "description": "AI 분석 실패: 모든 AI 엔진이 응답하지 않습니다",
                "vulnerable_code": "분석 불가",
                "fixed_code": "분석 불가",
                "fix_explanation": "API 키와 모델 설정을 확인해주세요.",
                "recommendation": "1. .env 파일 확인\n2. API 크레딧 확인\n3. 네트워크 연결 확인",
                "parse_error": True
            }]
        
        return vulnerabilities
    
    
    # core/improved_llm_analyzer.py 수정
    

    def _build_discovery_prompt(self, code: str, file_list: List[Dict] = None) -> str:
        """취약점 발견 프롬프트 - 빌더 함수 활용"""
        
        file_info = ""
        if file_list:
            file_info = f"\n분석 대상: {len(file_list)}개 파일\n"
            for f in file_list[:5]:
                file_info += f"- {f['path']} ({f['lines']}줄)\n"

                 # 코드 길이 제한
        max_code_length = 25000  # 프롬프트 공간 확보
        if len(code) > max_code_length:
            code = code[:max_code_length] + "\n# ... (코드가 잘렸습니다)"
        
        prompt = f"""Python 보안 전문가로서 코드를 분석하고 JSON으로만 응답하세요.

    {file_info}

    분석할 코드:
    {code}

    다음 JSON 형식으로만 응답하세요. 추가 설명이나 인사말 없이 JSON만 출력하세요:

    {{
        "vulnerabilities": [
            {{
                "type": "영어로_작성_필수",  // MUST BE IN ENGLISH (e.g., "SQL Injection", "XSS", "Command Injection")
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
      * 기타 영어 표준 명칭

    주의: JSON만 출력. 다른 텍스트 없음."""
    
        return prompt
    
    def _analyze_with_claude(self, prompt: str) -> List[Dict]:
        """Claude로 분석 - Claude 특화 프롬프트"""
        try:
            # 환경변수에서 모델명 가져오기
            model = os.getenv("ANTHROPIC_MODEL")
            if not model:
                model = "claude-3-opus-20240229"
                print(f"⚠️ ANTHROPIC_MODEL 미설정, 기본값 사용: {model}")
            print(f"모델: {model}")
            print(f"API 키 존재: {bool(os.getenv('ANTHROPIC_API_KEY'))}")
            # Claude는 system role이 없으므로 user 메시지에 통합
            claude_prompt = """You are a senior security expert analyzing Python code.
    Respond ONLY with valid JSON. No explanations, no markdown.

    """ + prompt
            
            print(f"최종 프롬프트 길이: {len(claude_prompt)}")
            response = self.claude_client.messages.create(
                model=model,
                max_tokens=4000,
                temperature=0.2,
                messages=[
                    {
                        "role": "user",
                        "content": claude_prompt
                    }
                ]
            )
            
            # Claude 응답 추출 (content[0].text)
            result_text = response.content[0].text
            
            print(f"📝 Claude 응답 길이: {len(result_text)}")
            print(f"📝 Claude 응답 처음 500자:\\n{result_text[:500]}\\n")
            # 응답 로깅
            print(f"📝 Claude 응답 길이: {len(result_text)}")
            if len(result_text) < 50:
                print(f"⚠️ 응답이 너무 짧음: {result_text}")
            
            vulnerabilities = self._parse_json_response(result_text)
            return vulnerabilities
            
        except AttributeError as e:
            # Claude 응답 형식 오류 처리
            print(f"❌ Claude 응답 형식 오류: {e}")
            if 'response' in locals():
                print(f"응답 구조: {type(response)}")
            raise
        except json.JSONDecodeError as e:
            print(f"❌ Claude JSON 파싱 실패: {e}")
            return self._create_parse_error(str(e), result_text[:500] if 'result_text' in locals() else "")
        except Exception as e:
            print(f"❌ Claude 호출 실패: {e}")
            raise

    def _analyze_with_gpt(self, prompt: str) -> List[Dict]:
        """GPT로 분석 - GPT 특화 설정"""
        try:
            # 환경변수에서 모델명 가져오기
            model = os.getenv("OPENAI_MODEL")
            if not model:
                model = "gpt-4-turbo-preview"
                print(f"⚠️ OPENAI_MODEL 미설정, 기본값 사용: {model}")
            
            # 토큰 길이 체크
            prompt_length = len(prompt)
            estimated_tokens = prompt_length // 4
            
            if estimated_tokens > 8000:
                print(f"⚠️ 프롬프트가 깁니다 ({estimated_tokens} 토큰 예상)")
            
            # GPT는 response_format 지원 확인
            kwargs = {
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a JSON API that analyzes Python code for vulnerabilities. Respond only with valid JSON. No markdown, no explanations."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.2,
                "max_tokens": 3000
            }
            
            # GPT-4 모델만 response_format 지원
            if "gpt-4" in model:
                kwargs["response_format"] = {"type": "json_object"}
            
            response = self.openai_client.chat.completions.create(**kwargs)
            
            # GPT 응답 추출 (choices[0].message.content)
            result_text = response.choices[0].message.content
            
            print(f"📝 GPT 응답 길이: {len(result_text)}")
            
            vulnerabilities = self._parse_json_response(result_text)
            return vulnerabilities
            
        except AttributeError as e:
            # GPT 응답 형식 오류 처리
            print(f"❌ GPT 응답 형식 오류: {e}")
            if 'response' in locals():
                print(f"응답 구조: {type(response)}")
            raise
        except json.JSONDecodeError as e:
            print(f"❌ GPT JSON 파싱 실패: {e}")
            return self._create_parse_error(str(e), result_text[:500] if 'result_text' in locals() else "")
        except Exception as e:
            print(f"❌ GPT 호출 실패: {e}")
            raise

    def _create_parse_error(self, error_msg: str, response_snippet: str) -> List[Dict]:
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

    def _parse_json_response(self, response_text: str) -> List[Dict]:
        """강화된 JSON 파싱 함수 - 디버깅 포함"""
        
        original_text = response_text  # 원본 보존
        
        print(f"🔍 원본 응답 길이: {len(response_text)} 문자")
        print(f"🔍 응답 시작 부분: {response_text[:200]}...")
        
        # 1. JSON 블록 추출 시도
        json_text = None
        
        # 방법 1: ```json 블록
        if "```json" in response_text:
            start = response_text.find("```json") + 7
            end = response_text.find("```", start)
            if end > start:
                json_text = response_text[start:end].strip()
                print("✅ ```json 블록 발견")
        
        # 방법 2: ``` 블록
        elif "```" in response_text:
            start = response_text.find("```") + 3
            end = response_text.find("```", start)
            if end > start:
                json_text = response_text[start:end].strip()
                print("✅ ``` 블록 발견")
        
        # 방법 3: 중괄호 찾기
        if not json_text and "{" in response_text:
            # 첫 번째 { 찾기
            start = response_text.find("{")
            if start >= 0:
                # 매칭되는 } 찾기 (간단한 방법)
                brace_count = 0
                end = start
                for i in range(start, len(response_text)):
                    if response_text[i] == "{":
                        brace_count += 1
                    elif response_text[i] == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            end = i + 1
                            break
                
                if end > start:
                    json_text = response_text[start:end]
                    print(f"✅ 중괄호 기반 추출: {start}:{end}")
        
        # JSON이 없으면 전체 텍스트 시도
        if not json_text:
            json_text = response_text.strip()
            print("⚠️ JSON 블록을 찾을 수 없음, 전체 텍스트 시도")
        
        # 2. 파싱 전 정리
        json_text = self._clean_json_text(json_text)
        
        print(f"🔍 정리된 JSON 시작: {json_text[:100]}...")
        
        # 3. 파싱 시도
        try:
            result = json.loads(json_text)

            # 결과 형태 유연 처리: dict | list 모두 지원
            vulnerabilities = []
            if isinstance(result, list):
                # LLM이 바로 취약점 배열을 반환한 경우
                vulnerabilities = result
            elif isinstance(result, dict):
                # 표준 스키마
                if 'vulnerabilities' in result and isinstance(result['vulnerabilities'], list):
                    vulnerabilities = result['vulnerabilities']
                # 대체 스키마(analysis.code_vulnerabilities 또는 analysis.vulnerabilities)
                elif isinstance(result.get('analysis'), dict):
                    analysis_obj = result['analysis']
                    if isinstance(analysis_obj.get('code_vulnerabilities'), list):
                        vulnerabilities = analysis_obj['code_vulnerabilities']
                    elif isinstance(analysis_obj.get('vulnerabilities'), list):
                        vulnerabilities = analysis_obj['vulnerabilities']
                # 단일 취약점 객체를 반환한 경우
                elif all(k in result for k in ['type', 'severity']):
                    vulnerabilities = [result]

            print(f"✅ JSON 파싱 성공: {len(vulnerabilities)}개 취약점")
            return vulnerabilities
            
        except json.JSONDecodeError as e:
            print(f"❌ JSON 파싱 실패: {e}")
            print(f"❌ 문제 위치: line {e.lineno}, column {e.colno}")
            
            # 문제 부분 출력
            lines = json_text.split('\n')
            if e.lineno <= len(lines):
                print(f"❌ 문제 라인: {lines[e.lineno-1]}")
            
            # 마지막 시도: 더 공격적인 정리
            try:
                json_text = self._aggressive_clean(original_text)
                result = json.loads(json_text)
                print("✅ 공격적 정리 후 파싱 성공")
                return result.get('vulnerabilities', [])
            except:
                # 완전 실패
                raise e

    def _clean_json_text(self, text: str) -> str:
        """JSON 텍스트 정리"""
        
        # 앞뒤 공백 제거
        text = text.strip()
        
        # BOM 제거
        if text.startswith('\ufeff'):
            text = text[1:]
        
        # 일반적인 접두사 제거
        prefixes = [
            "Here is the JSON response:",
            "Here's the analysis:",
            "JSON:",
            "```json",
            "```"
        ]
        
        for prefix in prefixes:
            if text.startswith(prefix):
                text = text[len(prefix):].strip()
        
        # 일반적인 접미사 제거
        suffixes = [
            "```",
            "I hope this helps!",
            "Let me know if you need",
        ]
        
        for suffix in suffixes:
            if text.endswith(suffix):
                text = text[:-len(suffix)].strip()
        
        return text

    def _aggressive_clean(self, text: str) -> str:
        """공격적인 JSON 추출 (최후의 수단)"""
        import re
        
        # 모든 가능한 JSON 패턴 찾기
        patterns = [
            r'\{[\s\S]*"vulnerabilities"[\s\S]*\}',  # vulnerabilities를 포함하는 JSON
            r'\{[^{}]*\{[^{}]*\}[^{}]*\}',  # 중첩된 객체
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text)
            if matches:
                # 가장 긴 매치 선택
                longest = max(matches, key=len)
                try:
                    # 테스트 파싱
                    json.loads(longest)
                    print(f"✅ 정규식 패턴으로 JSON 추출 성공")
                    return longest
                except:
                    continue
        
        # 실패
        return text

    def _fix_common_json_errors(self, text: str) -> str:
        """일반적인 JSON 오류 수정"""
        
        # 줄바꿈 처리
        text = text.replace('\n', '\\n')
        text = text.replace('\r', '\\r')
        text = text.replace('\t', '\\t')
        
        # 따옴표 이스케이프
        # 이미 이스케이프된 것은 건드리지 않음
        text = text.replace('\\\\', '__DOUBLE_BACKSLASH__')
        text = text.replace('\\"', '__ESCAPED_QUOTE__')
        
        # JSON 내부의 따옴표 처리 (매우 조심스럽게)
        # ... 복잡한 로직 필요
        
        # 임시 치환 복원
        text = text.replace('__ESCAPED_QUOTE__', '\\"')
        text = text.replace('__DOUBLE_BACKSLASH__', '\\\\')
        
        # 말미 쉼표 제거
        text = re.sub(r',\s*}', '}', text)
        text = re.sub(r',\s*]', ']', text)
        
        return text

    def _aggressive_json_fix(self, text: str) -> str:
        """더 공격적인 JSON 수정 (최후의 수단)"""
        import re
        
        # 모든 줄바꿈을 공백으로
        text = ' '.join(text.split())
        
        # 연속된 공백 제거
        text = re.sub(r'\s+', ' ', text)
        
        # 문자열 내부의 따옴표 처리
        # "key": "value with "quotes" inside" -> "key": "value with \"quotes\" inside"
        # 이것은 매우 복잡하므로 간단한 경우만 처리
        
        return text
        
    
    # core/improved_llm_analyzer.py


    # core/improved_llm_analyzer.py
# _add_rag_evidence 메서드 전체 교체

    # core/improved_llm_analyzer.py
# _add_rag_evidence 메서드 수정 - 코드 부분 제거

    # core/improved_llm_analyzer.py

    def _add_rag_evidence(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """각 취약점에 RAG 근거 추가 - 개선된 버전"""
        if not self.rag:
            return vulnerabilities
        
        print("📚 RAG로 공식 가이드라인 근거 찾는 중...")
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '')
            if not vuln_type:
                continue

            # 1. 개선된 RAG 검색 실행
            # search_vulnerability_evidence가 매핑과 메타데이터 필터링을 모두 처리
            results = self.rag.search_vulnerability_evidence(vuln_type)
            
            # 2. 검색 결과가 있는지 확인
            if results and results.get('vulnerability'):
                vuln_data = results['vulnerability']
                metadata = vuln_data.get('metadata', {})
                
                # 페이지 정보 추출 및 포맷팅
                page_info = "알 수 없음"
                start_page = metadata.get('start_page')
                end_page = metadata.get('end_page')

                if start_page and end_page:
                    if start_page != end_page:
                        page_info = f"{start_page}-{end_page}"
                    else:
                        page_info = str(start_page)
                
                # evidence 객체 생성
                vuln['evidence'] = {
                    'source': 'KISIA 가이드라인',
                    'document': 'Python_시큐어코딩_가이드(2023년_개정본).pdf',
                    'page': page_info,
                    'section_title': metadata.get('korean_name', ''),
                    'content': vuln_data.get('content', '')[:500] + "...", # 내용은 필요한 만큼 조절
                    'full_content': vuln_data.get('content', '')
                }
                print(f"  ✓ '{vuln_type}' → '{metadata.get('korean_name')}' 근거 찾음 (페이지: {page_info})")
            else:
                print(f"  ❌ '{vuln_type}'에 대한 가이드라인을 찾을 수 없음")

        return vulnerabilities

    def _extract_description_only(self, text: str) -> str:
        """텍스트에서 코드 부분을 제거하고 설명만 추출"""
        lines = text.split('\n')
        cleaned_lines = []
        in_code_block = False
        
        for line in lines:
            # 코드 블록 시작/끝 표시 감지
            if any(marker in line for marker in [
                '[안전하지 않은 코드]', '[안전한 코드]', 
                '안전하지 않은 코드 예시', '안전한 코드 예시',
                '```python', '```', 'def ', 'class ', 'import '
            ]):
                in_code_block = True
                continue
            
            # 코드 라인 번호 패턴 (예: "1:", "2:" 등)
            if re.match(r'^\d+:', line.strip()):
                in_code_block = True
                continue
            
            # 권장사항이나 설명 섹션 시작
            if any(marker in line for marker in ['[권장사항]', '[설명]', '[취약점']):
                in_code_block = False
            
            # 코드 블록이 아닌 경우만 추가
            if not in_code_block and line.strip():
                # 추가 필터링: 코드처럼 보이는 라인 제외
                if not any(pattern in line for pattern in ['__', 'self.', '()', '{}', '[]', '= ']):
                    cleaned_lines.append(line.strip())
        
        # 연속된 텍스트로 결합
        cleaned_text = ' '.join(cleaned_lines)
        
        # 중복 공백 제거
        cleaned_text = re.sub(r'\s+', ' ', cleaned_text)
        
        # 섹션 제목과 설명 부분만 추출
        if '[설명]' in cleaned_text:
            parts = cleaned_text.split('[설명]')
            if len(parts) > 1:
                cleaned_text = parts[1].split('[')[0].strip()
        
        return cleaned_text

    def _extract_keywords_from_description(self, description: str) -> List[str]:
        """설명에서 보안 관련 키워드 추출"""
        keywords = []
        
        # 보안 관련 중요 키워드
        security_terms = [
            '암호화', '해시', '패스워드', '비밀번호', '시크릿', 'secret', 'key',
            'SQL', 'XSS', 'CSRF', '인젝션', 'injection', '세션', 'session',
            '인증', '인가', 'authentication', 'authorization', '토큰', 'token',
            '파일', 'file', '경로', 'path', '명령어', 'command', 'os',
            '직렬화', 'serialize', 'pickle', 'yaml', 'eval', 'exec'
        ]
        
        description_lower = description.lower()
        for term in security_terms:
            if term.lower() in description_lower:
                keywords.append(term)
                if len(keywords) >= 3:  # 최대 3개
                    break
        
        return keywords

    def _find_most_relevant_document(self, documents: List[str], metadatas: List[Dict], 
                                    vuln_type: str, standard_type: str) -> Optional[int]:
        """가장 관련성 높은 문서 인덱스 찾기"""
        if not documents:
            return None
        
        best_score = -1
        best_idx = 0
        
        for i, (doc, meta) in enumerate(zip(documents, metadatas if metadatas else [{}]*len(documents))):
            score = 0
            
            # 1. 메타데이터의 vulnerability_types 확인
            if meta and 'vulnerability_types' in meta:
                doc_vuln_types = meta['vulnerability_types'].lower()
                if standard_type.lower() in doc_vuln_types:
                    score += 3  # 정확한 타입 매칭
                elif vuln_type.lower() in doc_vuln_types:
                    score += 2  # 원본 타입 매칭
            
            # 2. 문서 내용에 취약점 타입 언급 확인
            doc_lower = doc.lower()
            if vuln_type.lower() in doc_lower:
                score += 1
            
            # 3. 특정 키워드 매칭 (취약점별)
            if 'hardcoded' in vuln_type.lower() or 'secret' in vuln_type.lower():
                if any(word in doc_lower for word in ['환경변수', '환경 변수', 'environment', 'env', '하드코딩', '노출']):
                    score += 2
                if any(word in doc_lower for word in ['rsa', '암호화 키', '대칭키']):
                    score -= 1  # RSA 관련 내용은 감점 (Hardcoded Secret과 관련 낮음)
            
            elif 'sql' in vuln_type.lower():
                if any(word in doc_lower for word in ['파라미터', 'parameter', '바인딩', 'binding', 'prepared']):
                    score += 2
            
            elif 'xss' in vuln_type.lower():
                if any(word in doc_lower for word in ['이스케이프', 'escape', 'sanitize', '삭제', 'html']):
                    score += 2
            
            if score > best_score:
                best_score = score
                best_idx = i
        
        # 최소 점수 미달시 None 반환
        if best_score < 1:
            return None
        
        return best_idx

    def _calculate_relevance_score(self, content: str, vuln_type: str, description: str) -> float:
        """컨텐츠와 취약점 간 관련성 점수 계산 (0~1)"""
        score = 0.0
        content_lower = content.lower()
        
        # 1. 취약점 타입 언급 확인 (30%)
        if vuln_type.lower() in content_lower:
            score += 0.3
        
        # 2. 취약점별 특정 키워드 확인 (50%)
        keyword_score = 0.0
        
        if 'hardcoded' in vuln_type.lower() or 'secret' in vuln_type.lower():
            keywords = ['환경변수', '환경 변수', 'environment', '.env', 'config', '설정 파일', '하드코딩']
            matches = sum(1 for k in keywords if k in content_lower)
            keyword_score = min(matches * 0.1, 0.5)
        
        elif 'sql' in vuln_type.lower() or 'injection' in vuln_type.lower():
            keywords = ['파라미터', 'parameter', '바인딩', 'binding', 'prepared', 'statement', '?', '%s']
            matches = sum(1 for k in keywords if k in content_lower)
            keyword_score = min(matches * 0.1, 0.5)
        
        elif 'xss' in vuln_type.lower():
            keywords = ['이스케이프', 'escape', 'sanitize', '삭제', 'html', 'script', '스크립트']
            matches = sum(1 for k in keywords if k in content_lower)
            keyword_score = min(matches * 0.1, 0.5)
        
        else:
            # 일반적인 보안 키워드
            keywords = ['취약', '공격', '방어', '보안', '안전', '위험', '검증', '확인']
            matches = sum(1 for k in keywords if k in content_lower)
            keyword_score = min(matches * 0.08, 0.5)
        
        score += keyword_score
        
        # 3. 설명과의 유사성 (20%)
        if description:
            desc_words = set(description.lower().split())
            content_words = set(content_lower.split())
            if desc_words and content_words:
                intersection = desc_words & content_words
                similarity = len(intersection) / min(len(desc_words), 20)  # 최대 20단어 비교
                score += min(similarity * 0.2, 0.2)
        
        return min(score, 1.0)
        
    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> int:
        """보안 점수 계산"""
        if not vulnerabilities:
            return 100
        
        score = 100
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'MEDIUM')
            confidence = vuln.get('confidence', 'MEDIUM')
            
            # 심각도별 감점 (완화된 기준)
            severity_penalty = {
                'CRITICAL': 24,
                'HIGH': 14,
                'MEDIUM': 6,
                'LOW': 2
            }.get(severity, 6)
            
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