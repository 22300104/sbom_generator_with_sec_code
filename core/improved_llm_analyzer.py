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
            from rag.simple_rag import SimpleRAG
            self.rag = SimpleRAG()
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
    
    
    def _build_discovery_prompt(self, code: str, file_list: List[Dict] = None) -> str:
        """취약점 발견 프롬프트 - JSON 응답 강제"""
        
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
                "type": "취약점타입",
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
            
            # Claude는 system role이 없으므로 user 메시지에 통합
            claude_prompt = """You are a senior security expert analyzing Python code.
    Respond ONLY with valid JSON. No explanations, no markdown.

    """ + prompt
            
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
            vulnerabilities = result.get('vulnerabilities', [])
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


    def _add_rag_evidence(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """각 취약점에 RAG 근거 추가 - 개선된 버전"""
        if not self.rag:
            return vulnerabilities
        
        print("📚 RAG로 공식 가이드라인 근거 찾는 중...")
        try:
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', '')
                
                # RAG에서 관련 가이드라인 검색
                search_query = f"{vuln_type} 방어 방법 보안 가이드라인"
                results = self.rag.search_similar(search_query, top_k=3)  # top_k를 3으로 증가
                
                if results['documents'] and results['documents'][0]:
                    # 가장 관련성 높은 문서
                    evidence = results['documents'][0][0]
                    
                    # 메타데이터가 있으면 상세 정보 추가
                    if results.get('metadatas') and results['metadatas'][0]:
                        metadata = results['metadatas'][0][0]
                        
                        # 페이지 정보 추출
                        page = metadata.get('page', '?')
                        page_start = metadata.get('page_start', page)
                        page_end = metadata.get('page_end', page)
                        
                        # 페이지 범위 결정
                        if page_start and page_end and page_start != page_end:
                            page_info = f"{page_start}-{page_end}"
                        else:
                            page_info = str(page)
                        
                        vuln['evidence'] = {
                            'source': 'KISIA Python 시큐어코딩 가이드',
                            'document': 'Python_시큐어코딩_가이드(2023년_개정본).pdf',
                            'page': page_info,
                            'page_start': page_start,
                            'page_end': page_end,
                            'section_title': metadata.get('title', ''),
                            'vulnerability_types': metadata.get('vulnerability_types', ''),
                            'content': evidence[:500] + "..." if len(evidence) > 500 else evidence,
                            'full_content': evidence,  # 전체 내용 보관
                            'collection': results.get('collection_name', 'unknown')
                        }
                        
                        # 추가 관련 문서들도 저장 (있으면)
                        if len(results['documents'][0]) > 1:
                            related_docs = []
                            for i in range(1, min(3, len(results['documents'][0]))):
                                if i < len(results['metadatas'][0]):
                                    related_meta = results['metadatas'][0][i]
                                    related_docs.append({
                                        'page': related_meta.get('page', '?'),
                                        'type': related_meta.get('type', ''),
                                        'keywords': related_meta.get('keywords', '')
                                    })
                            vuln['evidence']['related_sections'] = related_docs
                    else:
                        vuln['evidence'] = {
                            'source': 'KISIA 가이드라인',
                            'content': evidence[:500] + "..." if len(evidence) > 500 else evidence
                        }
            
            return vulnerabilities
        except Exception as e:
            print(f"⚠️ RAG 처리 실패: {e}")
            return vulnerabilities
        
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