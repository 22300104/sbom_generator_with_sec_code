# rag/simple_rag.py
# 전체 파일 교체

import os
from typing import List, Dict
from openai import OpenAI
from prompts.all_prompts import RAG_PROMPTS, SYSTEM_PROMPTS

class SimpleRAG:
    def __init__(self):
        self.collection = None
        self.chroma_available = False
        
        # ChromaDB 로드 시도 (실패해도 계속 진행)
        try:
            import chromadb
            self.chroma_client = chromadb.PersistentClient(path="data/vector_db")
            
            try:
                self.collection = self.chroma_client.get_collection("kisia_vulnerabilities")
                self.chroma_available = True
                print(f"벡터 DB 로드 완료 (문서 수: {self.collection.count()})")
            except Exception as e:
                print(f"ChromaDB Collection 없음: {e}")
                print("RAG 없이 일반 Q&A 모드로 작동합니다.")
        except ImportError:
            print("ChromaDB가 설치되지 않았습니다. 일반 Q&A 모드로 작동합니다.")
        except Exception as e:
            print(f"ChromaDB 초기화 실패: {e}")
        
        # OpenAI 클라이언트 초기화
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY 환경 변수가 설정되지 않았습니다.")
        
        self.client = OpenAI(api_key=api_key)
        
    def search_similar(self, query: str, top_k: int = 5) -> Dict:
        """유사한 문서 검색 (ChromaDB 있을 때만) - 개선된 버전"""
        if self.chroma_available and self.collection:
            try:
                results = self.collection.query(
                    query_texts=[query],
                    n_results=top_k
                )
                # 컬렉션 이름 추가
                results['collection_name'] = self.collection.name if hasattr(self.collection, 'name') else 'unknown'
                return results
            except Exception as e:
                print(f"검색 오류: {e}")
                return {'documents': [[]], 'metadatas': [[]], 'collection_name': 'error'}
        else:
            return {'documents': [[]], 'metadatas': [[]], 'collection_name': 'none'}


# rag/simple_rag.py
# ask() 함수 전체 교체

    # rag/simple_rag.py
    # ask() 함수 수정

    def ask(self, question: str) -> str:
        """질문에 대한 답변 생성 - 완전한 컨텍스트 제공"""
        
        from prompts.all_prompts import RAG_PROMPTS, SYSTEM_PROMPTS
        import streamlit as st
        import time
        
        # 1. 완전한 컨텍스트 수집 (함수명 수정)
        context = {
            'analysis_info': self._get_analysis_info(),
            'vulnerabilities_detail': self._get_vulnerabilities_detail(),
            'code_context': self._get_code_context(),
            'sbom_info': self._get_sbom_info(),
            'conversation_history': self._get_full_conversation_history()
        }
        
        # 2. RAG 검색 (선택적, 빠르게)
        rag_note = ""
        rag_metadata = None
        
        if self.chroma_available:
            try:
                start_time = time.time()
                search_results = self.search_similar(question, top_k=3)
                
                if time.time() - start_time < 1.0 and search_results['documents'][0]:
                    docs = search_results['documents'][0]
                    metadatas = search_results.get('metadatas', [[]])[0]
                    
                    # 출처 정보 구성
                    source_info = []
                    for i, (doc, meta) in enumerate(zip(docs[:2], metadatas[:2])):
                        if meta:
                            page = meta.get('page', '?')
                            page_start = meta.get('page_start', page)
                            page_end = meta.get('page_end', page)
                            
                            if page_start and page_end and page_start != page_end:
                                page_range = f"p.{page_start}-{page_end}"
                            else:
                                page_range = f"p.{page}"
                            
                            source_info.append({
                                'page_range': page_range,
                                'title': meta.get('title', ''),
                                'type': meta.get('type', ''),
                                'vulnerability_types': meta.get('vulnerability_types', '')
                            })
                    
                    rag_context = "\n".join(docs[:2])
                    rag_note = f"\n\n[KISIA 가이드라인 참고]\n{rag_context}"
                    
                    # 메타데이터 저장 (나중에 사용)
                    rag_metadata = source_info
                    
                    print(f"RAG 문서 발견 ({len(docs)}개)")
            except Exception as e:
                print(f"RAG 검색 스킵: {e}")
        
        # 3. 스마트 프롬프트 구성 (모든 정보 포함)
        prompt = RAG_PROMPTS["qa_smart_context"].format(
            analysis_info=context['analysis_info'],
            vulnerabilities_detail=context['vulnerabilities_detail'],
            code_context=context['code_context'],
            sbom_info=context['sbom_info'],
            conversation_history=context['conversation_history'],
            question=question,
            rag_note=rag_note
        )
        
        # 프롬프트 길이 체크
        prompt_length = len(prompt)
        if prompt_length > 30000:  # 너무 길면 일부 축소
            print(f"프롬프트가 너무 김 ({prompt_length}자), 일부 축소")
            # 코드 컨텍스트를 줄임
            context['code_context'] = context['code_context'][:5000] + "\n... (생략) ..."
            prompt = RAG_PROMPTS["qa_smart_context"].format(
                analysis_info=context['analysis_info'],
                vulnerabilities_detail=context['vulnerabilities_detail'],
                code_context=context['code_context'],
                sbom_info=context['sbom_info'],
                conversation_history=context['conversation_history'][-5000:],  # 대화도 축소
                question=question,
                rag_note=rag_note
            )
        
        # 4. AI 답변 생성
        answer = self._generate_ai_answer(prompt)
        
        # 5. 출처 표시 (더 상세하게)
        if answer:
            footer_parts = ["\n\n---"]
            
            # RAG 메타데이터가 있으면 상세 출처 표시
            if rag_metadata:
                footer_parts.append("\n**참고 문서:**")
                # 메타데이터에서 문서명 추출
                used_docs = set()
                for source in rag_metadata:
                    doc_name = source.get('source_document', 'Python_시큐어코딩_가이드(2023년_개정본).pdf')
                    used_docs.add(doc_name)

                for doc in used_docs:
                    footer_parts.append(f"*{doc}*")
                
                for source in rag_metadata:
                    if source['page_range']:
                        footer_parts.append(f"• {source['page_range']}")
                        if source['title']:
                            footer_parts.append(f"  - {source['title']}")
                        if source['vulnerability_types']:
                            footer_parts.append(f"  - 관련: {source['vulnerability_types']}")
            
            elif rag_note:
                footer_parts.append("*KISIA 가이드라인 참조*")
            
            if "이전 대화" in context['conversation_history'] and len(context['conversation_history']) > 50:
                footer_parts.append("*대화 맥락 유지*")
            
            if len(footer_parts) == 1:  # 특별한 참조 없음
                footer_parts.append("*일반 보안 지식 기반*")
            
            return answer + "\n".join(footer_parts)
        else:
            return "죄송합니다. AI 서비스를 사용할 수 없습니다."
    
    def get_stats(self) -> Dict:
        """시스템 상태 정보"""
        if self.chroma_available and self.collection:
            return {
                "mode": "RAG 모드",
                "total_documents": self.collection.count(),
                "collection_name": "secure_coding_guide",
                "status": "정상"
            }
        else:
            return {
                "mode": "일반 Q&A 모드",
                "total_documents": 0,
                "collection_name": "없음",
                "status": "RAG 없이 작동 중"
            }
        
# rag/simple_rag.py
# 새로운 헬퍼 함수들 추가

    def _gather_complete_context(self) -> dict:
        """모든 컨텍스트 정보를 완전하게 수집"""
        import streamlit as st
        
        return {
            'analysis_info': self._get_analysis_info(),
            'vulnerabilities_detail': self._get_vulnerabilities_detail(),
            'code_context': self._get_code_context(),
            'sbom_info': self._get_sbom_info(),
            'conversation_history': self._get_full_conversation_history()
        }

    def _get_analysis_info(self) -> str:
        """분석 메타데이터 정보"""
        import streamlit as st
        
        analysis_results = st.session_state.get('analysis_results', {})
        if not analysis_results:
            return "아직 코드 분석을 수행하지 않았습니다."
        
        info_parts = []
        
        # 기본 정보
        info_parts.append(f"분석 완료 시간: {analysis_results.get('analysis_time', 0):.1f}초 전")
        info_parts.append(f"분석한 파일 수: {analysis_results.get('analyzed_files', 0)}개")
        
        # 분석 모드
        mode = st.session_state.get('analysis_mode', '알 수 없음')
        info_parts.append(f"분석 모드: {mode}")
        
        # AI 엔진
        if 'ai_analysis' in analysis_results:
            ai_result = analysis_results['ai_analysis']
            info_parts.append(f"AI 엔진: {ai_result.get('analyzed_by', 'Unknown')}")
            info_parts.append(f"보안 점수: {ai_result.get('security_score', 100)}/100")
            info_parts.append(f"발견된 취약점: {len(ai_result.get('vulnerabilities', []))}개")
        
        # 파일 목록
        if 'analysis_file_list' in st.session_state:
            files = st.session_state.analysis_file_list
            info_parts.append(f"\n분석한 파일 목록:")
            for f in files:
                info_parts.append(f"  - {f['path']} ({f['lines']}줄, {f['size']}바이트)")
        
        return "\n".join(info_parts)

    def _get_vulnerabilities_detail(self) -> str:
        """모든 취약점의 완전한 정보"""
        import streamlit as st
        import json
        
        analysis_results = st.session_state.get('analysis_results', {})
        if not analysis_results or 'ai_analysis' not in analysis_results:
            return "취약점 정보 없음"
        
        vulnerabilities = analysis_results['ai_analysis'].get('vulnerabilities', [])
        if not vulnerabilities:
            return "발견된 취약점 없음"
        
        vuln_details = []
        
        for i, vuln in enumerate(vulnerabilities, 1):
            vuln_details.append(f"\n[취약점 {i}]")
            vuln_details.append(f"타입: {vuln.get('type', 'Unknown')}")
            vuln_details.append(f"심각도: {vuln.get('severity', 'UNKNOWN')}")
            vuln_details.append(f"신뢰도: {vuln.get('confidence', 'UNKNOWN')}")
            
            # 위치 정보
            location = vuln.get('location', {})
            vuln_details.append(f"파일: {location.get('file', 'unknown')}")
            vuln_details.append(f"라인: {location.get('line', '?')}")
            vuln_details.append(f"함수: {location.get('function', 'unknown')}")
            
            # 설명
            vuln_details.append(f"설명: {vuln.get('description', '설명 없음')}")
            
            # 취약한 코드
            if vuln.get('vulnerable_code'):
                vuln_details.append(f"취약한 코드:\n```python\n{vuln['vulnerable_code']}\n```")
            
            # 수정된 코드 (중요!)
            if vuln.get('fixed_code'):
                vuln_details.append(f"수정 코드:\n```python\n{vuln['fixed_code']}\n```")
            
            # 수정 설명
            if vuln.get('fix_explanation'):
                vuln_details.append(f"수정 설명: {vuln['fix_explanation']}")
            
            # 권장사항
            if vuln.get('recommendation'):
                vuln_details.append(f"권장사항: {vuln['recommendation']}")
            
            vuln_details.append("-" * 40)
        
        return "\n".join(vuln_details)

    def _get_code_context(self) -> str:
        """분석한 코드의 일부 제공"""
        import streamlit as st
        
        # 분석한 코드 가져오기
        analysis_code = st.session_state.get('analysis_code', '')
        if not analysis_code:
            return "코드 컨텍스트 없음"
        
        # 너무 길면 주요 부분만
        max_length = 3000
        if len(analysis_code) > max_length:
            # 처음 부분과 취약점 관련 부분 포함
            code_preview = analysis_code[:max_length] + "\n... (코드 생략) ..."
        else:
            code_preview = analysis_code
        
        # 파일별로 구분된 경우 표시
        if "# ===== File:" in code_preview:
            return f"분석한 코드 (일부):\n\n{code_preview}"
        else:
            return f"분석한 코드:\n```python\n{code_preview}\n```"

    def _get_sbom_info(self) -> str:
        """SBOM 정보 제공"""
        import streamlit as st
        
        analysis_results = st.session_state.get('analysis_results', {})
        if 'sbom' not in analysis_results:
            return "SBOM 정보 없음"
        
        sbom = analysis_results['sbom']
        packages = sbom.get('packages', [])
        
        if not packages:
            return "발견된 패키지 없음"
        
        sbom_parts = []
        sbom_parts.append(f"총 {len(packages)}개 외부 패키지 사용")
        sbom_parts.append("\n패키지 목록:")
        
        for pkg in packages:
            name = pkg.get('name', 'unknown')
            version = pkg.get('version') or pkg.get('actual_version') or '버전 없음'
            status = pkg.get('status', '')
            
            sbom_parts.append(f"  - {name}: {version} {status}")
            
            # 종속성 정보
            if pkg.get('dependencies'):
                deps_count = pkg.get('dependencies_count', len(pkg['dependencies']))
                sbom_parts.append(f"    → {deps_count}개 종속성")
            
            # 취약점 정보
            if pkg.get('vulnerabilities'):
                vuln_count = len(pkg['vulnerabilities'])
                sbom_parts.append(f"    ⚠️ {vuln_count}개 알려진 취약점")
        
        # 간접 종속성
        indirect = sbom.get('indirect_dependencies', [])
        if indirect:
            sbom_parts.append(f"\n간접 종속성: {len(indirect)}개")
        
        return "\n".join(sbom_parts)

    def _get_full_conversation_history(self) -> str:
        """완전한 대화 기록 (잘리지 않음)"""
        import streamlit as st
        
        qa_messages = st.session_state.get('qa_messages', [])
        if not qa_messages:
            return "이전 대화 없음"
        
        history = []
        
        # 모든 대화 포함 (제한 없음)
        for i, msg in enumerate(qa_messages):
            if msg["role"] == "user":
                history.append(f"\n사용자: {msg['content']}")
            else:
                # 전체 답변 포함 (잘리지 않음)
                content = msg['content']
                # 푸터만 제거
                if '\n\n---\n' in content:
                    content = content.split('\n\n---\n')[0]
                history.append(f"\nAI: {content}")
        
        return "\n".join(history) if history else "이전 대화 없음"
    
    # rag/simple_rag.py
# SimpleRAG 클래스 안에 추가 (다른 메서드들 아래에)

    def _generate_ai_answer(self, prompt: str) -> str:
        """AI 답변 생성 (Claude 우선, GPT 폴백)"""
        from prompts.all_prompts import SYSTEM_PROMPTS
        import os
        
        answer = None
        
        # Claude 시도
        if os.getenv("ANTHROPIC_API_KEY"):
            try:
                from anthropic import Anthropic
                claude_client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
                model = os.getenv("ANTHROPIC_MODEL", "claude-3-opus-20240229")
                
                # Claude는 system을 user에 포함
                system_prompt = SYSTEM_PROMPTS.get("qa_expert", "")
                full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
                
                response = claude_client.messages.create(
                    model=model,
                    max_tokens=1500,
                    temperature=0.3,
                    messages=[{"role": "user", "content": full_prompt}]
                )
                
                answer = response.content[0].text
                print("✅ Claude 답변 생성")
                
            except Exception as e:
                print(f"⚠️ Claude 실패, GPT로 폴백: {e}")
        
        # GPT 폴백
        if not answer and os.getenv("OPENAI_API_KEY"):
            try:
                model = os.getenv("OPENAI_MODEL", "gpt-4-turbo-preview")
                
                response = self.client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPTS.get("qa_expert", "Python 보안 전문가입니다.")},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                    max_tokens=1500
                )
                
                answer = response.choices[0].message.content
                print("GPT 답변 생성")
                
            except Exception as e:
                print(f"❌ GPT도 실패: {e}")
                answer = None
        
        return answer if answer else "AI 서비스를 사용할 수 없습니다."