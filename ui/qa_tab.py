"""
개선된 Q&A 탭 - RAG 80% + GPT 20%
근거 기반 답변으로 신뢰성 향상
"""
import streamlit as st
import time
import os
from rag.simple_rag import SimpleRAG
from prompts.security_prompts import get_qa_prompt

def render_qa_tab():
    """전문적인 Q&A 탭 - RAG 기반 전문가 시스템"""
    
    # 전문적인 헤더
    st.markdown("""
    <div style="text-align: center; padding: 1rem 0 2rem 0;">
        <h2>Q&A</h2>
        <p style="color: var(--gray-600); font-size: 1.1rem;">
            Python 보안 전문가 시스템
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # RAG 시스템 초기화 및 상태 표시
    if 'rag_system' not in st.session_state:
        with st.spinner("Q&A 시스템 초기화 중..."):
            try:
                st.session_state.rag_system = SimpleRAG()
                stats = st.session_state.rag_system.get_stats()
                
                # 모드에 따른 다른 메시지
                if stats['mode'] == "RAG 모드":
                    st.success(f"RAG 모드 활성화: {stats['total_documents']}개 문서 로드")
                else:
                    st.info("일반 Q&A 모드로 작동 중")
                    st.caption("AI 기반 전문가 답변을 제공합니다.")
            except Exception as e:
                st.error(f"Q&A 시스템 초기화 실패: {e}")
                st.info("OpenAI API 키를 확인해주세요.")
                return
    
    rag = st.session_state.rag_system
    stats = rag.get_stats()
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "지식 베이스",
            f"{stats['total_documents']}개 문서",
            help="로드된 보안 가이드라인 문서 수"
        )
    
    with col2:
        api_status = "활성" if os.getenv("OPENAI_API_KEY") else "비활성"
        st.metric(
            "AI 엔진",
            api_status,
            help="OpenAI API 연결 상태"
        )
    
    
    with col3:
        # 실제 사용 중인 AI 엔진 확인
        if os.getenv("ANTHROPIC_API_KEY"):
            ai_engine = "Claude"
        elif os.getenv("OPENAI_API_KEY"):
            ai_engine = "GPT"
        else:
            ai_engine = "N/A"
        
        # RAG 상태에 따라 모드 표시
        if stats['mode'] == "RAG 모드":
            mode_text = f"RAG + {ai_engine}"
        else:
            mode_text = f"{ai_engine} Only"
        
        st.metric(
            "응답 모드",
            mode_text,
            help=f"{'RAG 검색 + ' if stats['mode'] == 'RAG 모드' else ''}{ai_engine} 생성 모드"
        )

    with col4:
        session_count = len(st.session_state.get('qa_messages', []))
        st.metric(
            "대화 수",
            f"{session_count//2}개",
            help="현재 세션의 질문-답변 수"
        )
    
    st.divider()
    
    # 채팅 히스토리 초기화
    if 'qa_messages' not in st.session_state:
        st.session_state.qa_messages = []
    
    # 질문 카테고리
    st.markdown("### 질문 카테고리")
    
    question_categories = [
        {
            "title": "취약점 방어",
            "questions": [
                "SQL 인젝션을 방어하는 방법은?",
                "파라미터 바인딩이 왜 안전한가요?",
                "패스워드는 어떻게 저장해야 하나요?",
                "XSS 공격을 방지하려면?"
            ]
        },
        {
            "title": "개발 모범 사례",
            "questions": [
                "환경변수는 왜 사용해야 하나요?",
                "입력 검증 방법은?",
                "안전한 암호화 방법은?",
                "로깅 시 주의사항은?"
            ]
        }
    ]
    
    # 카테고리별 질문 표시
    cols = st.columns(2)
    for i, category in enumerate(question_categories):
        with cols[i % 2]:
            with st.expander(category["title"]):
                for question in category["questions"]:
                    if st.button(
                        question, 
                        key=f"cat_q_{i}_{question}",
                        use_container_width=True
                    ):
                        st.session_state.pending_question = question
    
    st.divider()
    
    # 채팅 인터페이스
    st.markdown("### AI에게 질문하기")
    
    # 대화 기록이 있는지 확인
    if st.session_state.qa_messages:
        st.markdown("#### 대화 기록")
        
        # 대화 기록 표시
        chat_container = st.container()
        with chat_container:
            for i, msg in enumerate(st.session_state.qa_messages):
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])
                    
                    # 출처 정보가 있는 경우
                    if msg.get("sources"):
                        with st.expander("참고 문서", expanded=False):
                            for j, source in enumerate(msg["sources"][:3], 1):  # 상위 3개만 표시
                                st.markdown(f"**{j}.** {source}")
                    
                    # 답변에 대한 피드백 (선택적)
                    if msg["role"] == "assistant" and i == len(st.session_state.qa_messages) - 1:
                        col1, col2, col3 = st.columns([1, 1, 8])
                        with col1:
                            if st.button("도움됨", key=f"like_{i}", help="도움이 되었어요"):
                                st.success("피드백 감사합니다!")
                        with col2:
                            if st.button("개선필요", key=f"dislike_{i}", help="더 나은 답변이 필요해요"):
                                st.info("피드백을 반영하여 개선하겠습니다.")
        
        # 대화 초기화 버튼
        if st.button("새 대화 시작", help="현재 대화를 초기화합니다"):
            st.session_state.qa_messages = []
            st.rerun()
    
    else:
        # 첫 대화 안내
        st.info("""
        **보안 전문가 Q&A에 오신 것을 환영합니다!**
        
        위의 카테고리에서 질문을 선택하거나, 아래에 직접 질문을 입력해보세요.
        KISIA 가이드라인을 기반으로 정확하고 실무적인 답변을 드립니다.
        """)
    
    # 질문 입력
    st.markdown("#### 질문 입력")
    
    # 질문 입력 도우미
    with st.expander("효과적인 질문 작성 팁"):
        st.markdown("""
        **좋은 질문의 예:**
        • "Flask에서 SQL 인젝션을 방지하는 구체적인 방법은?"
        • "Django에서 CSRF 토큰을 어떻게 구현하나요?"
        • "Python에서 패스워드 해싱 시 salt 사용법은?"
        
        **피해야 할 질문:**
        • "보안이 뭐예요?" (너무 광범위)
        • "해킹 방법 알려주세요" (부적절한 목적)
        • "버그 있어요" (구체적 정보 부족)
        """)
    
    # 질문 입력 필드
    if prompt := st.chat_input("보안 관련 질문을 입력하세요... (예: SQL 인젝션 방어 방법은?)"):
        process_question(prompt, rag)
    
    # 예제 질문 처리
    if 'pending_question' in st.session_state:
        process_question(st.session_state.pending_question, rag)
        del st.session_state.pending_question


 

def process_question(question: str, rag):
    """전문적인 질문 처리 - AI 중심, RAG 보조"""
    
    # 사용자 메시지 추가
    st.session_state.qa_messages.append({"role": "user", "content": question})
    
    with st.chat_message("user"):
        st.markdown(question)
    
    with st.chat_message("assistant"):
        # 전문적인 로딩 인디케이터
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        try:
            start_time = time.time()
            
            # 1단계: 질문 분석 중
            status_text.text("질문 분석 중...")
            progress_bar.progress(30)
            time.sleep(0.3)
            
            # 2단계: 답변 생성 (RAG는 ask() 내부에서 처리)
            status_text.text("답변 생성 중...")
            progress_bar.progress(70)
            
            # ask() 함수가 RAG 검색과 AI 답변을 모두 처리
            response = rag.ask(question)
            
            # 출처 정보 파싱 (있으면)
            source_docs = []
            if "참고 문서:" in response:
                # 응답에서 출처 정보 추출
                lines = response.split('\n')
                for i, line in enumerate(lines):
                    if "Python_시큐어코딩_가이드" in line:
                        # 다음 줄들에서 페이지 정보 수집
                        j = i + 1
                        while j < len(lines) and lines[j].startswith('•'):
                            page_info = lines[j].strip('• ')
                            source_docs.append(page_info)
                            j += 1

            # 완료
            progress_bar.progress(100)
            elapsed = time.time() - start_time
            status_text.text(f"답변 완료 ({elapsed:.2f}초)")
            
            # 답변 표시
            st.markdown(response)
            
            # 출처가 있으면 별도 박스로 표시
            if source_docs:
                with st.expander("가이드라인 출처 상세", expanded=False):
                    st.info("**Python_시큐어코딩_가이드(2023년_개정본).pdf**")
                    for doc in source_docs:
                        st.caption(f"• {doc}")

            # 성능 정보
            col1, col2, col3 = st.columns(3)
            with col1:
                st.caption(f"응답시간: {elapsed:.2f}초")
            with col2:
                # 답변 유형 판단
                if "KISIA" in response or "가이드" in response:
                    st.caption(f"가이드라인 참조")
                else:
                    st.caption(f"일반 지식 기반")
            with col3:
                st.caption(f"답변 완료")
            
            # 대화 기록에 추가
            st.session_state.qa_messages.append({
                "role": "assistant",
                "content": response,
                "elapsed_time": elapsed
            })
            
        except Exception as e:
            progress_bar.progress(100)
            status_text.text("오류 발생")
            st.error(f"답변 생성 중 오류가 발생했습니다: {e}")
            
        finally:
            # UI 정리
            time.sleep(0.5)
            progress_bar.empty()
            status_text.empty()

 

def generate_answer_with_sources(question: str, documents: list, sources: list) -> str:
    """근거 기반 답변 생성"""
    
    from openai import OpenAI
    from prompts.all_prompts import RAG_PROMPTS, SYSTEM_PROMPTS
    
    # 문서 컨텍스트 생성
    context = "\n\n".join(documents[:3])  # 상위 3개 문서
    
    # 중앙 관리 프롬프트 사용
    prompt = RAG_PROMPTS["qa_with_context"].format(
        question=question,
        rag_evidences=context
    )
    
    try:
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        model = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
        
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPTS.get("rag_strict", SYSTEM_PROMPTS["rag_assistant"])
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=1000
        )
        
        answer = response.choices[0].message.content
        
        # 답변에 근거 표시 추가
        answer += "\n\n---\n*📌 이 답변은 KISIA Python 시큐어코딩 가이드라인을 기반으로 작성되었습니다.*"
        
        return answer
        
    except Exception as e:
        # GPT 실패 시 RAG 문서 직접 사용
        return f"""
다음은 관련 가이드라인 내용입니다:

{documents[0][:500]}...

전체 내용은 출처를 참고해주세요.
"""


def render_code_context_qa():
    """코드 컨텍스트 기반 Q&A"""
    st.subheader("코드 분석 Q&A")
    
    user_code = st.text_area(
        "분석할 코드:",
        height=200,
        placeholder="보안 검토가 필요한 Python 코드를 입력하세요..."
    )
    
    if user_code:
        st.info(f"📝 {len(user_code)}자의 코드가 입력되었습니다.")
        
        # 코드 관련 질문 예제
        code_questions = [
            "이 코드의 보안 취약점은?",
            "SQL 인젝션 위험이 있나요?",
            "어떻게 개선할 수 있나요?",
        ]
        
        col1, col2, col3 = st.columns(3)
        for i, q in enumerate(code_questions):
            with [col1, col2, col3][i]:
                if st.button(q):
                    analyze_code_with_question(user_code, q)


def analyze_code_with_question(code: str, question: str):
    """코드와 질문을 함께 분석"""
    
    from core.llm_analyzer import ImprovedLLMAnalyzer
    
    with st.spinner("코드 분석 중..."):
        try:
            analyzer = ImprovedLLMAnalyzer()
            
            # 코드 분석
            result = analyzer.analyze_code_security(code)
            
            if result['success']:
                vulns = result['analysis']['vulnerabilities']
                safe_practices = result['analysis']['safe_practices']
                
                st.write("### 분석 결과")
                
                # 취약점
                if vulns:
                    st.warning(f"{len(vulns)}개 취약점 발견")
                    for vuln in vulns:
                        with st.expander(f"{vuln['type']} - {vuln['severity']}"):
                            st.write(f"**이유:** {vuln.get('reasoning', '')}")
                            st.write(f"**공격 시나리오:** {vuln.get('attack_scenario', '')}")
                            st.write(f"**권장사항:** {vuln.get('recommendation', '')}")
                else:
                    st.success("취약점이 발견되지 않았습니다.")
                
                # 안전한 practice
                if safe_practices:
                    st.success(f"👍 {len(safe_practices)}개의 안전한 코딩 practice 발견")
                    for practice in safe_practices:
                        st.write(f"• {practice['practice']}: {practice['description']}")
        
        except Exception as e:
            st.error(f"분석 실패: {e}")