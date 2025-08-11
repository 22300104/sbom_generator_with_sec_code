"""
Q&A tab UI with code context
"""
import streamlit as st
import time
import os

# RAG 시스템 임포트
try:
    from rag.simple_rag import SimpleRAG
    from core.llm_analyzer import LLMSecurityAnalyzer
    RAG_AVAILABLE = True
except Exception as e:
    RAG_AVAILABLE = False
    RAG_ERROR = str(e)

def render_qa_tab():
    """Q&A 탭 렌더링 - 코드 컨텍스트 포함"""
    st.header("💬 시큐어 코딩 가이드 Q&A")
    
    # RAG 시스템 체크
    if not RAG_AVAILABLE:
        st.error(f"⚠️ RAG 시스템을 로드할 수 없습니다: {RAG_ERROR}")
        return
    
    # OpenAI API 키 체크
    if not os.getenv("OPENAI_API_KEY"):
        st.warning("⚠️ OpenAI API Key가 설정되지 않았습니다.")
        api_key = st.text_input("API Key 입력:", type="password", key="qa_api_key")
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key
            st.rerun()
        return
    
    # 시스템 초기화
    if 'rag_system' not in st.session_state:
        try:
            with st.spinner("시스템 초기화 중..."):
                st.session_state.rag_system = SimpleRAG()
                st.session_state.llm_analyzer = LLMSecurityAnalyzer()
                stats = st.session_state.rag_system.get_stats()
                st.success(f"✅ 시스템 준비 완료 (문서 {stats['total_documents']}개)")
        except Exception as e:
            st.error(f"❌ 시스템 초기화 실패: {e}")
            return
    
    rag = st.session_state.rag_system
    llm = st.session_state.llm_analyzer
    
    # 사이드바 - 코드 입력
    with st.sidebar:
        st.subheader("📝 분석할 코드 (선택)")
        
        # 코드 입력 영역
        user_code = st.text_area(
            "코드를 입력하면 이를 기준으로 답변합니다:",
            height=200,
            placeholder="분석하려는 Python 코드를 입력하세요...",
            key="qa_user_code",
            help="코드를 입력하면 '내 코드'를 참조하는 질문에 대해 구체적인 답변을 받을 수 있습니다."
        )
        
        # 코드가 입력되면 세션에 저장
        if user_code:
            st.session_state.current_code = user_code
            st.success(f"✅ 코드 {len(user_code)}자 입력됨")
        
        st.divider()
        
        # 예시 질문들
        st.subheader("💡 예시 질문")
        
        if 'current_code' in st.session_state:
            # 코드가 있을 때의 질문
            example_questions = [
                "내 코드의 보안 취약점을 분석해줘",
                "내 코드에 SQL 인젝션 취약점이 있어?",
                "내 코드를 더 안전하게 개선하려면?",
                "내 코드의 특정 라인을 설명해줘",
            ]
        else:
            # 일반 질문
            example_questions = [
                "SQL 인젝션 방어 방법",
                "XSS 공격 방지 방법",
                "안전한 패스워드 저장",
                "파일 업로드 보안",
            ]
        
        for q in example_questions:
            if st.button(q, key=f"example_{q}", use_container_width=True):
                st.session_state.qa_input = q
    
    # 메인 영역
    st.subheader("🗨️ 질문하기")
    
    # 현재 코드 상태 표시
    if 'current_code' in st.session_state:
        st.info(f"📝 분석 대상 코드: {len(st.session_state.current_code)}자 입력됨")
    else:
        st.caption("💡 사이드바에 코드를 입력하면 더 구체적인 분석이 가능합니다.")
    
    # 채팅 기록 초기화
    if 'qa_messages' not in st.session_state:
        st.session_state.qa_messages = []
    
    # 이전 대화 표시
    for message in st.session_state.qa_messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
            if "time" in message:
                st.caption(f"⏱️ {message['time']:.2f}초")
    
    # 입력 처리
    if prompt := st.chat_input("질문을 입력하세요...") or st.session_state.get('qa_input'):
        if 'qa_input' in st.session_state:
            prompt = st.session_state.qa_input
            del st.session_state.qa_input
        
        # 사용자 메시지 추가
        st.session_state.qa_messages.append({"role": "user", "content": prompt})
        
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # AI 응답 생성
        with st.chat_message("assistant"):
            with st.spinner("답변 생성 중..."):
                start_time = time.time()
                
                try:
                    # 코드 컨텍스트가 있고 "내 코드"를 언급하는 경우
                    if ('current_code' in st.session_state and 
                        any(keyword in prompt.lower() for keyword in ['내 코드', '내코드', 'my code', '위 코드', '이 코드'])):
                        
                        response = analyze_code_with_question(
                            st.session_state.current_code, 
                            prompt, 
                            rag, 
                            llm
                        )
                    else:
                        # 일반 RAG 질문
                        response = rag.ask(prompt)
                    
                    elapsed_time = time.time() - start_time
                    
                    # 답변 표시
                    st.markdown(response)
                    st.caption(f"⏱️ {elapsed_time:.2f}초")
                    
                    # 대화 기록에 추가
                    st.session_state.qa_messages.append({
                        "role": "assistant", 
                        "content": response,
                        "time": elapsed_time
                    })
                    
                except Exception as e:
                    st.error(f"❌ 오류 발생: {e}")
    
    # 대화 관리 버튼
    col1, col2 = st.columns([1, 1])
    with col1:
        if st.button("🔄 대화 초기화", use_container_width=True):
            st.session_state.qa_messages = []
            st.rerun()
    with col2:
        if st.button("🗑️ 코드 초기화", use_container_width=True):
            if 'current_code' in st.session_state:
                del st.session_state.current_code
            st.rerun()

def analyze_code_with_question(code: str, question: str, rag, llm):
    """코드와 질문을 함께 분석"""
    
    # 가이드라인 컨텍스트 가져오기
    guideline_context = ""
    
    # 질문에서 키워드 추출하여 관련 가이드라인 검색
    keywords = []
    if "sql" in question.lower() or "인젝션" in question.lower():
        keywords.append("SQL 삽입")
    if "xss" in question.lower() or "스크립트" in question.lower():
        keywords.append("크로스사이트 스크립트")
    if "파일" in question.lower() or "업로드" in question.lower():
        keywords.append("파일 업로드")
    if "패스워드" in question.lower() or "암호" in question.lower():
        keywords.append("패스워드")
    
    # 키워드가 없으면 일반적인 보안 검색
    if not keywords:
        keywords = ["입력값 검증", "보안 취약점"]
    
    # 각 키워드에 대해 가이드라인 검색
    for keyword in keywords:
        results = rag.search_similar(keyword, top_k=2)
        if results['documents'][0]:
            guideline_context += f"\n[{keyword} 관련 가이드라인]\n"
            guideline_context += results['documents'][0][0][:500] + "\n"
    
    # 개선된 프롬프트
    prompt = f"""
    당신은 Python 시큐어 코딩 전문가입니다. 
    사용자가 제공한 실제 코드를 분석하여 질문에 답변해주세요.
    
    [사용자의 실제 코드]
    ```python
    {code}
    ```
    
    [Python 시큐어코딩 가이드라인]
    {guideline_context}
    
    [사용자 질문]
    {question}
    
    [답변 지침]
    1. 반드시 위에 제공된 사용자의 실제 코드를 기준으로 답변하세요.
    2. 구체적인 라인 번호나 변수명을 언급하며 설명하세요.
    3. 예제 코드를 보여주지 말고, 사용자 코드의 문제점을 직접 지적하세요.
    4. 가이드라인을 인용할 때는 구체적으로 어떤 부분이 위반되었는지 설명하세요.
    5. 개선 방법을 제시할 때는 사용자 코드를 수정한 버전을 보여주세요.
    
    답변:
    """
    
    try:
        from openai import OpenAI
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system", 
                    "content": "당신은 Python 보안 전문가입니다. 사용자가 제공한 실제 코드를 분석하여 구체적이고 정확한 답변을 제공합니다."
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=1500
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        return f"분석 중 오류 발생: {str(e)}"