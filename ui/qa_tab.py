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
    """Q&A 탭 - RAG 중심 답변"""
    st.header("💬 시큐어 코딩 Q&A")
    
    # RAG 시스템 초기화
    if 'rag_system' not in st.session_state:
        try:
            st.session_state.rag_system = SimpleRAG()
            stats = st.session_state.rag_system.get_stats()
            st.success(f"✅ 가이드라인 로드 완료 ({stats['total_documents']}개 문서)")
        except Exception as e:
            st.error(f"❌ RAG 시스템 오류: {e}")
            return
    
    rag = st.session_state.rag_system
    
    # 채팅 히스토리
    if 'qa_messages' not in st.session_state:
        st.session_state.qa_messages = []
    
    # 예제 질문
    with st.sidebar:
        st.subheader("💡 예제 질문")
        example_questions = [
            "SQL 인젝션을 방어하는 방법은?",
            "파라미터 바인딩이 왜 안전한가요?",
            "패스워드는 어떻게 저장해야 하나요?",
            "XSS 공격을 방지하려면?",
            "환경변수는 왜 사용해야 하나요?",
        ]
        
        for q in example_questions:
            if st.button(q, key=f"ex_{q}"):
                st.session_state.pending_question = q
    
    # 이전 대화 표시
    for msg in st.session_state.qa_messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg.get("sources"):
                with st.expander("📚 출처 보기"):
                    for source in msg["sources"]:
                        st.caption(source)
    
    # 질문 입력
    if prompt := st.chat_input("질문을 입력하세요..."):
        process_question(prompt, rag)
    
    # 예제 질문 처리
    if 'pending_question' in st.session_state:
        process_question(st.session_state.pending_question, rag)
        del st.session_state.pending_question


def process_question(question: str, rag):
    """질문 처리 - RAG 80% + GPT 20%"""
    
    # 사용자 메시지 추가
    st.session_state.qa_messages.append({"role": "user", "content": question})
    
    with st.chat_message("user"):
        st.markdown(question)
    
    with st.chat_message("assistant"):
        with st.spinner("답변 생성 중..."):
            start_time = time.time()
            
            # 1단계: RAG에서 관련 문서 검색 (80%)
            search_results = rag.search_similar(question, top_k=5)
            
            if not search_results['documents'][0]:
                st.warning("관련 가이드라인을 찾을 수 없습니다.")
                response = "죄송합니다. 관련된 가이드라인을 찾을 수 없습니다."
                sources = []
            else:
                # 관련 문서 추출
                documents = search_results['documents'][0]
                metadatas = search_results['metadatas'][0] if search_results.get('metadatas') else []
                
                # 중복 제거 및 정리
                unique_docs = []
                seen = set()
                sources = []
                
                for i, doc in enumerate(documents):
                    doc_preview = doc[:200]
                    if doc_preview not in seen:
                        seen.add(doc_preview)
                        unique_docs.append(doc)
                        
                        # 출처 정보
                        if i < len(metadatas):
                            page = metadatas[i].get('page', '?')
                            sources.append(f"KISIA 가이드라인 p.{page}: {doc[:100]}...")
                
                # 2단계: GPT로 답변 생성 (20% - 문서 기반)
                response = generate_answer_with_sources(question, unique_docs, sources)
            
            elapsed = time.time() - start_time
            
            # 답변 표시
            st.markdown(response)
            
            # 소요 시간
            st.caption(f"⏱️ {elapsed:.2f}초")
            
            # 출처 표시
            if sources:
                with st.expander("📚 참고 문서"):
                    for source in sources[:3]:  # 상위 3개만
                        st.caption(source)
            
            # 대화 기록에 추가
            st.session_state.qa_messages.append({
                "role": "assistant",
                "content": response,
                "sources": sources
            })


def generate_answer_with_sources(question: str, documents: list, sources: list) -> str:
    """근거 기반 답변 생성"""
    
    from openai import OpenAI
    
    # 문서 컨텍스트 생성
    context = "\n\n".join(documents[:3])  # 상위 3개 문서
    
    # 프롬프트 생성
    prompt = get_qa_prompt(question, context)
    
    try:
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": """당신은 KISIA Python 시큐어코딩 가이드 전문가입니다.
                    반드시 제공된 문서를 근거로 답변하세요.
                    추측하지 말고, 문서에 없는 내용은 '가이드라인에 명시되지 않음'이라고 하세요."""
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,  # 일관성 있는 답변
            max_tokens=1000
        )
        
        answer = response.choices[0].message.content
        
        # 답변에 근거 표시 추가
        answer += "\n\n---\n*📌 이 답변은 KISIA Python 시큐어코딩 가이드라인을 기반으로 작성되었습니다.*"
        
        return answer
        
    except Exception as e:
        # GPT 실패 시 RAG 문서 직접 사용
        return f"""
다음은 KISIA 가이드라인의 관련 내용입니다:

{documents[0][:500]}...

전체 내용은 출처를 참고해주세요.
"""


def render_code_context_qa():
    """코드 컨텍스트 기반 Q&A"""
    st.subheader("📝 코드 분석 Q&A")
    
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
                    st.warning(f"⚠️ {len(vulns)}개 취약점 발견")
                    for vuln in vulns:
                        with st.expander(f"{vuln['type']} - {vuln['severity']}"):
                            st.write(f"**이유:** {vuln.get('reasoning', '')}")
                            st.write(f"**공격 시나리오:** {vuln.get('attack_scenario', '')}")
                            st.write(f"**권장사항:** {vuln.get('recommendation', '')}")
                else:
                    st.success("✅ 취약점이 발견되지 않았습니다.")
                
                # 안전한 practice
                if safe_practices:
                    st.success(f"👍 {len(safe_practices)}개의 안전한 코딩 practice 발견")
                    for practice in safe_practices:
                        st.write(f"• {practice['practice']}: {practice['description']}")
        
        except Exception as e:
            st.error(f"분석 실패: {e}")