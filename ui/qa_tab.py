"""
Q&A tab UI
"""
import streamlit as st

def render_qa_tab():
    """Q&A 탭 렌더링"""
    st.header("💬 Q&A with RAG")
    
    st.info("🚧 RAG 시스템 구현 예정")
    
    # 채팅 인터페이스
    if 'messages' not in st.session_state:
        st.session_state.messages = []
    
    # 기존 메시지 표시
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])
    
    # 입력
    if prompt := st.chat_input("질문을 입력하세요..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        
        with st.chat_message("user"):
            st.write(prompt)
        
        # TODO: RAG 시스템 연동
        with st.chat_message("assistant"):
            response = "RAG 시스템이 구현되면 여기에 답변이 표시됩니다."
            st.write(response)
            st.session_state.messages.append({"role": "assistant", "content": response})