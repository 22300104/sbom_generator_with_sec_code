import streamlit as st
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

st.set_page_config(
    page_title="SBOM Security Analyzer",
    page_icon="🔒",
    layout="wide"
)

st.title("🔒 SBOM Security Analyzer")
st.write("설치 성공! 이제 시작할 수 있습니다.")

# 사이드바
with st.sidebar:
    st.header("설정")
    st.write("OpenAI API Key 설정됨:", "OPENAI_API_KEY" in os.environ)

# 메인 탭
tab1, tab2, tab3 = st.tabs(["📝 코드 분석", "💬 Q&A", "📚 가이드라인"])

with tab1:
    st.header("Python 코드 분석")
    code = st.text_area("Python 코드 입력:", height=300)
    if st.button("분석 시작"):
        st.info("분석 기능 구현 예정")

with tab2:
    st.header("Q&A")
    st.info("RAG 시스템 구현 예정")

with tab3:
    st.header("가이드라인 관리")
    st.info("PDF 업로드 기능 구현 예정")