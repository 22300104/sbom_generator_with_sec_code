"""
SBOM Security Analyzer - Main Streamlit App
"""
import streamlit as st
import os
from dotenv import load_dotenv
from config import app_config

# UI 모듈 임포트
from ui.code_analysis_tab import render_code_analysis_tab
from ui.qa_tab import render_qa_tab

# 환경 변수 로드
load_dotenv()

# 페이지 설정
st.set_page_config(
    page_title=app_config.APP_NAME,
    page_icon=app_config.PAGE_ICON,
    layout=app_config.LAYOUT
)

def main():
    st.title(f"{app_config.PAGE_ICON} {app_config.APP_NAME}")
    
    # 사이드바
    with st.sidebar:
        st.header("⚙️ 설정")
        
        st.subheader("🔑 API 상태")
        has_api_key = "OPENAI_API_KEY" in os.environ and os.environ["OPENAI_API_KEY"]
        if has_api_key:
            st.success("✅ OpenAI API Key 설정됨")
        else:
            st.warning("⚠️ OpenAI API Key 필요")
            api_key = st.text_input("API Key 입력:", type="password")
            if api_key:
                os.environ["OPENAI_API_KEY"] = api_key
                st.rerun()
        
        st.divider()
        
        # 캐시 클리어 (개발용)
        if st.button("🔄 캐시 클리어"):
            st.cache_data.clear()
            st.rerun()
    
    # 메인 탭
    tab1, tab2, tab3 = st.tabs(["📝 코드 분석", "💬 Q&A", "📚 가이드라인"])
    
    with tab1:
        render_code_analysis_tab()
    
    with tab2:
        render_qa_tab()
    

if __name__ == "__main__":
    main()