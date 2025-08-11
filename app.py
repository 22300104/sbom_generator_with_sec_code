"""
SBOM Security Analyzer - Main App
프로젝트 분석 탭 제거, 통합된 코드 분석 탭 사용
"""
import streamlit as st
import os
from dotenv import load_dotenv

# 환경 변수 로드
load_dotenv()

# 페이지 설정
st.set_page_config(
    page_title="SBOM Security Analyzer",
    page_icon="🔒",
    layout="wide"
)

# UI 모듈 임포트
from ui.code_analysis_tab import render_code_analysis_tab
from ui.qa_tab import render_qa_tab

def main():
    st.title("🔒 SBOM Security Analyzer")
    
    with st.sidebar:
        st.header("⚙️ 설정")
        
        # API 키 상태
        has_api_key = bool(os.getenv("OPENAI_API_KEY"))
        if has_api_key:
            st.success("✅ OpenAI API Key 설정됨")
            model = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
            st.caption(f"모델: {model}")
        else:
            st.warning("⚠️ OpenAI API Key 미설정")
            st.info("AI 보안 분석을 사용하려면 API 키가 필요합니다")
            
            api_key = st.text_input("API Key 입력:", type="password", key="api_key_input")
            if api_key:
                os.environ["OPENAI_API_KEY"] = api_key
                st.rerun()
        
        st.divider()
        
        # 기능 설명
        st.subheader("📋 주요 기능")
        st.markdown("""
        **분석 탭:**
        - 코드 직접 입력
        - GitHub 저장소 분석
        - 압축 파일 업로드
        - SBOM 생성 (SPDX, CycloneDX)
        - AI 취약점 탐지
        - 알려진 취약점 검사
        
        **Q&A 탭:**
        - KISIA 가이드라인 기반
        - 시큐어 코딩 질문 답변
        """)
        
        # 캐시 클리어
        if st.button("🔄 캐시 클리어"):
            st.cache_data.clear()
            for key in list(st.session_state.keys()):
                if key != 'api_key_input':  # API 키는 유지
                    del st.session_state[key]
            st.rerun()
    
    # 메인 탭
    tab1, tab2, tab3 = st.tabs(["🔍 분석", "💬 Q&A", "📖 도움말"])
    
    with tab1:
        render_code_analysis_tab()
    
    with tab2:
        render_qa_tab()
    
    with tab3:
        render_help_tab()


def render_help_tab():
    """도움말 탭"""
    st.header("📖 사용 가이드")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔍 분석 기능")
        st.markdown("""
        ### 입력 방법
        1. **직접 입력**: Python 코드를 텍스트 영역에 입력
        2. **GitHub URL**: 공개 저장소 URL 입력
        3. **파일 업로드**: .py 파일 또는 압축파일
        
        ### 분석 모드
        - **⚡ 빠른 분석**: SBOM과 패키지 정보만 (1-2초)
        - **🤖 AI 보안 분석**: GPT 기반 취약점 탐지 (10-20초)
        - **🔥 전체 분석**: 모든 기능 실행 (20-30초)
        
        ### 탐지 가능한 취약점
        - SQL/Command Injection
        - XSS, CSRF
        - 약한 암호화
        - 하드코딩된 시크릿
        - 안전하지 않은 역직렬화
        - Path Traversal
        """)
    
    with col2:
        st.subheader("💡 팁")
        st.markdown("""
        ### 성능 최적화
        - 큰 프로젝트는 파일 수 제한 (50개 권장)
        - 코드 크기 제한 조정 (기본 15,000자)
        - 빠른 분석으로 먼저 확인
        
        ### SBOM 표준 형식
        - **SPDX 2.3**: 라이선스 중심
        - **CycloneDX 1.4**: 보안 중심
        
        ### 환경 스캔
        - 실제 설치된 패키지 버전 확인
        - requirements.txt와 비교
        - 버전 불일치 감지
        
        ### 문제 해결
        - 패키지 "미설치" 표시 → 환경 스캔 체크
        - 분석 느림 → 코드 크기 줄이기
        - API 오류 → API 키 확인
        """)
    
    with st.expander("🤔 자주 묻는 질문"):
        st.markdown("""
        **Q: 파라미터 바인딩이 SQL 인젝션으로 잘못 탐지됩니다**
        - A: 최신 버전에서 수정되었습니다. `?`나 `%s`를 사용한 파라미터 바인딩은 안전합니다.
        
        **Q: GitHub private 저장소를 분석할 수 있나요?**
        - A: 현재는 공개 저장소만 지원합니다.
        
        **Q: 분석 결과를 저장할 수 있나요?**
        - A: 다운로드 탭에서 JSON, SPDX, CycloneDX 형식으로 저장 가능합니다.
        
        **Q: SECRET_KEY='dev'가 위험하다고 나오는데 개발용입니다**
        - A: 개발용이라도 하드코딩은 권장하지 않습니다. 환경변수 사용을 권장합니다.
        """)


if __name__ == "__main__":
    main()