import streamlit as st
import os
import json
from dotenv import load_dotenv
from backend import SBOMAnalyzer

# Load environment variables
load_dotenv()

st.set_page_config(
    page_title="SBOM Security Analyzer",
    page_icon="🔒",
    layout="wide"
)

# 분석기 초기화
@st.cache_resource
def get_analyzer():
    return SBOMAnalyzer()

def main():
    st.title("🔒 SBOM Security Analyzer")
    
    # 사이드바
    with st.sidebar:
        st.header("⚙️ 설정")
        
        st.subheader("📊 분석 옵션")
        show_stdlib = st.checkbox("표준 라이브러리 표시", value=False)
        
        st.divider()
        
        st.subheader("🔑 API 상태")
        has_api_key = "OPENAI_API_KEY" in os.environ and os.environ["OPENAI_API_KEY"]
        if has_api_key:
            st.success("✅ OpenAI API Key 설정됨")
        else:
            st.warning("⚠️ OpenAI API Key 필요")
            st.text_input("API Key 입력:", type="password", key="api_key_input")
    
    # 메인 탭
    tab1, tab2, tab3 = st.tabs(["📝 코드 분석", "💬 Q&A", "📚 가이드라인"])
    
    with tab1:
        st.header("Python 코드 분석")
        
        # 두 개의 컬럼으로 입력 영역 구성
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.subheader("📄 Python 코드")
            code_input = st.text_area(
                "코드를 입력하세요:",
                height=400,
                placeholder="import pandas as pd\nimport numpy as np\n...",
                value="""import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import requests

def main():
    df = pd.read_csv('data.csv')
    return df

if __name__ == '__main__':
    main()"""
            )
        
        with col2:
            st.subheader("📦 requirements.txt (선택)")
            req_input = st.text_area(
                "requirements.txt 내용:",
                height=400,
                placeholder="pandas==2.0.0\nnumpy>=1.24.0\n...",
                value="""pandas==2.0.0
numpy>=1.24.0
scikit-learn
requests==2.31.0"""
            )
        
        # 분석 버튼
        if st.button("🔍 SBOM 생성", type="primary", use_container_width=True):
            if code_input:
                analyzer = get_analyzer()
                
                with st.spinner("코드 분석 중..."):
                    result = analyzer.analyze(code_input, req_input)
                
                if result.get("success"):
                    # 성공 메시지
                    st.success("✅ 분석 완료!")
                    
                    # 요약 정보 표시
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("전체 Import", result["summary"]["total_imports"])
                    with col2:
                        st.metric("외부 패키지", result["summary"]["external_packages"])
                    with col3:
                        st.metric("버전 확인", result["summary"]["with_version"])
                    with col4:
                        st.metric("버전 미확인", result["summary"]["without_version"])
                    
                    # 패키지 목록 테이블
                    st.subheader("📋 발견된 패키지")
                    
                    if result["packages"]:
                        # 테이블 데이터 준비
                        table_data = []
                        for pkg in result["packages"]:
                            row = {
                                "상태": pkg["status"],
                                "Import명": pkg["name"],
                                "설치 패키지명": pkg["install_name"],
                                "버전": pkg["version"] if pkg["version"] else "미지정",
                                "별칭": pkg["alias"] if pkg["alias"] else "-"
                            }
                            table_data.append(row)
                        
                        # 데이터프레임으로 표시
                        import pandas as pd
                        df = pd.DataFrame(table_data)
                        st.dataframe(df, use_container_width=True)
                        
                        # SBOM JSON 생성
                        sbom_data = {
                            "tool": "SBOM Security Analyzer",
                            "version": "0.1.0",
                            "timestamp": pd.Timestamp.now().isoformat(),
                            "packages": result["packages"]
                        }
                        
                        # JSON 다운로드 버튼
                        st.download_button(
                            label="📥 SBOM JSON 다운로드",
                            data=json.dumps(sbom_data, indent=2),
                            file_name="sbom.json",
                            mime="application/json"
                        )
                        
                        # 상세 정보 (접을 수 있게)
                        with st.expander("🔍 상세 분석 결과"):
                            st.json(result)
                    else:
                        st.info("외부 패키지를 찾을 수 없습니다.")
                
                elif "error" in result:
                    st.error(f"❌ 오류 발생: {result['error']}")
            else:
                st.warning("⚠️ Python 코드를 입력해주세요.")
    
    with tab2:
        st.header("Q&A with RAG")
        st.info("🚧 RAG 시스템 구현 예정")
        
        # TODO: RAG 구현
        st.text_area("질문:", placeholder="SBOM이나 보안에 대해 물어보세요...")
        if st.button("답변 받기", disabled=True):
            pass
    
    with tab3:
        st.header("가이드라인 관리")
        st.info("🚧 PDF 업로드 기능 구현 예정")
        
        # TODO: PDF 업로드 구현
        uploaded_files = st.file_uploader(
            "PDF 파일 선택",
            type=['pdf'],
            accept_multiple_files=True,
            disabled=True
        )

if __name__ == "__main__":
    main()