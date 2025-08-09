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
        # 캐시 클리어 버튼 추가 (사이드바에)
        if st.button("🔄 캐시 클리어"):
            st.cache_resource.clear()
            st.rerun()
            
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

        # 사이드바에 옵션 추가 (약 30번째 줄)
        st.subheader("🔍 검사 옵션")
        check_vulnerabilities = st.checkbox("취약점 검사", value=True)
        st.caption("OSV 데이터베이스를 사용한 실시간 검사")

            # SBOM 형식 선택 추가
        st.subheader("📦 SBOM 형식")
        sbom_format = st.selectbox(
            "출력 형식 선택",
            options=["Custom JSON", "SPDX", "CycloneDX"],
            help="Custom JSON: 간단한 형식\nSPDX: 라이선스 중심\nCycloneDX: 보안 중심"
        )
    
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
                    # analyze 호출 부분 수정 (약 90번째 줄)
                    result = analyzer.analyze(code_input, req_input)
                
                if result.get("success"):
                    # 성공 메시지
                    st.success("✅ 분석 완료!")
                    
                    # 요약 정보 표시 부분 수정 (약 98번째 줄)
                    col1, col2, col3, col4, col5 = st.columns(5)  # 5개 컬럼으로 변경
                    with col1:
                        st.metric("전체 Import", result["summary"]["total_imports"])
                    with col2:
                        st.metric("외부 패키지", result["summary"].get("external_packages", 0))
                    with col3:
                        st.metric("버전 확인", result["summary"]["with_version"])
                    with col4:
                        st.metric("버전 미확인", result["summary"]["without_version"])
                    with col5:
                        # 취약점 메트릭 추가
                        vuln_count = result["summary"].get("total_vulnerabilities", 0)
                        if vuln_count > 0:
                            st.metric("🚨 취약점", vuln_count, delta_color="inverse")
                        else:
                            st.metric("🛡️ 취약점", "0")

                    # 패키지 목록 테이블 부분도 수정
                    st.subheader("📋 발견된 패키지")

                    if result["packages"]:
                        # 취약점이 있는 패키지 먼저 표시
                        vulnerable_packages = [p for p in result["packages"] if p.get("vulnerabilities")]
                        safe_packages = [p for p in result["packages"] if not p.get("vulnerabilities")]
                        
                        # 취약점 경고
                        if vulnerable_packages:
                            st.error(f"⚠️ {len(vulnerable_packages)}개 패키지에서 취약점이 발견되었습니다!")
                            
                            # 취약한 패키지 상세 정보
                            with st.expander("🚨 취약점 상세 정보", expanded=True):
                                for pkg in vulnerable_packages:
                                    st.markdown(f"### {pkg['name']} ({pkg['version']})")
                                    
                                    for vuln in pkg["vulnerabilities"]:
                                        col1, col2 = st.columns([3, 1])
                                        with col1:
                                            st.write(f"**{vuln['id']}** - {vuln['severity']}")
                                            st.write(f"📝 {vuln['summary']}")
                                        with col2:
                                            if vuln.get('fixed_version'):
                                                st.info(f"수정 버전:\n{vuln['fixed_version']}")
                                    st.divider()
                        
                        # 전체 패키지 테이블
                        table_data = []
                        for pkg in result["packages"]:
                            vuln_count = len(pkg.get("vulnerabilities", []))
                            row = {
                                "상태": pkg["status"],
                                "Import명": pkg["name"],
                                "설치 패키지명": pkg["install_name"],
                                "버전": pkg["version"] if pkg["version"] else "미지정",
                                "취약점": f"{vuln_count}개" if vuln_count > 0 else "없음",
                                "별칭": pkg["alias"] if pkg["alias"] else "-"
                            }
                            table_data.append(row)
                        
                        # 데이터프레임으로 표시
                        import pandas as pd
                        df = pd.DataFrame(table_data)
                        
                        # 취약점이 있는 행 강조
                        def highlight_vulnerabilities(row):
                            if "개" in row["취약점"] and row["취약점"] != "0개":
                                return ['background-color: #ffcccc'] * len(row)
                            return [''] * len(row)
                        
                        styled_df = df.style.apply(highlight_vulnerabilities, axis=1)
                        st.dataframe(styled_df, use_container_width=True)
                        
                        # SBOM 생성 부분 수정
                        if sbom_format == "Custom JSON":
                            # 기존 코드
                            sbom_data = {
                                "tool": "SBOM Security Analyzer",
                                "version": "0.1.0",
                                "timestamp": pd.Timestamp.now().isoformat(),
                                "packages": result["packages"],
                                "vulnerabilities_summary": {
                                    "total": result["summary"].get("total_vulnerabilities", 0),
                                    "affected_packages": result["summary"].get("vulnerable_packages", 0)
                                }
                            }
                        else:
                            # 표준 형식 사용 - analyzer 객체 직접 사용
                            metadata = {
                                "project_name": "MyPythonProject",
                                "project_version": "1.0.0"
                            }
                            sbom_data = analyzer.generate_sbom(
                                result["packages"], 
                                sbom_format, 
                                metadata
                            )

                        # SBOM 표시
                        with st.expander(f"📄 {sbom_format} 형식 보기", expanded=False):
                            st.json(sbom_data)

                        # JSON 다운로드 버튼
                        filename = f"sbom_{sbom_format.lower()}.json"
                        st.download_button(
                            label=f"📥 SBOM 다운로드 ({sbom_format})",
                            data=json.dumps(sbom_data, indent=2),
                            file_name=filename,
                            mime="application/json"
                        )
                
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
    
    # app.py의 tab3 부분
    with tab3:
        st.header("📚 가이드라인 관리")
        
        analyzer = get_analyzer()
        
        if analyzer.guideline_loader.is_loaded:
            # 로드된 문서 통계
            doc_list = analyzer.guideline_loader.get_document_list()
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("📁 총 문서", len(doc_list))
            with col2:
                total_pages = sum(d["pages"] for d in doc_list)
                st.metric("📄 총 페이지", total_pages)
            with col3:
                total_chars = sum(d["characters"] for d in doc_list)
                st.metric("📝 총 문자", f"{total_chars:,}")
            
            # 문서 목록
            st.subheader("📋 로드된 가이드라인")
            
            # 데이터프레임으로 표시
            import pandas as pd
            df = pd.DataFrame(doc_list)
            st.dataframe(df, use_container_width=True)
            
            # 키워드 검색
            st.subheader("🔍 통합 검색")
            search_col1, search_col2 = st.columns([3, 1])
            
            with search_col1:
                keyword = st.text_input("검색어 입력:", placeholder="예: 비밀번호, 암호화, SQL")
            
            with search_col2:
                search_btn = st.button("검색", type="primary", use_container_width=True)
            
            if keyword and search_btn:
                with st.spinner("검색 중..."):
                    results = analyzer.guideline_loader.search_in_all(keyword)
                
                if results:
                    st.success(f"'{keyword}' 검색 결과: {len(results)}건")
                    
                    # 파일별로 그룹화
                    from collections import defaultdict
                    grouped = defaultdict(list)
                    for r in results:
                        grouped[r["file"]].append(r)
                    
                    # 파일별로 표시
                    for filename, file_results in grouped.items():
                        with st.expander(f"📄 {filename} ({len(file_results)}건)"):
                            for result in file_results:
                                st.markdown(f"**페이지 {result['page']}**")
                                st.markdown(result['snippet'])
                                st.divider()
                else:
                    st.info("검색 결과가 없습니다.")
            
            # 문서 내용 보기
            st.subheader("📖 문서 내용 보기")
            
            selected_doc = st.selectbox(
                "문서 선택",
                options=[d["filename"] for d in doc_list]
            )
            
            if selected_doc:
                doc_info = next(d for d in doc_list if d["filename"] == selected_doc)
                
                page_num = st.slider(
                    "페이지 선택",
                    min_value=1,
                    max_value=doc_info["pages"],
                    value=1
                )
                
                content = analyzer.guideline_loader.get_document_content(selected_doc, page_num)
                
                if content:
                    with st.expander(f"내용 (페이지 {page_num})", expanded=True):
                        st.text_area(
                            "",
                            value=content[:2000],  # 처음 2000자만
                            height=400,
                            disabled=True
                        )
                        if len(content) > 2000:
                            st.caption(f"... (총 {len(content)}자 중 처음 2000자만 표시)")
        
        else:
            st.warning("⚠️ 가이드라인이 로드되지 않았습니다.")
            st.info("data/guidelines/ 폴더에 PDF 파일을 넣어주세요.")

if __name__ == "__main__":
    main()