"""
Code analysis tab UI
"""
import streamlit as st
import json
import pandas as pd
from core.analyzer import SBOMAnalyzer
from core.formatter import SBOMFormatter
from security.vulnerability import check_vulnerabilities

def render_code_analysis_tab():
    """코드 분석 탭 렌더링"""
    st.header("Python 코드 분석")
    
    # 분석기 초기화
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = SBOMAnalyzer()
    if 'formatter' not in st.session_state:
        st.session_state.formatter = SBOMFormatter()
    
    analyzer = st.session_state.analyzer
    formatter = st.session_state.formatter
    
    # 입력 영역
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
requests==2.25.0"""
        )
    
    # 분석 버튼
    if st.button("🔍 SBOM 생성", type="primary", use_container_width=True):
        if code_input:
            with st.spinner("코드 분석 중..."):
                result = analyzer.analyze(code_input, req_input)
                
                # 취약점 검사
                if result.get("success"):
                    result = check_vulnerabilities(result["packages"], result)
            
            if result.get("success"):
                display_analysis_results(result, formatter)
            elif "error" in result:
                st.error(f"❌ 오류 발생: {result['error']}")
        else:
            st.warning("⚠️ Python 코드를 입력해주세요.")

def display_analysis_results(result, formatter):
    """분석 결과 표시"""
    st.success("✅ 분석 완료!")
    
    # 요약 정보
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("전체 Import", result["summary"]["total_imports"])
    with col2:
        st.metric("외부 패키지", result["summary"]["external_packages"])
    with col3:
        st.metric("버전 확인", result["summary"]["with_version"])
    with col4:
        st.metric("버전 미확인", result["summary"]["without_version"])
    with col5:
        vuln_count = result["summary"].get("total_vulnerabilities", 0)
        if vuln_count > 0:
            st.metric("🚨 취약점", vuln_count)
        else:
            st.metric("🛡️ 취약점", "0")
    
    # 취약점 경고
    vulnerable_packages = [p for p in result["packages"] if p.get("vulnerabilities")]
    if vulnerable_packages:
        st.error(f"⚠️ {len(vulnerable_packages)}개 패키지에서 취약점이 발견되었습니다!")
        
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
    
    # 패키지 테이블
    if result["packages"]:
        st.subheader("📋 발견된 패키지")
        
        table_data = []
        for pkg in result["packages"]:
            vuln_count = len(pkg.get("vulnerabilities", []))
            table_data.append({
                "상태": pkg["status"],
                "Import명": pkg["name"],
                "설치 패키지명": pkg["install_name"],
                "버전": pkg["version"] if pkg["version"] else "미지정",
                "취약점": f"{vuln_count}개" if vuln_count > 0 else "없음",
                "별칭": pkg["alias"] if pkg["alias"] else "-"
            })
        
        df = pd.DataFrame(table_data)
        st.dataframe(df, use_container_width=True)
    
    # SBOM 다운로드
    sbom_format = st.selectbox("SBOM 형식", ["Custom JSON", "SPDX", "CycloneDX"])
    
    if sbom_format == "Custom JSON":
        sbom_data = {
            "tool": "SBOM Security Analyzer",
            "version": "0.1.0",
            "timestamp": pd.Timestamp.now().isoformat(),
            "packages": result["packages"]
        }
    else:
        metadata = {"project_name": "MyProject", "project_version": "1.0.0"}
        sbom_data = formatter.format_sbom(result["packages"], sbom_format, metadata)
    
    with st.expander(f"📄 {sbom_format} 형식 보기"):
        st.json(sbom_data)
    
    st.download_button(
        label=f"📥 SBOM 다운로드 ({sbom_format})",
        data=json.dumps(sbom_data, indent=2),
        file_name=f"sbom_{sbom_format.lower()}.json",
        mime="application/json"
    )