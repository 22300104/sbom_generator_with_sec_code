"""
Code analysis tab UI - Improved UX for SBOM format selection
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
    
    # SBOM 생성 섹션 - 형식 선택과 버튼을 한 줄에 배치
    st.subheader("🔧 SBOM 생성 옵션")
    
    col1, col2, col3 = st.columns([2, 2, 3])
    
    with col1:
        sbom_format = st.selectbox(
            "📋 출력 형식",
            options=["Custom JSON", "SPDX", "CycloneDX"],
            help="• Custom JSON: 간단한 커스텀 형식\n• SPDX: 라이선스 컴플라이언스 중심\n• CycloneDX: 보안 취약점 중심"
        )
    
    with col2:
        check_vulns = st.checkbox(
            "🔍 취약점 검사",
            value=True,
            help="OSV 데이터베이스를 사용한 실시간 취약점 검사"
        )
    
    with col3:
        # 분석 버튼
        analyze_button = st.button(
            f"🚀 SBOM 생성 ({sbom_format})",
            type="primary",
            use_container_width=True
        )
    
    # 분석 실행
    if analyze_button:
        if code_input:
            with st.spinner("코드 분석 중..."):
                result = analyzer.analyze(code_input, req_input)
                
                # 취약점 검사 (옵션에 따라)
                if result.get("success") and check_vulns:
                    with st.spinner("취약점 검사 중..."):
                        result = check_vulnerabilities(result["packages"], result)
            
            if result.get("success"):
                # 선택된 형식을 전달
                display_analysis_results(result, formatter, sbom_format, check_vulns)
            elif "error" in result:
                st.error(f"❌ 오류 발생: {result['error']}")
        else:
            st.warning("⚠️ Python 코드를 입력해주세요.")

def display_analysis_results(result, formatter, sbom_format, vulnerability_checked):
    """분석 결과 표시"""
    
    # 구분선
    st.divider()
    
    # 성공 메시지와 형식 표시
    col1, col2 = st.columns([3, 1])
    with col1:
        st.success(f"✅ 분석 완료! - {sbom_format} 형식으로 SBOM 생성됨")
    with col2:
        # 재분석 버튼
        if st.button("🔄 다시 분석"):
            st.rerun()
    
    # 요약 정보
    st.subheader("📊 분석 요약")
    
    if vulnerability_checked:
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
                st.metric("🚨 취약점", vuln_count, delta_color="inverse")
            else:
                st.metric("🛡️ 취약점", "0", delta_color="off")
    else:
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("전체 Import", result["summary"]["total_imports"])
        with col2:
            st.metric("외부 패키지", result["summary"]["external_packages"])
        with col3:
            st.metric("버전 확인", result["summary"]["with_version"])
        with col4:
            st.metric("버전 미확인", result["summary"]["without_version"])
    
    # 취약점 경고 (취약점 검사를 했을 경우만)
    if vulnerability_checked:
        vulnerable_packages = [p for p in result["packages"] if p.get("vulnerabilities")]
        if vulnerable_packages:
            st.error(f"⚠️ {len(vulnerable_packages)}개 패키지에서 취약점이 발견되었습니다!")
            
            with st.expander("🚨 취약점 상세 정보", expanded=True):
                for pkg in vulnerable_packages:
                    st.markdown(f"### {pkg['name']} ({pkg['version']})")
                    for vuln in pkg["vulnerabilities"]:
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            severity_emoji = {
                                "CRITICAL": "🔴",
                                "HIGH": "🟠", 
                                "MEDIUM": "🟡",
                                "LOW": "🔵"
                            }.get(vuln['severity'], "⚪")
                            st.write(f"{severity_emoji} **{vuln['id']}** - {vuln['severity']}")
                            st.write(f"📝 {vuln['summary']}")
                        with col2:
                            if vuln.get('fixed_version'):
                                st.info(f"수정 버전:\n{vuln['fixed_version']}")
                    st.divider()
    
    # 패키지 테이블
    st.subheader("📋 발견된 패키지")
    
    if result["packages"]:
        table_data = []
        for pkg in result["packages"]:
            vuln_count = len(pkg.get("vulnerabilities", []))
            row = {
                "상태": pkg["status"],
                "Import명": pkg["name"],
                "설치 패키지명": pkg["install_name"],
                "버전": pkg["version"] if pkg["version"] else "미지정",
            }
            
            if vulnerability_checked:
                row["취약점"] = f"{vuln_count}개" if vuln_count > 0 else "✅"
            
            if pkg["alias"]:
                row["별칭"] = pkg["alias"]
            
            table_data.append(row)
        
        df = pd.DataFrame(table_data)
        
        # 취약점이 있는 행 강조 (취약점 검사를 했을 경우만)
        if vulnerability_checked:
            def highlight_vulnerabilities(row):
                if "취약점" in row and "개" in str(row["취약점"]) and row["취약점"] != "0개":
                    return ['background-color: #ffcccc'] * len(row)
                return [''] * len(row)
            
            styled_df = df.style.apply(highlight_vulnerabilities, axis=1)
            st.dataframe(styled_df, use_container_width=True, hide_index=True)
        else:
            st.dataframe(df, use_container_width=True, hide_index=True)
    
    # SBOM 생성 및 표시
    st.subheader(f"📄 생성된 SBOM")
    
    # SBOM 데이터 생성
    if sbom_format == "Custom JSON":
        sbom_data = {
            "tool": "SBOM Security Analyzer",
            "version": "0.1.0",
            "timestamp": pd.Timestamp.now().isoformat(),
            "packages": result["packages"],
            "summary": result["summary"]
        }
        if vulnerability_checked:
            sbom_data["vulnerabilities_summary"] = {
                "total": result["summary"].get("total_vulnerabilities", 0),
                "affected_packages": result["summary"].get("vulnerable_packages", 0)
            }
    else:
        # SPDX 또는 CycloneDX 형식
        metadata = {
            "project_name": "MyPythonProject", 
            "project_version": "1.0.0"
        }
        sbom_data = formatter.format_sbom(result["packages"], sbom_format, metadata)
    
    # 두 개의 탭으로 표시: 미리보기와 다운로드
    tab1, tab2 = st.tabs(["👁️ 미리보기", "💾 다운로드"])
    
    with tab1:
        # SBOM 내용 표시
        st.json(sbom_data)
    
    with tab2:
        # 형식별 설명
        format_info = {
            "SPDX": "🔷 SPDX는 Linux Foundation이 주도하는 표준으로, 라이선스 컴플라이언스와 법적 검토에 최적화되어 있습니다.",
            "CycloneDX": "🔶 CycloneDX는 OWASP가 만든 표준으로, 보안 취약점 추적과 리스크 관리에 특화되어 있습니다.",
            "Custom JSON": "🔵 Custom JSON은 이 도구의 고유 형식으로, 모든 분석 정보를 포함하는 가장 상세한 형식입니다."
        }
        st.info(format_info.get(sbom_format, ""))
        
        # 다운로드 옵션
        col1, col2 = st.columns(2)
        
        with col1:
            filename = f"sbom_{sbom_format.lower().replace(' ', '_')}.json"
            st.download_button(
                label=f"📥 JSON 파일 다운로드",
                data=json.dumps(sbom_data, indent=2),
                file_name=filename,
                mime="application/json",
                use_container_width=True
            )
        
        with col2:
            # Pretty print 버전 다운로드
            pretty_json = json.dumps(sbom_data, indent=4, ensure_ascii=False)
            st.download_button(
                label=f"📥 Pretty JSON 다운로드",
                data=pretty_json,
                file_name=f"sbom_{sbom_format.lower()}_pretty.json",
                mime="application/json",
                use_container_width=True
            )