"""
Enhanced Code analysis tab UI with LLM integration
"""
import streamlit as st
import json
import pandas as pd
from core.analyzer import SBOMAnalyzer
from core.formatter import SBOMFormatter
from core.llm_analyzer import LLMSecurityAnalyzer
from security.vulnerability import check_vulnerabilities
import time

def render_code_analysis_tab():
    """강화된 코드 분석 탭"""
    st.header("🔍 AI 기반 코드 보안 분석")
    
    # 분석기 초기화
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = SBOMAnalyzer()
    if 'formatter' not in st.session_state:
        st.session_state.formatter = SBOMFormatter()
    if 'llm_analyzer' not in st.session_state:
        try:
            st.session_state.llm_analyzer = LLMSecurityAnalyzer()
        except:
            st.session_state.llm_analyzer = None
    
    analyzer = st.session_state.analyzer
    formatter = st.session_state.formatter
    llm_analyzer = st.session_state.llm_analyzer
    
    # 분석 모드 선택
    analysis_mode = st.radio(
        "분석 모드 선택",
        ["🚀 빠른 분석 (SBOM + OSV)", "🤖 AI 심층 분석 (LLM + RAG)", "⚡ 전체 분석 (All)"],
        horizontal=True
    )
    
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
import sqlite3

def get_user_data(user_id):
    # SQL 인젝션 취약점 예시
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def save_file(file_content, filename):
    # 경로 조작 취약점 예시
    with open(f"uploads/{filename}", 'w') as f:
        f.write(file_content)

if __name__ == '__main__':
    data = get_user_data(input("User ID: "))
    print(data)"""
        )
    
    with col2:
        st.subheader("📦 requirements.txt")
        req_input = st.text_area(
            "requirements.txt 내용:",
            height=400,
            placeholder="pandas==2.0.0\nnumpy>=1.24.0\n...",
            value="""pandas==2.0.0
numpy>=1.24.0
scikit-learn==1.0.0
requests==2.25.0
sqlite3"""
        )
    
    # 분석 버튼
    if st.button("🔍 보안 분석 시작", type="primary", use_container_width=True):
        if not code_input:
            st.warning("코드를 입력해주세요.")
            return
        
        # 진행 상태 표시
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # 1단계: SBOM 생성
        status_text.text("📊 SBOM 생성 중...")
        progress_bar.progress(20)
        
        sbom_result = analyzer.analyze(code_input, req_input)
        
        if not sbom_result.get("success"):
            st.error(f"SBOM 생성 실패: {sbom_result.get('error')}")
            return
        
        # 2단계: 취약점 검사
        if analysis_mode in ["🚀 빠른 분석 (SBOM + OSV)", "⚡ 전체 분석 (All)"]:
            status_text.text("🔍 OSV 취약점 검사 중...")
            progress_bar.progress(40)
            sbom_result = check_vulnerabilities(sbom_result["packages"], sbom_result)
        
        # 3단계: LLM 분석
        llm_analysis = None
        if analysis_mode in ["🤖 AI 심층 분석 (LLM + RAG)", "⚡ 전체 분석 (All)"] and llm_analyzer:
            status_text.text("🤖 AI 보안 분석 중...")
            progress_bar.progress(60)
            llm_analysis = llm_analyzer.analyze_code_security(code_input, sbom_result)
        
        progress_bar.progress(100)
        status_text.text("✅ 분석 완료!")
        time.sleep(0.5)
        progress_bar.empty()
        status_text.empty()
        
        # 결과 표시
        display_enhanced_results(sbom_result, llm_analysis, formatter, analysis_mode)

def display_enhanced_results(sbom_result, llm_analysis, formatter, analysis_mode):
    """향상된 분석 결과 표시"""
    
    st.success("✅ 보안 분석 완료!")
    
    # 탭으로 결과 구성
    tabs = ["📊 SBOM", "🚨 취약점", "🤖 AI 분석", "📋 보고서", "💾 다운로드"]
    tab1, tab2, tab3, tab4, tab5 = st.tabs(tabs)
    
    with tab1:
        display_sbom_info(sbom_result)
    
    with tab2:
        display_vulnerabilities(sbom_result, llm_analysis)
    
    with tab3:
        if llm_analysis and llm_analysis.get("success"):
            display_ai_analysis(llm_analysis["analysis"])
        else:
            st.info("AI 분석을 실행하려면 'AI 심층 분석' 또는 '전체 분석' 모드를 선택하세요.")
    
    with tab4:
        generate_security_report(sbom_result, llm_analysis)
    
    with tab5:
        provide_download_options(sbom_result, llm_analysis, formatter)

def display_sbom_info(result):
    """SBOM 정보 표시"""
    st.subheader("📦 발견된 패키지")
    
    # 요약 메트릭
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("전체 패키지", result["summary"]["external_packages"])
    with col2:
        st.metric("버전 확인", result["summary"]["with_version"])
    with col3:
        st.metric("버전 미확인", result["summary"]["without_version"])
    with col4:
        vuln_count = result["summary"].get("total_vulnerabilities", 0)
        st.metric("취약점", vuln_count, delta_color="inverse" if vuln_count > 0 else "off")
    
    # 패키지 테이블
    if result["packages"]:
        df_data = []
        for pkg in result["packages"]:
            df_data.append({
                "패키지": pkg["name"],
                "설치명": pkg["install_name"],
                "버전": pkg.get("version", "미지정"),
                "취약점": len(pkg.get("vulnerabilities", [])),
                "상태": pkg["status"]
            })
        
        df = pd.DataFrame(df_data)
        st.dataframe(df, use_container_width=True, hide_index=True)

def display_vulnerabilities(sbom_result, llm_analysis):
    """취약점 정보 표시"""
    st.subheader("🚨 보안 취약점 분석")
    
    # OSV 취약점
    osv_vulns = []
    for pkg in sbom_result.get("packages", []):
        for vuln in pkg.get("vulnerabilities", []):
            osv_vulns.append({
                "패키지": pkg["name"],
                "버전": pkg.get("version"),
                "CVE": vuln["id"],
                "심각도": vuln["severity"],
                "설명": vuln["summary"][:100] + "..."
            })
    
    if osv_vulns:
        st.warning(f"⚠️ OSV 데이터베이스에서 {len(osv_vulns)}개 취약점 발견")
        df = pd.DataFrame(osv_vulns)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.success("✅ OSV 데이터베이스에서 알려진 취약점 없음")
    
    # AI 발견 취약점
    if llm_analysis and llm_analysis.get("success"):
        ai_vulns = llm_analysis["analysis"].get("code_vulnerabilities", [])
        if ai_vulns:
            st.warning(f"🤖 AI가 코드에서 {len(ai_vulns)}개 보안 이슈 발견")
            for vuln in ai_vulns:
                with st.expander(f"{vuln.get('type', '취약점')} - {vuln.get('severity', 'MEDIUM')}"):
                    st.write(f"**설명**: {vuln.get('description', '')}")
                    if vuln.get('line_numbers'):
                        st.write(f"**위치**: 라인 {vuln.get('line_numbers')}")
                    if vuln.get('recommendation'):
                        st.info(f"💡 **권장사항**: {vuln.get('recommendation')}")

def display_ai_analysis(analysis):
    """AI 분석 결과 표시"""
    st.subheader("🤖 AI 보안 분석 결과")
    
    # 보안 점수
    score = analysis.get("security_score", 0)
    col1, col2 = st.columns([1, 3])
    
    with col1:
        # 점수에 따른 색상
        if score >= 80:
            color = "🟢"
            status = "안전"
        elif score >= 60:
            color = "🟡"
            status = "주의"
        else:
            color = "🔴"
            status = "위험"
        
        st.metric("보안 점수", f"{score}/100", delta=f"{status} {color}")
    
    with col2:
        # 즉시 조치사항
        if analysis.get("immediate_actions"):
            st.error("⚠️ **즉시 필요한 조치**")
            for action in analysis["immediate_actions"]:
                st.write(f"• {action}")
    
    # 보안 모범 사례
    if analysis.get("best_practices"):
        st.info("💡 **적용 가능한 보안 모범 사례**")
        for practice in analysis["best_practices"]:
            st.write(f"• {practice}")
    
    # 의존성 위험
    if analysis.get("dependency_risks"):
        st.warning("📦 **의존성 관련 위험**")
        for risk in analysis["dependency_risks"]:
            st.write(f"• **{risk.get('package', '')}**: {risk.get('description', '')}")

def generate_security_report(sbom_result, llm_analysis):
    """종합 보안 보고서 생성"""
    st.subheader("📋 종합 보안 보고서")
    
    report = f"""
# 보안 분석 보고서
생성 시간: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}

## 1. SBOM 요약
- 전체 패키지: {sbom_result['summary']['external_packages']}개
- 버전 확인: {sbom_result['summary']['with_version']}개
- 취약점 발견: {sbom_result['summary'].get('total_vulnerabilities', 0)}개

## 2. 주요 발견사항
"""
    
    if llm_analysis and llm_analysis.get("success"):
        analysis = llm_analysis["analysis"]
        report += f"""
### 보안 점수: {analysis.get('security_score', 'N/A')}/100

### 코드 취약점
"""
        for vuln in analysis.get("code_vulnerabilities", []):
            report += f"- **{vuln.get('type')}** ({vuln.get('severity')}): {vuln.get('description')}\n"
        
        report += "\n### 즉시 필요한 조치\n"
        for action in analysis.get("immediate_actions", []):
            report += f"- {action}\n"
    
    st.text_area("보고서 내용", report, height=400)
    
    st.download_button(
        "📥 보고서 다운로드",
        data=report,
        file_name=f"security_report_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown"
    )

def provide_download_options(sbom_result, llm_analysis, formatter):
    """다운로드 옵션 제공"""
    st.subheader("💾 결과 다운로드")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        # SBOM JSON
        st.download_button(
            "📥 SBOM (JSON)",
            data=json.dumps(sbom_result, indent=2),
            file_name="sbom.json",
            mime="application/json"
        )
    
    with col2:
        # SPDX 형식
        spdx_data = formatter.format_sbom(sbom_result["packages"], "SPDX")
        st.download_button(
            "📥 SBOM (SPDX)",
            data=json.dumps(spdx_data, indent=2),
            file_name="sbom_spdx.json",
            mime="application/json"
        )
    
    with col3:
        # AI 분석 결과
        if llm_analysis and llm_analysis.get("success"):
            st.download_button(
                "📥 AI 분석 결과",
                data=json.dumps(llm_analysis["analysis"], indent=2),
                file_name="ai_analysis.json",
                mime="application/json"
            )