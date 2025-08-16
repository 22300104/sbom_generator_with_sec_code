# ui/integrated_code_analysis_tab.py
"""
통합된 코드 분석 탭
- 파일 선택 기능
- 개선된 AI 분석
- RAG 기반 근거 제시
"""
import streamlit as st
import json
import time
from pathlib import Path
from typing import Dict, List, Optional

# 컴포넌트 임포트
from ui.file_selector import FileSelector
from core.improved_llm_analyzer import ImprovedSecurityAnalyzer
from core.analyzer import SBOMAnalyzer
from core.formatter import SBOMFormatter
from core.project_downloader import ProjectDownloader


def render_code_analysis_tab():
    """메인 코드 분석 탭"""
    st.header("🔍 보안 분석")
    
    # 입력 방법 선택
    input_method = st.radio(
        "입력 방법:",
        ["📝 직접 입력", "🔗 GitHub", "📦 파일 업로드"],
        horizontal=True
    )
    
    if input_method == "📝 직접 입력":
        handle_direct_input()
    elif input_method == "🔗 GitHub":
        handle_github_with_selector()
    elif input_method == "📦 파일 업로드":
        handle_file_upload_with_selector()


def handle_direct_input():
    """직접 코드 입력"""
    col1, col2 = st.columns([2, 1])
    
    with col1:
        code = st.text_area(
            "Python 코드:",
            height=400,
            placeholder="분석할 Python 코드를 입력하세요..."
        )
    
    with col2:
        requirements = st.text_area(
            "requirements.txt (선택):",
            height=400,
            placeholder="pandas==2.0.0\nnumpy>=1.24.0"
        )
    
    if code:
        st.divider()
        
        # 분석 옵션
        col1, col2, col3 = st.columns(3)
        
        with col1:
            analysis_mode = st.selectbox(
                "분석 모드:",
                ["🚀 빠른 분석", "🤖 AI 보안 분석", "🔥 전체 분석"]
            )
        
        with col2:
            use_claude = st.checkbox("Claude 사용", value=True)
        
        with col3:
            include_sbom = st.checkbox("SBOM 생성", value=True)
        
        # 분석 실행
        if st.button("🔍 분석 시작", type="primary", use_container_width=True):
            with st.spinner("분석 중..."):
                run_analysis(
                    code=code,
                    requirements=requirements,
                    mode=analysis_mode,
                    use_claude=use_claude,
                    include_sbom=include_sbom
                )


def handle_github_with_selector():
    """GitHub 프로젝트 분석 - 파일 선택 기능 포함"""
    st.subheader("GitHub 저장소 분석")
    
    # GitHub URL 입력
    col1, col2 = st.columns([3, 1])
    
    with col1:
        github_url = st.text_input(
            "저장소 URL:",
            placeholder="https://github.com/owner/repository"
        )
    
    with col2:
        st.write("")
        st.write("")
        download_btn = st.button("📥 다운로드", type="primary")
    
    # 예제 저장소
    with st.expander("📌 예제"):
        examples = {
            "Flask": "https://github.com/pallets/flask",
            "FastAPI": "https://github.com/tiangolo/fastapi",
            "Django": "https://github.com/django/django",
            "Requests": "https://github.com/psf/requests"
        }
        
        for name, url in examples.items():
            if st.button(name, key=f"ex_{name}"):
                st.session_state.github_url = url
                st.rerun()
    
    # URL 세션에서 가져오기
    if 'github_url' in st.session_state:
        github_url = st.session_state.github_url
        del st.session_state.github_url
        download_btn = True
    
    # 다운로드 및 파일 선택
    if download_btn and github_url:
        downloader = ProjectDownloader()
        
        with st.spinner("다운로드 중..."):
            success, message, project_path = downloader.download_github(github_url)
        
        if success:
            st.success(message)
            
            # 파일 선택 UI
            st.divider()
            selector = FileSelector(Path(project_path))
            selected_files = selector.render()
            
            if selected_files:
                # 분석 옵션
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    analysis_mode = st.selectbox(
                        "분석 모드:",
                        ["🚀 빠른 분석", "🤖 AI 보안 분석", "🔥 전체 분석"]
                    )
                
                with col2:
                    use_claude = st.checkbox("Claude 사용", value=True)
                
                with col3:
                    include_sbom = st.checkbox("SBOM 생성", value=True)
                
                # 분석 실행
                if st.button("🔍 선택 파일 분석", type="primary", use_container_width=True):
                    # 선택된 파일 코드 가져오기
                    code, file_list = selector.get_selected_code()
                    requirements = selector.get_requirements()
                    
                    with st.spinner(f"{len(file_list)}개 파일 분석 중..."):
                        run_analysis(
                            code=code,
                            requirements=requirements,
                            file_list=file_list,
                            mode=analysis_mode,
                            use_claude=use_claude,
                            include_sbom=include_sbom,
                            project_name=github_url.split('/')[-1]
                        )
            
            # 정리
            downloader.cleanup()
        else:
            st.error(message)


def handle_file_upload_with_selector():
    """파일 업로드 - 선택 기능 포함"""
    import tempfile
    import zipfile
    
    uploaded_file = st.file_uploader(
        "파일 선택:",
        type=['zip', 'tar', 'gz', 'py']
    )
    
    if uploaded_file:
        if uploaded_file.name.endswith('.py'):
            # 단일 Python 파일
            code = uploaded_file.read().decode('utf-8')
            
            if st.button("🔍 분석", type="primary"):
                with st.spinner("분석 중..."):
                    run_analysis(code=code)
        else:
            # 압축 파일
            with tempfile.TemporaryDirectory() as tmpdir:
                # 압축 해제
                tmp_path = Path(tmpdir) / uploaded_file.name
                tmp_path.write_bytes(uploaded_file.getbuffer())
                
                if uploaded_file.name.endswith('.zip'):
                    with zipfile.ZipFile(tmp_path, 'r') as zf:
                        zf.extractall(tmpdir)
                
                # 파일 선택 UI
                st.divider()
                selector = FileSelector(Path(tmpdir))
                selected_files = selector.render()
                
                if selected_files:
                    if st.button("🔍 선택 파일 분석", type="primary", use_container_width=True):
                        code, file_list = selector.get_selected_code()
                        requirements = selector.get_requirements()
                        
                        with st.spinner(f"{len(file_list)}개 파일 분석 중..."):
                            run_analysis(
                                code=code,
                                requirements=requirements,
                                file_list=file_list
                            )


def run_analysis(
    code: str,
    requirements: str = "",
    file_list: List[Dict] = None,
    mode: str = "🤖 AI 보안 분석",
    use_claude: bool = True,
    include_sbom: bool = True,
    project_name: str = "Project"
):
    """통합 분석 실행"""
    
    results = {}
    start_time = time.time()
    
    # 진행 상황
    progress = st.progress(0)
    status = st.empty()
    
    try:
        # 1. SBOM 분석
        if include_sbom and mode in ["🚀 빠른 분석", "🔥 전체 분석"]:
            status.text("📦 SBOM 분석 중...")
            progress.progress(30)
            
            analyzer = SBOMAnalyzer()
            sbom_result = analyzer.analyze(code, requirements, scan_environment=False)
            
            if sbom_result.get("success"):
                results['sbom'] = sbom_result
                
                # SBOM 표준 포맷 생성
                formatter = SBOMFormatter()
                results['sbom_formats'] = {
                    'spdx': formatter.to_spdx(
                        sbom_result['packages'],
                        {'project_name': project_name}
                    ),
                    'cyclonedx': formatter.to_cyclonedx(
                        sbom_result['packages'],
                        {'project_name': project_name}
                    )
                }
            
            progress.progress(50)
        
        # 2. AI 보안 분석
        if mode in ["🤖 AI 보안 분석", "🔥 전체 분석"]:
            status.text("🤖 AI 보안 분석 중...")
            progress.progress(70)
            
            # 개선된 분석기 사용
            analyzer = ImprovedSecurityAnalyzer(use_claude=use_claude)
            ai_result = analyzer.analyze_security(code, file_list)
            
            results['ai_analysis'] = ai_result
            
            progress.progress(90)
        
        progress.progress(100)
        status.text("✅ 분석 완료!")
        
    except Exception as e:
        st.error(f"❌ 분석 오류: {e}")
    finally:
        progress.empty()
        status.empty()
    
    # 분석 시간
    results['analysis_time'] = time.time() - start_time
    
    # 결과 표시
    display_results(results)


def display_results(results: Dict):
    """분석 결과 표시"""
    
    # 분석 시간
    st.success(f"✅ 분석 완료 ({results['analysis_time']:.1f}초)")
    
    # 탭으로 결과 구성
    tabs = []
    
    if 'ai_analysis' in results:
        tabs.append("🤖 보안 분석")
    if 'sbom' in results:
        tabs.append("📦 SBOM")
    tabs.append("💾 다운로드")
    
    tab_objects = st.tabs(tabs)
    tab_idx = 0
    
    # AI 분석 탭
    if 'ai_analysis' in results:
        with tab_objects[tab_idx]:
            display_ai_results(results['ai_analysis'])
        tab_idx += 1
    
    # SBOM 탭
    if 'sbom' in results:
        with tab_objects[tab_idx]:
            display_sbom_results(results['sbom'])
        tab_idx += 1
    
    # 다운로드 탭
    with tab_objects[tab_idx]:
        display_download_options(results)


def display_ai_results(ai_result: Dict):
    """AI 분석 결과 표시"""
    if not ai_result.get('success'):
        st.error("분석 실패")
        return
    
    # 메트릭
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("보안 점수", f"{ai_result['security_score']}/100")
    
    with col2:
        vulns = len(ai_result['vulnerabilities'])
        st.metric("발견된 취약점", vulns)
    
    with col3:
        st.metric("분석 엔진", ai_result.get('analyzed_by', 'AI'))
    
    # 요약
    st.info(ai_result['summary'])
    
    # 취약점 상세
    if ai_result['vulnerabilities']:
        st.subheader("🔍 발견된 취약점")
        
        for vuln in ai_result['vulnerabilities']:
            severity_icon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }.get(vuln.get('severity', 'MEDIUM'), '⚪')
            
            confidence = vuln.get('confidence', 'MEDIUM')
            confidence_badge = {
                'HIGH': '⭐⭐⭐',
                'MEDIUM': '⭐⭐',
                'LOW': '⭐'
            }.get(confidence, '⭐⭐')
            
            # 위치 정보
            location = vuln.get('location', {})
            title = f"{severity_icon} {vuln['type']}"
            if location.get('file'):
                title += f" - {location['file']}"
            if location.get('line'):
                title += f" (라인 {location['line']})"
            
            with st.expander(title):
                # 설명
                st.write("**설명:**", vuln['description'])
                
                # 데이터 흐름
                if vuln.get('data_flow'):
                    st.info(f"**데이터 흐름:** {vuln['data_flow']}")
                
                # 공격 시나리오
                if vuln.get('exploit_scenario'):
                    st.warning(f"**공격 시나리오:** {vuln['exploit_scenario']}")
                
                # RAG 근거
                if vuln.get('evidence'):
                    evidence = vuln['evidence']
                    st.success(f"**📚 {evidence['source']}:**")
                    if evidence.get('page'):
                        st.caption(f"페이지 {evidence['page']}")
                    st.caption(evidence['content'][:300] + "...")
                
                # 권장사항
                if vuln.get('recommendation'):
                    st.success(f"**개선 방법:** {vuln['recommendation']}")
                
                # 확신도
                st.caption(f"확신도: {confidence_badge} {confidence}")
    else:
        st.success("✅ 취약점이 발견되지 않았습니다!")


def display_sbom_results(sbom: Dict):
    """SBOM 결과 표시"""
    import pandas as pd
    
    st.subheader("📦 Software Bill of Materials")
    
    # 요약
    summary = sbom.get('summary', {})
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("외부 패키지", summary.get('external_packages', 0))
    with col2:
        st.metric("버전 확인", summary.get('with_version', 0))
    with col3:
        st.metric("종속성", summary.get('total_dependencies', 0))
    
    # 패키지 목록
    if sbom.get('packages'):
        df_data = []
        for pkg in sbom['packages']:
            df_data.append({
                "패키지": pkg['name'],
                "설치명": pkg.get('install_name', pkg['name']),
                "버전": pkg.get('version', '미확인'),
                "상태": pkg.get('status', ''),
                "종속성": pkg.get('dependencies_count', 0)
            })
        
        df = pd.DataFrame(df_data)
        st.dataframe(df, use_container_width=True, hide_index=True)


def display_download_options(results: Dict):
    """다운로드 옵션"""
    st.subheader("💾 다운로드")
    
    # JSON 결과
    json_str = json.dumps(results, indent=2, default=str, ensure_ascii=False)
    st.download_button(
        "📥 전체 결과 (JSON)",
        data=json_str,
        file_name="security_analysis.json",
        mime="application/json"
    )
    
    # SBOM 형식
    if results.get('sbom_formats'):
        col1, col2 = st.columns(2)
        
        with col1:
            if results['sbom_formats'].get('spdx'):
                spdx_json = json.dumps(
                    results['sbom_formats']['spdx'],
                    indent=2,
                    ensure_ascii=False
                )
                st.download_button(
                    "📥 SPDX 2.3",
                    data=spdx_json,
                    file_name="sbom_spdx.json",
                    mime="application/json"
                )
        
        with col2:
            if results['sbom_formats'].get('cyclonedx'):
                cyclone_json = json.dumps(
                    results['sbom_formats']['cyclonedx'],
                    indent=2,
                    ensure_ascii=False
                )
                st.download_button(
                    "📥 CycloneDX 1.4",
                    data=cyclone_json,
                    file_name="sbom_cyclonedx.json",
                    mime="application/json"
                )
    
    # 보안 보고서
    if 'ai_analysis' in results:
        report = generate_security_report(results)
        st.download_button(
            "📄 보안 보고서 (Markdown)",
            data=report,
            file_name="security_report.md",
            mime="text/markdown"
        )


def generate_security_report(results: Dict) -> str:
    """보안 보고서 생성"""
    report = []
    report.append("# 보안 분석 보고서\n\n")
    report.append(f"생성 시간: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    
    if 'ai_analysis' in results:
        ai = results['ai_analysis']
        report.append("## 보안 분석 결과\n\n")
        report.append(f"- 보안 점수: {ai['security_score']}/100\n")
        report.append(f"- 발견된 취약점: {len(ai['vulnerabilities'])}개\n")
        report.append(f"- 분석 엔진: {ai.get('analyzed_by', 'AI')}\n\n")
        
        if ai['vulnerabilities']:
            report.append("### 취약점 상세\n\n")
            
            for i, vuln in enumerate(ai['vulnerabilities'], 1):
                report.append(f"#### {i}. {vuln['type']}\n\n")
                report.append(f"- **심각도**: {vuln['severity']}\n")
                report.append(f"- **확신도**: {vuln.get('confidence', 'MEDIUM')}\n")
                
                location = vuln.get('location', {})
                if location:
                    report.append(f"- **위치**: {location.get('file', 'unknown')}")
                    if location.get('line'):
                        report.append(f" (라인 {location['line']})")
                    report.append("\n")
                
                report.append(f"- **설명**: {vuln['description']}\n")
                
                if vuln.get('data_flow'):
                    report.append(f"- **데이터 흐름**: {vuln['data_flow']}\n")
                
                if vuln.get('recommendation'):
                    report.append(f"- **권장사항**: {vuln['recommendation']}\n")
                
                if vuln.get('evidence'):
                    evidence = vuln['evidence']
                    report.append(f"- **근거**: {evidence['source']}")
                    if evidence.get('page'):
                        report.append(f" (페이지 {evidence['page']})")
                    report.append("\n")
                
                report.append("\n")
    
    return ''.join(report)