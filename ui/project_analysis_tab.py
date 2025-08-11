"""
프로젝트 분석 탭 - GitHub/압축파일 분석
"""
import streamlit as st
import os
import time
import json
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional

from core.project_downloader import ProjectDownloader
from core.analyzer import SBOMAnalyzer
from core.llm_analyzer import LLMSecurityAnalyzer
from security.vulnerability import check_vulnerabilities_enhanced


def render_project_analysis_tab():
    """프로젝트 분석 탭 렌더링"""
    st.header("📁 프로젝트 전체 분석")
    
    # 서브 탭 추가
    sub_tab1, sub_tab2, sub_tab3 = st.tabs(["🔍 새 분석", "📊 비교 분석", "📈 히스토리"])
    
    with sub_tab1:
        render_new_analysis()
    
    with sub_tab2:
        render_comparison_analysis()
    
    with sub_tab3:
        render_analysis_history()


def render_new_analysis():
    """새 프로젝트 분석"""
    st.markdown("""
    GitHub 저장소나 압축 파일을 업로드하여 프로젝트 전체를 분석합니다.
    - **GitHub**: 공개 저장소 URL 입력
    - **압축파일**: ZIP, TAR, 7Z 등 지원
    """)
    
    # 입력 방법 선택
    input_method = st.radio(
        "입력 방법 선택",
        ["🔗 GitHub URL", "📦 압축파일 업로드"],
        horizontal=True
    )
    
    downloader = None
    project_path = None
    
    if input_method == "🔗 GitHub URL":
        project_path = handle_github_input()
    else:
        project_path = handle_file_upload()
    
    # 프로젝트 경로가 있으면 분석 실행
    if project_path:
        analyze_project(project_path)


def handle_github_input() -> Optional[Path]:
    """GitHub URL 입력 처리"""
    col1, col2 = st.columns([3, 1])
    
    with col1:
        github_url = st.text_input(
            "GitHub 저장소 URL",
            placeholder="https://github.com/owner/repository",
            help="예: https://github.com/streamlit/streamlit"
        )
    
    with col2:
        st.write("")  # 여백
        st.write("")  # 여백
        download_btn = st.button("📥 다운로드", type="primary", use_container_width=True)
    
    # 예제 URL들
    with st.expander("📌 예제 저장소"):
        examples = {
            "간단한 Flask 앱": "https://github.com/pallets/flask/tree/main/examples/tutorial",
            "Django 프로젝트": "https://github.com/django/django",
            "FastAPI 예제": "https://github.com/tiangolo/fastapi",
            "보안 취약점 데모": "https://github.com/OWASP/Python-Security",
        }
        
        for name, url in examples.items():
            if st.button(f"{name}", key=f"example_{name}"):
                st.session_state.github_url_input = url
                st.rerun()
    
    # 세션에서 URL 가져오기
    if 'github_url_input' in st.session_state:
        github_url = st.session_state.github_url_input
        del st.session_state.github_url_input
        download_btn = True
    
    if download_btn and github_url:
        downloader = ProjectDownloader()
        
        with st.spinner("🔄 GitHub 저장소 다운로드 중..."):
            success, message, project_path = downloader.download_github(github_url)
        
        if success:
            st.success(f"✅ {message}")
            
            # 프로젝트 정보 표시
            project_info = downloader._analyze_project_structure(Path(project_path))
            
            with st.expander("📊 프로젝트 구조", expanded=True):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Python 파일", f"{project_info['file_count']}개")
                with col2:
                    st.metric("총 라인 수", f"{project_info['total_lines']:,}")
                with col3:
                    if project_info['frameworks']:
                        st.metric("프레임워크", ", ".join(project_info['frameworks']))
                
                # 파일 목록 (상위 10개)
                if project_info['python_files']:
                    st.write("**주요 Python 파일:**")
                    for file in project_info['python_files'][:10]:
                        st.caption(f"📄 {file}")
                    
                    if len(project_info['python_files']) > 10:
                        st.caption(f"... 외 {len(project_info['python_files'])-10}개 파일")
            
            # 세션에 저장
            st.session_state.current_project_path = project_path
            st.session_state.current_project_info = project_info
            
            return Path(project_path)
        else:
            st.error(f"❌ {message}")
            return None
    
    # 이전에 다운로드한 프로젝트가 있으면 사용
    if 'current_project_path' in st.session_state:
        return Path(st.session_state.current_project_path)
    
    return None


def handle_file_upload() -> Optional[Path]:
    """압축파일 업로드 처리"""
    uploaded_file = st.file_uploader(
        "압축파일 선택",
        type=['zip', 'tar', 'gz', 'bz2', '7z', 'rar'],
        help="Python 프로젝트가 포함된 압축파일을 업로드하세요"
    )
    
    if uploaded_file:
        # 임시 파일로 저장
        import tempfile
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded_file.name).suffix) as tmp_file:
            tmp_file.write(uploaded_file.getbuffer())
            tmp_path = tmp_file.name
        
        downloader = ProjectDownloader()
        
        with st.spinner("📦 압축파일 추출 중..."):
            success, message, project_path = downloader.extract_archive(tmp_path)
        
        # 임시 파일 삭제
        try:
            os.unlink(tmp_path)
        except:
            pass
        
        if success:
            st.success(f"✅ {message}")
            
            # 프로젝트 정보 표시
            project_info = downloader._analyze_project_structure(Path(project_path))
            
            with st.expander("📊 프로젝트 구조", expanded=True):
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Python 파일", f"{project_info['file_count']}개")
                with col2:
                    st.metric("총 라인 수", f"{project_info['total_lines']:,}")
                
                if project_info['frameworks']:
                    st.write(f"**프레임워크:** {', '.join(project_info['frameworks'])}")
            
            # 세션에 저장
            st.session_state.current_project_path = project_path
            st.session_state.current_project_info = project_info
            
            return Path(project_path)
        else:
            st.error(f"❌ {message}")
            return None
    
    # 이전에 업로드한 프로젝트가 있으면 사용
    if 'current_project_path' in st.session_state:
        return Path(st.session_state.current_project_path)
    
    return None


def render_comparison_analysis():
    """프로젝트 비교 분석"""
    from core.project_comparator import ProjectComparator
    from core.analysis_history import AnalysisHistory
    
    st.subheader("📊 프로젝트 비교 분석")
    st.markdown("여러 프로젝트의 보안 수준을 비교합니다.")
    
    # 세션에서 분석된 프로젝트 가져오기
    if 'project_comparator' not in st.session_state:
        st.session_state.project_comparator = ProjectComparator()
    
    comparator = st.session_state.project_comparator
    
    # 비교할 프로젝트 선택
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**프로젝트 추가**")
        
        # 최근 분석 결과에서 선택
        if 'recent_analyses' in st.session_state:
            project_names = list(st.session_state.recent_analyses.keys())
            selected_project = st.selectbox(
                "분석된 프로젝트 선택",
                ["선택하세요"] + project_names
            )
            
            if selected_project != "선택하세요":
                if st.button("➕ 비교 목록에 추가"):
                    results = st.session_state.recent_analyses[selected_project]
                    project_id = comparator.add_project(selected_project, results)
                    st.success(f"✅ {selected_project} 추가됨")
                    st.rerun()
    
    with col2:
        st.write("**비교 목록**")
        
        if comparator.projects:
            for pid, project in comparator.projects.items():
                st.write(f"• {project['name']}")
                st.caption(f"  보안 점수: {project['metrics']['security_score']}/100")
        else:
            st.info("비교할 프로젝트를 추가하세요")
    
    # 비교 실행
    if len(comparator.projects) >= 2:
        if st.button("🔍 비교 분석 실행", type="primary", use_container_width=True):
            with st.spinner("비교 분석 중..."):
                comparison = comparator.compare_projects()
            
            # 결과 표시
            st.divider()
            st.subheader("📊 비교 결과")
            
            # 전체 순위
            st.write("### 🏆 전체 순위")
            rankings = comparison['rankings']['overall']
            for i, item in enumerate(rankings, 1):
                medal = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f"{i}."
                st.write(f"{medal} **{item['name']}** (점수: {item['score']})")
            
            # 상세 메트릭
            tab1, tab2, tab3 = st.tabs(["보안 점수", "취약점", "의존성"])
            
            with tab1:
                display_score_comparison(comparison)
            
            with tab2:
                display_vulnerability_comparison(comparison)
            
            with tab3:
                display_dependency_comparison(comparison)
            
            # 인사이트
            st.write("### 💡 주요 발견사항")
            for insight in comparison['insights']:
                st.write(f"• {insight}")
            
            # 권장사항
            st.write("### 📋 프로젝트별 권장사항")
            for rec in comparison['recommendations']:
                with st.expander(f"{rec['name']}"):
                    if rec['priority_actions']:
                        st.write("**우선 조치사항:**")
                        for action in rec['priority_actions']:
                            st.write(f"• {action}")
                    
                    if rec['improvements']:
                        st.write("**개선사항:**")
                        for improvement in rec['improvements']:
                            st.write(f"• {improvement}")
            
            # 보고서 다운로드
            report = comparator.generate_comparison_report()
            st.download_button(
                "📥 비교 보고서 다운로드",
                data=report,
                file_name=f"comparison_report_{int(time.time())}.md",
                mime="text/markdown"
            )
    
    # 초기화 버튼
    if comparator.projects:
        if st.button("🔄 비교 목록 초기화"):
            st.session_state.project_comparator = ProjectComparator()
            st.rerun()


def render_analysis_history():
    """분석 히스토리"""
    from core.analysis_history import AnalysisHistory
    
    st.subheader("📈 분석 히스토리")
    
    # 히스토리 관리자 초기화
    if 'history_manager' not in st.session_state:
        st.session_state.history_manager = AnalysisHistory()
    
    history = st.session_state.history_manager
    
    # 통계 표시
    stats = history.get_statistics()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("총 프로젝트", stats.get('total_projects', 0) or 0)
    with col2:
        st.metric("총 분석", stats.get('total_analyses', 0) or 0)
    with col3:
        avg_score = stats.get('avg_security_score', 0)
        if avg_score is not None:
            st.metric("평균 보안 점수", f"{avg_score:.1f}")
        else:
            st.metric("평균 보안 점수", "N/A")
    with col4:
        st.metric("총 취약점", stats.get('total_vulnerabilities', 0) or 0)
    
    # 최근 분석 목록
    st.write("### 📅 최근 분석")
    
    days = st.slider("기간 (일)", 1, 30, 7)
    recent = history.get_recent_analyses(days=days)
    
    if recent:
        df_data = []
        for analysis in recent:
            df_data.append({
                "프로젝트": analysis['project_name'],
                "타입": analysis['project_type'],
                "분석일": analysis['analyzed_at'],
                "보안점수": f"{analysis['security_score']}/100",
                "취약점": analysis['vulnerability_count'],
                "치명적": analysis['critical_count']
            })
        
        df = pd.DataFrame(df_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        # 상세 보기
        selected_project = st.selectbox(
            "프로젝트 선택 (상세 보기)",
            ["선택하세요"] + list(set(a['project_name'] for a in recent))
        )
        
        if selected_project != "선택하세요":
            project_history = history.get_project_history(selected_project)
            
            if project_history:
                st.write(f"### 📊 {selected_project} 히스토리")
                
                # 추세 차트
                chart_data = []
                for h in project_history:
                    chart_data.append({
                        "날짜": h['analyzed_at'],
                        "보안점수": h['security_score'],
                        "취약점수": h['vulnerability_count']
                    })
                
                if chart_data:
                    df_chart = pd.DataFrame(chart_data)
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.line_chart(df_chart.set_index('날짜')['보안점수'])
                    with col2:
                        st.line_chart(df_chart.set_index('날짜')['취약점수'])
                
                # 버전 간 비교
                if len(project_history) >= 2:
                    st.write("### 🔄 버전 비교")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        version1 = st.selectbox(
                            "이전 버전",
                            [(h['id'], h['analyzed_at']) for h in project_history[1:]],
                            format_func=lambda x: x[1]
                        )
                    
                    with col2:
                        version2 = st.selectbox(
                            "최신 버전",
                            [(h['id'], h['analyzed_at']) for h in project_history[:1]],
                            format_func=lambda x: x[1]
                        )
                    
                    if st.button("비교하기"):
                        comparison = history.compare_analyses(version1[0], version2[0])
                        
                        if not comparison.get('error'):
                            st.write("**변경사항:**")
                            
                            changes = comparison['changes']
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.metric(
                                    "보안 점수 변화",
                                    f"{changes['security_score']:+d}",
                                    delta_color="normal"
                                )
                                st.metric(
                                    "취약점 변화",
                                    f"{changes['vulnerability_count']:+d}",
                                    delta_color="inverse"
                                )
                            
                            with col2:
                                st.metric(
                                    "치명적 취약점 변화",
                                    f"{changes['critical_count']:+d}",
                                    delta_color="inverse"
                                )
                                st.metric(
                                    "패키지 수 변화",
                                    f"{changes['package_count']:+d}"
                                )
                            
                            if comparison['improvements']:
                                st.success("**개선사항:**")
                                for imp in comparison['improvements']:
                                    st.write(f"• {imp}")
                            
                            if comparison['regressions']:
                                st.warning("**악화사항:**")
                                for reg in comparison['regressions']:
                                    st.write(f"• {reg}")
    else:
        st.info("아직 분석 기록이 없습니다.")
    
    # 데이터 관리
    with st.expander("🗂️ 데이터 관리"):
        st.write("오래된 기록 정리")
        
        cleanup_days = st.number_input("보관 기간 (일)", 30, 365, 90)
        
        if st.button("🗑️ 오래된 기록 삭제"):
            deleted = history.cleanup_old_records(cleanup_days)
            st.success(f"✅ {deleted}개의 오래된 기록이 삭제되었습니다.")


def display_score_comparison(comparison):
    """보안 점수 비교 표시"""
    import pandas as pd
    
    projects = comparison['projects']
    
    df_data = []
    for project in projects:
        df_data.append({
            "프로젝트": project['name'],
            "보안 점수": project['metrics']['security_score']
        })
    
    df = pd.DataFrame(df_data)
    st.bar_chart(df.set_index('프로젝트'))


def display_vulnerability_comparison(comparison):
    """취약점 비교 표시"""
    projects = comparison['projects']
    
    # 심각도별 비교
    severity_data = []
    for project in projects:
        metrics = project['metrics']['vulnerabilities']
        severity_data.append({
            "프로젝트": project['name'],
            "CRITICAL": metrics['critical'],
            "HIGH": metrics['high'],
            "MEDIUM": metrics['medium'],
            "LOW": metrics['low']
        })
    
    df = pd.DataFrame(severity_data)
    st.dataframe(df, use_container_width=True, hide_index=True)
    
    # 차트
    chart_df = df.set_index('프로젝트')
    st.bar_chart(chart_df)


def display_dependency_comparison(comparison):
    """의존성 비교 표시"""
    projects = comparison['projects']
    
    df_data = []
    for project in projects:
        deps = project['metrics']['dependencies']
        health = project.get('dependency_health', 0)
        health_str = f"{health:.1f}%" if health is not None else "N/A"
        
        df_data.append({
            "프로젝트": project['name'],
            "총 패키지": deps['total'],
            "취약한 패키지": deps['vulnerable'],
            "건강도": health_str
        })
    
    df = pd.DataFrame(df_data)
    st.dataframe(df, use_container_width=True, hide_index=True)


def analyze_project(project_path: Path):
    """프로젝트 전체 분석"""
    
    st.divider()
    st.subheader("🔍 분석 옵션")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        analyze_code = st.checkbox("💻 코드 보안 분석", value=True)
        max_files = st.number_input("최대 분석 파일 수", 10, 200, 50)
    
    with col2:
        analyze_deps = st.checkbox("📦 의존성 분석", value=True)
        check_vulns = st.checkbox("🛡️ 취약점 검사", value=True)
    
    with col3:
        analyze_structure = st.checkbox("🏗️ 구조 분석", value=True)
        generate_report = st.checkbox("📄 보고서 생성", value=True)
    
    if st.button("🚀 전체 분석 시작", type="primary", use_container_width=True):
        
        # 프로젝트 데이터 수집
        downloader = ProjectDownloader()
        
        with st.spinner(f"📂 프로젝트 파일 분석 중... (최대 {max_files}개)"):
            project_data = downloader.analyze_project_files(project_path, max_files=max_files)
        
        st.info(f"""
        📊 **분석 대상:**
        - Python 파일: {project_data['statistics']['total_files']}개
        - 총 코드: {project_data['statistics']['total_lines']:,}줄
        - 스킵된 파일: {project_data['statistics']['skipped_files']}개
        """)
        
        results = {}
        
        # 1. 의존성 분석
        if analyze_deps:
            with st.spinner("📦 의존성 분석 중..."):
                results['dependencies'] = analyze_dependencies(
                    project_data['combined_code'],
                    project_data['combined_requirements']
                )
        
        # 2. 코드 보안 분석
        if analyze_code:
            with st.spinner("🔒 코드 보안 분석 중... (시간이 걸릴 수 있습니다)"):
                results['security'] = analyze_security(
                    project_data['combined_code'],
                    project_data['files']
                )
        
        # 3. 취약점 검사
        if check_vulns and 'dependencies' in results:
            with st.spinner("🛡️ 알려진 취약점 검사 중..."):
                results['vulnerabilities'] = check_known_vulnerabilities(
                    results['dependencies']
                )
        
        # 4. 구조 분석
        if analyze_structure:
            results['structure'] = analyze_project_structure(
                project_path,
                project_data['files']
            )
        
        # 결과 표시
        display_analysis_results(results, project_data)
        
        # 5. 보고서 생성
        if generate_report:
            report = generate_analysis_report(results, project_data)
            
            st.download_button(
                "📥 분석 보고서 다운로드",
                data=report,
                file_name=f"security_analysis_{int(time.time())}.md",
                mime="text/markdown"
            )
        
        # 결과를 세션에 저장
        st.session_state.project_analysis_results = results
        
        # 히스토리에 저장
        if 'history_manager' not in st.session_state:
            from core.analysis_history import AnalysisHistory
            st.session_state.history_manager = AnalysisHistory()
        
        # 프로젝트 이름 결정
        project_name = project_path.name
        project_type = 'upload'  # 또는 'github' 등
        
        # 히스토리 저장
        history = st.session_state.history_manager
        analysis_id = history.save_analysis(
            project_name=project_name,
            analysis_results=results,
            project_type=project_type
        )
        
        st.success(f"✅ 분석 결과가 히스토리에 저장되었습니다 (ID: {analysis_id})")
        
        # 최근 분석 결과 세션에 저장 (비교용)
        if 'recent_analyses' not in st.session_state:
            st.session_state.recent_analyses = {}
        st.session_state.recent_analyses[project_name] = results


def analyze_dependencies(code: str, requirements: str) -> Dict:
    """의존성 분석"""
    analyzer = SBOMAnalyzer()
    
    # 코드와 requirements 분석
    result = analyzer.analyze(code, requirements, scan_environment=False)
    
    if result.get('success'):
        return {
            'packages': result.get('packages', []),
            'summary': result.get('summary', {}),
            'indirect_dependencies': result.get('indirect_dependencies', [])
        }
    
    return {}


def analyze_security(code: str, files: List[Dict]) -> Dict:
    """코드 보안 분석"""
    
    # LLM 분석기 체크
    if not os.getenv("OPENAI_API_KEY"):
        return {
            'error': 'OpenAI API 키가 설정되지 않았습니다.',
            'vulnerabilities': []
        }
    
    try:
        llm_analyzer = LLMSecurityAnalyzer()
        
        # 파일이 너무 많으면 주요 파일만 분석
        if len(code) > 50000:  # 50KB 이상이면
            # 주요 파일만 선택
            priority_files = ['main.py', 'app.py', 'views.py', 'models.py', 'admin.py']
            filtered_code = []
            
            for line in code.split('\n'):
                if line.startswith('# ===== File:'):
                    current_file = line
                    # 우선순위 파일인지 확인
                    if any(pf in line for pf in priority_files):
                        filtered_code.append(current_file)
                        include_current = True
                    else:
                        include_current = False
                elif include_current:
                    filtered_code.append(line)
            
            code = '\n'.join(filtered_code[:30000])  # 30KB로 제한
        
        # 보안 분석 실행
        result = llm_analyzer.analyze_code_security(code)
        
        if result.get('success'):
            return result['analysis']
        else:
            return {'error': '분석 실패', 'vulnerabilities': []}
            
    except Exception as e:
        return {'error': str(e), 'vulnerabilities': []}


def check_known_vulnerabilities(dependencies: Dict) -> Dict:
    """알려진 취약점 검사"""
    
    if not dependencies or not dependencies.get('packages'):
        return {}
    
    from security.vulnerability import VulnerabilityChecker
    
    checker = VulnerabilityChecker()
    packages = dependencies.get('packages', [])
    indirect = dependencies.get('indirect_dependencies', [])
    
    # 모든 패키지 검사
    vuln_results = checker.check_all_dependencies(packages, indirect, max_workers=3)
    
    return vuln_results


def analyze_project_structure(project_path: Path, files: List[Dict]) -> Dict:
    """프로젝트 구조 분석"""
    
    structure = {
        'architecture': 'Unknown',
        'patterns': [],
        'recommendations': []
    }
    
    # 파일 이름 패턴으로 아키텍처 추측
    file_names = [f['name'] for f in files]
    file_paths = [f['path'] for f in files]
    
    # MVC/MVT 패턴 체크
    if any('views.py' in f for f in file_names) and any('models.py' in f for f in file_names):
        if any('urls.py' in f for f in file_names):
            structure['architecture'] = 'Django MVT'
        else:
            structure['architecture'] = 'MVC Pattern'
    
    # Flask 패턴
    elif 'app.py' in file_names or 'application.py' in file_names:
        if any('blueprints' in f for f in file_paths):
            structure['architecture'] = 'Flask with Blueprints'
        else:
            structure['architecture'] = 'Flask Application'
    
    # FastAPI
    elif 'main.py' in file_names and any('routers' in f for f in file_paths):
        structure['architecture'] = 'FastAPI'
    
    # 보안 패턴 체크
    security_patterns = []
    
    # 인증/인가 파일 확인
    if any(auth in str(file_paths) for auth in ['auth', 'authentication', 'login', 'permission']):
        security_patterns.append("인증/인가 모듈 발견")
    
    # 미들웨어 확인
    if any('middleware' in f for f in file_paths):
        security_patterns.append("미들웨어 사용")
    
    # 테스트 확인
    if any('test' in f.lower() for f in file_paths):
        security_patterns.append("테스트 코드 포함")
    
    structure['patterns'] = security_patterns
    
    # 권장사항 생성
    recommendations = []
    
    if 'auth' not in str(file_paths).lower():
        recommendations.append("인증 모듈 추가 권장")
    
    if not any('test' in f.lower() for f in file_paths):
        recommendations.append("테스트 코드 작성 권장")
    
    if not any('.env' in f for f in file_names) and not any('config' in f for f in file_paths):
        recommendations.append("환경 설정 분리 권장")
    
    structure['recommendations'] = recommendations
    
    return structure


def display_analysis_results(results: Dict, project_data: Dict):
    """분석 결과 표시"""
    
    st.divider()
    st.subheader("📊 분석 결과")
    
    # 탭으로 결과 구성
    tabs = []
    tab_contents = []
    
    if 'dependencies' in results:
        tabs.append("📦 의존성")
        tab_contents.append(results['dependencies'])
    
    if 'security' in results:
        tabs.append("🔒 보안")
        tab_contents.append(results['security'])
    
    if 'vulnerabilities' in results:
        tabs.append("🛡️ 취약점")
        tab_contents.append(results['vulnerabilities'])
    
    if 'structure' in results:
        tabs.append("🏗️ 구조")
        tab_contents.append(results['structure'])
    
    if tabs:
        tab_objects = st.tabs(tabs)
        
        for i, (tab, content) in enumerate(zip(tab_objects, tab_contents)):
            with tab:
                if "의존성" in tabs[i]:
                    display_dependencies_results(content)
                elif "보안" in tabs[i]:
                    display_security_results(content)
                elif "취약점" in tabs[i]:
                    display_vulnerability_results(content)
                elif "구조" in tabs[i]:
                    display_structure_results(content)


def display_dependencies_results(deps: Dict):
    """의존성 결과 표시"""
    if not deps:
        st.warning("의존성 정보가 없습니다.")
        return
    
    summary = deps.get('summary', {})
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("외부 패키지", summary.get('external_packages', 0))
    with col2:
        st.metric("버전 확인", summary.get('with_version', 0))
    with col3:
        st.metric("간접 종속성", len(deps.get('indirect_dependencies', [])))
    
    # 패키지 목록
    if deps.get('packages'):
        st.write("**주요 패키지:**")
        
        df_data = []
        for pkg in deps['packages'][:20]:
            df_data.append({
                "패키지": pkg['name'],
                "설치명": pkg.get('install_name', pkg['name']),
                "버전": pkg.get('version', '미확인'),
                "상태": pkg.get('status', '')
            })
        
        if df_data:
            df = pd.DataFrame(df_data)
            st.dataframe(df, use_container_width=True, hide_index=True)


def display_security_results(security: Dict):
    """보안 분석 결과 표시"""
    
    if security.get('error'):
        st.error(f"분석 오류: {security['error']}")
        return
    
    vulns = security.get('code_vulnerabilities', [])
    
    if not vulns:
        st.success("✅ 코드 취약점이 발견되지 않았습니다!")
        return
    
    # 요약
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("보안 점수", f"{security.get('security_score', 0)}/100")
    with col2:
        st.metric("발견된 취약점", len(vulns))
    with col3:
        critical = sum(1 for v in vulns if v.get('severity') == 'CRITICAL')
        st.metric("치명적", critical)
    
    # 취약점 목록
    st.write("**발견된 취약점:**")
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        severity_vulns = [v for v in vulns if v.get('severity') == severity]
        
        if severity_vulns:
            color = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}[severity]
            
            with st.expander(f"{color} {severity} ({len(severity_vulns)}개)"):
                for vuln in severity_vulns:
                    st.write(f"**{vuln['type']}**")
                    st.caption(f"라인: {vuln.get('line_numbers', ['?'])[0]}")
                    st.write(vuln.get('description', ''))
                    
                    if vuln.get('vulnerable_code'):
                        st.code(vuln['vulnerable_code'], language='python')


def display_vulnerability_results(vulns: Dict):
    """취약점 검사 결과 표시"""
    
    if not vulns:
        st.info("취약점 정보가 없습니다.")
        return
    
    stats = vulns.get('statistics', {})
    
    # 통계
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("검사한 패키지", stats.get('total_checked', 0))
    with col2:
        st.metric("총 취약점", stats.get('total_vulnerabilities', 0))
    with col3:
        st.metric("CRITICAL", stats.get('critical', 0))
    with col4:
        st.metric("HIGH", stats.get('high', 0))
    
    # 취약한 패키지 목록
    if vulns.get('direct_vulnerabilities'):
        st.write("**취약한 패키지:**")
        
        for pkg_name, data in vulns['direct_vulnerabilities'].items():
            with st.expander(f"📦 {pkg_name} ({len(data['vulnerabilities'])}개)"):
                for vuln in data['vulnerabilities']:
                    st.write(f"**{vuln['id']}** - {vuln['severity']}")
                    st.caption(vuln['summary'])
                    if vuln.get('fixed_version'):
                        st.info(f"수정 버전: {vuln['fixed_version']}")


def display_structure_results(structure: Dict):
    """구조 분석 결과 표시"""
    
    st.write(f"**아키텍처:** {structure.get('architecture', 'Unknown')}")
    
    if structure.get('patterns'):
        st.write("**발견된 패턴:**")
        for pattern in structure['patterns']:
            st.write(f"• {pattern}")
    
    if structure.get('recommendations'):
        st.write("**권장사항:**")
        for rec in structure['recommendations']:
            st.write(f"• {rec}")


def generate_analysis_report(results: Dict, project_data: Dict) -> str:
    """분석 보고서 생성"""
    
    report = []
    report.append("# 프로젝트 보안 분석 보고서\n")
    report.append(f"생성 시간: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    
    # 프로젝트 개요
    report.append("## 프로젝트 개요\n")
    report.append(f"- 분석 파일: {project_data['statistics']['total_files']}개\n")
    report.append(f"- 총 코드: {project_data['statistics']['total_lines']:,}줄\n\n")
    
    # 의존성
    if 'dependencies' in results:
        deps = results['dependencies']
        report.append("## 의존성 분석\n")
        report.append(f"- 외부 패키지: {deps['summary'].get('external_packages', 0)}개\n")
        report.append(f"- 간접 종속성: {len(deps.get('indirect_dependencies', []))}개\n\n")
    
    # 보안 취약점
    if 'security' in results:
        security = results['security']
        report.append("## 코드 보안 분석\n")
        
        if not security.get('error'):
            report.append(f"- 보안 점수: {security.get('security_score', 0)}/100\n")
            report.append(f"- 발견된 취약점: {len(security.get('code_vulnerabilities', []))}개\n\n")
            
            vulns = security.get('code_vulnerabilities', [])
            if vulns:
                report.append("### 취약점 상세\n")
                for vuln in vulns:
                    report.append(f"- **{vuln['type']}** ({vuln.get('severity', 'MEDIUM')})\n")
                    report.append(f"  - 위치: 라인 {vuln.get('line_numbers', ['?'])[0]}\n")
                    report.append(f"  - 설명: {vuln.get('description', '')}\n")
                report.append("\n")
    
    # 알려진 취약점
    if 'vulnerabilities' in results:
        vulns = results['vulnerabilities']
        stats = vulns.get('statistics', {})
        
        report.append("## 알려진 취약점\n")
        report.append(f"- 검사한 패키지: {stats.get('total_checked', 0)}개\n")
        report.append(f"- 발견된 취약점: {stats.get('total_vulnerabilities', 0)}개\n")
        report.append(f"  - CRITICAL: {stats.get('critical', 0)}개\n")
        report.append(f"  - HIGH: {stats.get('high', 0)}개\n\n")
    
    # 구조 분석
    if 'structure' in results:
        structure = results['structure']
        report.append("## 프로젝트 구조\n")
        report.append(f"- 아키텍처: {structure.get('architecture', 'Unknown')}\n\n")
        
        if structure.get('recommendations'):
            report.append("### 권장사항\n")
            for rec in structure['recommendations']:
                report.append(f"- {rec}\n")
    
    return ''.join(report)