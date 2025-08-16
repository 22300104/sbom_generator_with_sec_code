# ui/staged_code_analysis_tab.py
"""
단계별 코드 분석 탭
각 단계를 명확히 분리하여 상태 관리 개선
"""
import streamlit as st
import time
import json
from pathlib import Path
from typing import Dict, List, Optional
import tempfile
import os

from ui.memory_file_selector import MemoryFileSelector
from core.improved_llm_analyzer import ImprovedSecurityAnalyzer
from core.analyzer import SBOMAnalyzer
from core.project_downloader import ProjectDownloader


def render_code_analysis_tab():
    """메인 코드 분석 탭 - 단계별 UI"""
    st.header("🔍 보안 분석")
    
    # 단계 초기화
    if 'analysis_stage' not in st.session_state:
        st.session_state.analysis_stage = 'input'  # input -> files -> analyze -> results
    
    # 디버그 정보 (개발용)
    with st.sidebar:
        st.caption(f"현재 단계: {st.session_state.analysis_stage}")
        if st.button("🔄 초기화"):
            reset_analysis_state()
            st.rerun()
    
    # 단계별 렌더링
    if st.session_state.analysis_stage == 'input':
        render_input_stage()
    
    elif st.session_state.analysis_stage == 'files':
        render_file_selection_stage()
    
    elif st.session_state.analysis_stage == 'analyze':
        render_analysis_stage()
    
    elif st.session_state.analysis_stage == 'results':
        render_results_stage()


def reset_analysis_state():
    """분석 상태 초기화"""
    keys_to_remove = [
        'analysis_stage', 'project_files', 'project_name', 
        'selected_files', 'analysis_results', 'requirements_content'
    ]
    for key in keys_to_remove:
        if key in st.session_state:
            del st.session_state[key]


def render_input_stage():
    """1단계: 입력 선택"""
    st.subheader("📥 1단계: 소스 코드 입력")
    
    input_method = st.radio(
        "입력 방법 선택:",
        ["🔗 GitHub URL", "📦 파일 업로드", "📝 직접 입력"],
        horizontal=True
    )
    
    if input_method == "🔗 GitHub URL":
        handle_github_input()
    elif input_method == "📦 파일 업로드":
        handle_file_upload()
    elif input_method == "📝 직접 입력":
        handle_direct_input()


def handle_github_input():
    """GitHub 입력 처리"""
    # 취약한 예제 프로젝트 임포트
    from ui.vulnerable_examples import VULNERABLE_EXAMPLES
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        github_url = st.text_input(
            "GitHub 저장소 URL:",
            placeholder="https://github.com/owner/repository"
        )
    
    with col2:
        st.write("")
        st.write("")
        download_btn = st.button("📥 다운로드", type="primary", use_container_width=True)
    
    # 예제 탭
    tab1, tab2, tab3 = st.tabs(["🟢 일반 예제", "🔴 취약한 예제", "🔗 GitHub 예제"])
    
    with tab1:
        st.caption("보안 분석 테스트용 일반 프로젝트")
        col1, col2 = st.columns(2)
        
        # 로컬 취약한 예제들
        with col1:
            if st.button("Flask 취약 앱", key="vuln_flask"):
                example = VULNERABLE_EXAMPLES['flask_vulnerable']
                st.session_state.project_files = example['files']
                st.session_state.project_name = example['name']
                st.session_state.analysis_stage = 'files'
                st.rerun()
            
            if st.button("Django 취약 앱", key="vuln_django"):
                example = VULNERABLE_EXAMPLES['django_vulnerable']
                st.session_state.project_files = example['files']
                st.session_state.project_name = example['name']
                st.session_state.analysis_stage = 'files'
                st.rerun()
        
        with col2:
            if st.button("FastAPI 취약 앱", key="vuln_fastapi"):
                example = VULNERABLE_EXAMPLES['fastapi_vulnerable']
                st.session_state.project_files = example['files']
                st.session_state.project_name = example['name']
                st.session_state.analysis_stage = 'files'
                st.rerun()
    
    with tab2:
        st.caption("다양한 취약점이 포함된 데모 프로젝트")
        st.info("""
        포함된 취약점:
        - SQL Injection
        - XSS (Cross-Site Scripting)
        - 하드코딩된 시크릿
        - 약한 암호화 (MD5, SHA1)
        - 명령어 삽입
        - 경로 조작
        - 안전하지 않은 역직렬화
        - CSRF 취약점
        - 접근 제어 미흡
        """)
    
    with tab3:
        st.caption("GitHub에서 실제 프로젝트 다운로드")
        examples = {
            "Flask": "https://github.com/pallets/flask",
            "FastAPI": "https://github.com/tiangolo/fastapi",
            "Requests": "https://github.com/psf/requests",
            "OWASP Python": "https://github.com/OWASP/Python-Security"
        }
        
        for name, url in examples.items():
            if st.button(name, key=f"ex_{name}"):
                st.session_state.temp_github_url = url
    
    # 예제 선택 처리
    if 'temp_github_url' in st.session_state:
        github_url = st.session_state.temp_github_url
        del st.session_state.temp_github_url
        download_btn = True
    
    if download_btn and github_url:
        with st.spinner("🔄 GitHub 저장소 다운로드 중..."):
            success, project_files = download_github_project(github_url)
        
        if success:
            st.success("✅ 다운로드 완료!")
            
            # 프로젝트 정보 저장
            st.session_state.project_files = project_files
            st.session_state.project_name = github_url.split('/')[-1].replace('.git', '')
            st.session_state.analysis_stage = 'files'
            st.rerun()
        else:
            st.error("❌ 다운로드 실패")


def download_github_project(github_url: str) -> tuple[bool, List[Dict]]:
    """GitHub 프로젝트 다운로드 및 파일 정보 추출"""
    downloader = ProjectDownloader()
    
    try:
        success, message, project_path = downloader.download_github(github_url)
        
        if not success:
            return False, []
        
        # 모든 Python 파일을 메모리로 읽기
        project_files = []
        project_path = Path(project_path)
        
        # 제외할 디렉토리
        exclude_dirs = {'venv', '.venv', '__pycache__', '.git', 'node_modules', 
                       'site-packages', 'dist', 'build', '.tox'}
        
        for py_file in project_path.rglob('*.py'):
            # 제외 디렉토리 체크
            if any(exclude in py_file.parts for exclude in exclude_dirs):
                continue
            
            try:
                # 파일 내용 읽기
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # 상대 경로
                rel_path = py_file.relative_to(project_path)
                
                # 파일 정보 저장
                project_files.append({
                    'path': str(rel_path),
                    'content': content,
                    'size': len(content.encode('utf-8')),
                    'lines': len(content.splitlines())
                })
            except Exception as e:
                continue
        
        # requirements.txt 찾기
        req_content = ""
        for req_file in ['requirements.txt', 'requirements-dev.txt', 'setup.py']:
            req_path = project_path / req_file
            if req_path.exists():
                try:
                    with open(req_path, 'r', encoding='utf-8', errors='ignore') as f:
                        req_content += f"# {req_file}\n{f.read()}\n\n"
                except:
                    pass
        
        if req_content:
            st.session_state.requirements_content = req_content
        
        # 정리
        downloader.cleanup()
        
        return True, project_files
        
    except Exception as e:
        st.error(f"오류: {e}")
        return False, []


def handle_file_upload():
    """파일 업로드 처리"""
    uploaded_file = st.file_uploader(
        "Python 파일 또는 압축 파일 선택:",
        type=['py', 'zip', 'tar', 'gz']
    )
    
    if uploaded_file:
        if uploaded_file.name.endswith('.py'):
            # 단일 Python 파일
            content = uploaded_file.read().decode('utf-8')
            
            project_files = [{
                'path': uploaded_file.name,
                'content': content,
                'size': len(content.encode('utf-8')),
                'lines': len(content.splitlines())
            }]
            
            st.session_state.project_files = project_files
            st.session_state.project_name = uploaded_file.name[:-3]
            st.session_state.analysis_stage = 'files'
            st.rerun()
        
        else:
            # 압축 파일
            with st.spinner("압축 해제 중..."):
                success, project_files = extract_archive(uploaded_file)
            
            if success:
                st.success("✅ 파일 추출 완료!")
                st.session_state.project_files = project_files
                st.session_state.project_name = uploaded_file.name.split('.')[0]
                st.session_state.analysis_stage = 'files'
                st.rerun()
            else:
                st.error("❌ 압축 해제 실패")


def extract_archive(uploaded_file) -> tuple[bool, List[Dict]]:
    """압축 파일 추출"""
    import zipfile
    import tarfile
    
    project_files = []
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # 임시 파일로 저장
        tmp_path = Path(tmpdir) / uploaded_file.name
        tmp_path.write_bytes(uploaded_file.getbuffer())
        
        try:
            # ZIP 파일
            if uploaded_file.name.endswith('.zip'):
                with zipfile.ZipFile(tmp_path, 'r') as zf:
                    zf.extractall(tmpdir)
            
            # TAR 파일
            elif uploaded_file.name.endswith(('.tar', '.tar.gz', '.tgz')):
                with tarfile.open(tmp_path, 'r:*') as tf:
                    tf.extractall(tmpdir)
            
            # Python 파일 수집
            exclude_dirs = {'venv', '__pycache__', '.git', 'node_modules'}
            
            for py_file in Path(tmpdir).rglob('*.py'):
                if any(exclude in py_file.parts for exclude in exclude_dirs):
                    continue
                
                try:
                    with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    rel_path = py_file.relative_to(tmpdir)
                    
                    project_files.append({
                        'path': str(rel_path),
                        'content': content,
                        'size': len(content.encode('utf-8')),
                        'lines': len(content.splitlines())
                    })
                except:
                    continue
            
            return True, project_files
            
        except Exception as e:
            st.error(f"오류: {e}")
            return False, []


def handle_direct_input():
    """직접 입력 처리"""
    code = st.text_area(
        "Python 코드 입력:",
        height=400,
        placeholder="분석할 Python 코드를 입력하세요..."
    )
    
    if code and st.button("다음 단계 →", type="primary"):
        project_files = [{
            'path': 'main.py',
            'content': code,
            'size': len(code.encode('utf-8')),
            'lines': len(code.splitlines())
        }]
        
        st.session_state.project_files = project_files
        st.session_state.project_name = "DirectInput"
        st.session_state.analysis_stage = 'files'
        st.rerun()


def render_file_selection_stage():
    """2단계: 파일 선택"""
    st.subheader("📂 2단계: 분석할 파일 선택")
    
    # 뒤로가기 버튼
    if st.button("← 이전 단계"):
        st.session_state.analysis_stage = 'input'
        st.rerun()
    
    # 프로젝트 정보
    project_files = st.session_state.get('project_files', [])
    project_name = st.session_state.get('project_name', 'Unknown')
    
    st.info(f"""
    **프로젝트**: {project_name}  
    **총 파일**: {len(project_files)}개
    """)
    
    if not project_files:
        st.error("파일이 없습니다.")
        return
    
    # 파일 선택 UI
    selector = MemoryFileSelector(project_files)
    selected_paths = selector.render()
    
    st.divider()
    
    # 분석 옵션
    if selected_paths:
        st.subheader("⚙️ 분석 옵션")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            analysis_mode = st.selectbox(
                "분석 모드:",
                ["🤖 AI 보안 분석", "⚡ 빠른 분석", "🔥 전체 분석"]
            )
            st.session_state.analysis_mode = analysis_mode
        
        with col2:
            use_claude = st.checkbox("Claude 사용", value=True)
            st.session_state.use_claude = use_claude
        
        with col3:
            include_sbom = st.checkbox("SBOM 생성", value=True)
            st.session_state.include_sbom = include_sbom
        
        # 분석 시작 버튼
        if st.button("🚀 분석 시작", type="primary", use_container_width=True):
            # 선택된 파일 코드 가져오기
            code, file_list = selector.get_selected_code()
            
            if code:
                st.session_state.analysis_code = code
                st.session_state.analysis_file_list = file_list
                st.session_state.analysis_stage = 'analyze'
                st.rerun()
            else:
                st.error("파일을 선택해주세요.")
    else:
        st.warning("분석할 파일을 선택해주세요.")


def render_analysis_stage():
    """3단계: 분석 실행"""
    st.subheader("🔍 3단계: 보안 분석 실행")
    
    # 분석 정보
    file_list = st.session_state.get('analysis_file_list', [])
    code = st.session_state.get('analysis_code', '')
    
    st.info(f"""
    **분석 대상**: {len(file_list)}개 파일  
    **코드 크기**: {len(code):,}자 ({len(code)/1024:.1f}KB)
    """)
    
    # 분석 실행
    with st.spinner("분석 중... (최대 30초 소요)"):
        results = run_analysis(
            code=code,
            file_list=file_list,
            mode=st.session_state.get('analysis_mode', '🤖 AI 보안 분석'),
            use_claude=st.session_state.get('use_claude', True),
            include_sbom=st.session_state.get('include_sbom', True)
        )
    
    # 결과 저장 및 다음 단계
    st.session_state.analysis_results = results
    st.session_state.analysis_stage = 'results'
    st.rerun()


def run_analysis(code: str, file_list: List[Dict], mode: str, use_claude: bool, include_sbom: bool) -> Dict:
    """분석 실행"""
    from core.formatter import SBOMFormatter
    
    results = {}
    start_time = time.time()
    
    try:
        # SBOM 분석
        if include_sbom and mode in ["⚡ 빠른 분석", "🔥 전체 분석"]:
            analyzer = SBOMAnalyzer()
            requirements = st.session_state.get('requirements_content', '')
            sbom_result = analyzer.analyze(code, requirements, scan_environment=False)
            
            if sbom_result.get("success"):
                results['sbom'] = sbom_result
                
                # SBOM 표준 형식 생성
                formatter = SBOMFormatter()
                project_name = st.session_state.get('project_name', 'Project')
                
                results['sbom_formats'] = {
                    'spdx': formatter.to_spdx(
                        sbom_result.get('packages', []),
                        {'project_name': project_name}
                    ),
                    'cyclonedx': formatter.to_cyclonedx(
                        sbom_result.get('packages', []),
                        {'project_name': project_name}
                    )
                }
        
        # AI 보안 분석
        if mode in ["🤖 AI 보안 분석", "🔥 전체 분석"]:
            ai_analyzer = ImprovedSecurityAnalyzer(use_claude=use_claude)
            ai_result = ai_analyzer.analyze_security(code, file_list)
            results['ai_analysis'] = ai_result
        
    except Exception as e:
        st.error(f"분석 오류: {e}")
        results['error'] = str(e)
    
    results['analysis_time'] = time.time() - start_time
    results['analyzed_files'] = len(file_list)
    
    return results


def render_results_stage():
    """4단계: 결과 표시"""
    st.subheader("📊 4단계: 분석 결과")
    
    # 네비게이션
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🏠 처음으로"):
            reset_analysis_state()
            st.rerun()
    
    with col2:
        if st.button("📂 파일 다시 선택"):
            st.session_state.analysis_stage = 'files'
            st.rerun()
    
    with col3:
        if st.button("🔄 다시 분석"):
            st.session_state.analysis_stage = 'analyze'
            st.rerun()
    
    st.divider()
    
    # 결과 표시
    results = st.session_state.get('analysis_results', {})
    
    if not results:
        st.error("분석 결과가 없습니다.")
        return
    
    # 분석 시간
    st.success(f"✅ 분석 완료 ({results.get('analysis_time', 0):.1f}초)")
    
    # 탭으로 결과 구성
    tabs = []
    if 'ai_analysis' in results:
        tabs.append("🤖 보안 분석")
    if 'sbom' in results:
        tabs.append("📦 SBOM")
    if results.get('sbom_formats'):
        tabs.append("📋 SBOM 표준")
    tabs.append("💾 다운로드")
    
    if tabs:
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
        
        # SBOM 표준 탭
        if results.get('sbom_formats'):
            with tab_objects[tab_idx]:
                display_sbom_standards(results['sbom_formats'])
            tab_idx += 1
        
        # 다운로드 탭
        with tab_objects[-1]:
            display_download_options(results)


def display_ai_results(ai_result: Dict):
    """AI 분석 결과 표시"""
    if not ai_result.get('success'):
        st.error("분석 실패")
        return
    
    # 메트릭
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("보안 점수", f"{ai_result.get('security_score', 100)}/100")
    
    with col2:
        vulns = len(ai_result.get('vulnerabilities', []))
        st.metric("발견된 취약점", vulns)
    
    with col3:
        st.metric("분석 엔진", ai_result.get('analyzed_by', 'AI'))
    
    # 요약
    st.info(ai_result.get('summary', ''))
    
    # 취약점 상세
    vulnerabilities = ai_result.get('vulnerabilities', [])
    
    if vulnerabilities:
        st.subheader("🔍 발견된 취약점")
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'MEDIUM')
            severity_icon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }.get(severity, '⚪')
            
            location = vuln.get('location', {})
            title = f"{severity_icon} {vuln.get('type', 'Unknown')}"
            if location.get('file'):
                title += f" - {location['file']}"
            
            with st.expander(title):
                st.write("**설명:**", vuln.get('description', ''))
                
                if vuln.get('data_flow'):
                    st.info(f"**데이터 흐름:** {vuln['data_flow']}")
                
                if vuln.get('exploit_scenario'):
                    st.warning(f"**공격 시나리오:** {vuln['exploit_scenario']}")
                
                if vuln.get('evidence'):
                    evidence = vuln['evidence']
                    st.success(f"**📚 {evidence.get('source', 'KISIA')}:**")
                    st.caption(evidence.get('content', '')[:300] + "...")
                
                if vuln.get('recommendation'):
                    st.success(f"**개선 방법:** {vuln['recommendation']}")
    else:
        st.success("✅ 취약점이 발견되지 않았습니다!")


def display_sbom_results(sbom: Dict):
    """SBOM 결과 표시"""
    import pandas as pd
    
    st.subheader("📦 Software Bill of Materials")
    
    summary = sbom.get('summary', {})
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("외부 패키지", summary.get('external_packages', 0))
    with col2:
        st.metric("버전 확인", summary.get('with_version', 0))
    with col3:
        st.metric("종속성", summary.get('total_dependencies', 0))
    
    # 패키지 목록
    packages = sbom.get('packages', [])
    if packages:
        df_data = []
        for pkg in packages[:20]:  # 상위 20개만
            df_data.append({
                "패키지": pkg.get('name', ''),
                "버전": pkg.get('version', '미확인'),
                "상태": pkg.get('status', '')
            })
        
        if df_data:
            df = pd.DataFrame(df_data)
            st.dataframe(df, use_container_width=True, hide_index=True)


def display_download_options(results: Dict):
    """다운로드 옵션"""
    st.subheader("💾 다운로드")
    
    # JSON 결과
    json_str = json.dumps(results, indent=2, default=str, ensure_ascii=False)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.download_button(
            "📥 전체 결과 (JSON)",
            data=json_str,
            file_name=f"analysis_{int(time.time())}.json",
            mime="application/json"
        )
        
        # 보안 보고서
        if 'ai_analysis' in results:
            report = generate_security_report(results)
            st.download_button(
                "📄 보안 보고서 (Markdown)",
                data=report,
                file_name=f"security_report_{int(time.time())}.md",
                mime="text/markdown"
            )
    
    with col2:
        # SBOM 표준 형식 다운로드
        if results.get('sbom_formats'):
            if results['sbom_formats'].get('spdx'):
                spdx_json = json.dumps(
                    results['sbom_formats']['spdx'],
                    indent=2,
                    ensure_ascii=False
                )
                st.download_button(
                    "📦 SPDX 2.3 형식",
                    data=spdx_json,
                    file_name=f"sbom_spdx_{int(time.time())}.json",
                    mime="application/json"
                )
            
            if results['sbom_formats'].get('cyclonedx'):
                cyclone_json = json.dumps(
                    results['sbom_formats']['cyclonedx'],
                    indent=2,
                    ensure_ascii=False
                )
                st.download_button(
                    "📦 CycloneDX 1.4 형식",
                    data=cyclone_json,
                    file_name=f"sbom_cyclonedx_{int(time.time())}.json",
                    mime="application/json"
                )


def display_sbom_standards(sbom_formats: Dict):
    """SBOM 표준 형식 표시"""
    st.subheader("📋 SBOM 표준 형식")
    
    tab1, tab2 = st.tabs(["SPDX 2.3", "CycloneDX 1.4"])
    
    with tab1:
        if sbom_formats.get('spdx'):
            st.info("SPDX (Software Package Data Exchange) - 라이선스 중심 표준")
            
            spdx = sbom_formats['spdx']
            
            # 기본 정보
            col1, col2 = st.columns(2)
            with col1:
                st.write("**문서 정보**")
                st.caption(f"- SPDX 버전: {spdx.get('spdxVersion', 'N/A')}")
                st.caption(f"- 문서 ID: {spdx.get('SPDXID', 'N/A')}")
                st.caption(f"- 프로젝트명: {spdx.get('name', 'N/A')}")
            
            with col2:
                st.write("**생성 정보**")
                creation = spdx.get('creationInfo', {})
                st.caption(f"- 생성일: {creation.get('created', 'N/A')[:19]}")
                st.caption(f"- 도구: {creation.get('creators', ['N/A'])[0]}")
            
            # 패키지 목록
            st.write("**패키지 목록**")
            packages = spdx.get('packages', [])
            if packages:
                for pkg in packages[:10]:
                    with st.expander(f"📦 {pkg.get('name', 'Unknown')}"):
                        st.caption(f"ID: {pkg.get('SPDXID', 'N/A')}")
                        st.caption(f"버전: {pkg.get('versionInfo', 'N/A')}")
                        st.caption(f"홈페이지: {pkg.get('homepage', 'N/A')}")
                        
                        # 취약점 정보
                        refs = pkg.get('externalRefs', [])
                        vuln_refs = [r for r in refs if r.get('referenceCategory') == 'SECURITY']
                        if vuln_refs:
                            st.warning(f"⚠️ {len(vuln_refs)}개 취약점 발견")
            
            # JSON 뷰어
            with st.expander("📄 전체 JSON 보기"):
                st.json(spdx)
    
    with tab2:
        if sbom_formats.get('cyclonedx'):
            st.info("CycloneDX - 보안 중심 표준 (OWASP)")
            
            cyclone = sbom_formats['cyclonedx']
            
            # 기본 정보
            col1, col2 = st.columns(2)
            with col1:
                st.write("**BOM 정보**")
                st.caption(f"- 형식: {cyclone.get('bomFormat', 'N/A')}")
                st.caption(f"- 스펙 버전: {cyclone.get('specVersion', 'N/A')}")
                st.caption(f"- 시리얼: {cyclone.get('serialNumber', 'N/A')[:20]}...")
            
            with col2:
                st.write("**메타데이터**")
                metadata = cyclone.get('metadata', {})
                st.caption(f"- 타임스탬프: {metadata.get('timestamp', 'N/A')[:19]}")
                component = metadata.get('component', {})
                st.caption(f"- 프로젝트: {component.get('name', 'N/A')}")
            
            # 컴포넌트 목록
            st.write("**컴포넌트 목록**")
            components = cyclone.get('components', [])
            if components:
                for comp in components[:10]:
                    with st.expander(f"📦 {comp.get('name', 'Unknown')}"):
                        st.caption(f"타입: {comp.get('type', 'N/A')}")
                        st.caption(f"버전: {comp.get('version', 'N/A')}")
                        st.caption(f"PURL: {comp.get('purl', 'N/A')}")
                        
                        # 취약점 정보
                        vulns = comp.get('vulnerabilities', [])
                        if vulns:
                            st.warning(f"⚠️ {len(vulns)}개 취약점")
                            for vuln in vulns[:3]:
                                st.caption(f"- {vuln.get('id', 'N/A')}: {vuln.get('description', '')[:100]}...")
            
            # JSON 뷰어
            with st.expander("📄 전체 JSON 보기"):
                st.json(cyclone)


def generate_security_report(results: Dict) -> str:
    """보안 보고서 생성"""
    report = []
    report.append("# 보안 분석 보고서\n\n")
    report.append(f"생성 시간: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    
    if 'ai_analysis' in results:
        ai = results['ai_analysis']
        report.append("## 보안 분석 결과\n\n")
        report.append(f"- 보안 점수: {ai.get('security_score', 100)}/100\n")
        report.append(f"- 발견된 취약점: {len(ai.get('vulnerabilities', []))}개\n\n")
        
        vulnerabilities = ai.get('vulnerabilities', [])
        if vulnerabilities:
            report.append("### 취약점 상세\n\n")
            for i, vuln in enumerate(vulnerabilities, 1):
                report.append(f"#### {i}. {vuln.get('type', 'Unknown')}\n")
                report.append(f"- 심각도: {vuln.get('severity', 'MEDIUM')}\n")
                report.append(f"- 설명: {vuln.get('description', '')}\n")
                if vuln.get('recommendation'):
                    report.append(f"- 권장사항: {vuln['recommendation']}\n")
                report.append("\n")
    
    return ''.join(report)