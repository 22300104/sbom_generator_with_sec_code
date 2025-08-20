# ui/staged_code_analysis_tab.py
"""
단계별 코드 분석 탭
각 단계를 명확히 분리하여 상태 관리 개선
"""
import streamlit as st
from streamlit_monaco import st_monaco
import time
import json
from pathlib import Path
from typing import Dict, List, Optional
import tempfile
import os

from ui.memory_file_selector import MemoryFileSelector
from core.improved_llm_analyzer import ImprovedSecurityAnalyzer
from core.analyzer import SBOMAnalyzer
from core.formatter import SBOMFormatter
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


# ui/staged_code_analysis_tab.py
# handle_github_input() 함수 수정

def handle_github_input():
    """GitHub 입력 처리 - 개선된 예제 구조"""
    
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
    
    # 통합된 예제 섹션
    st.divider()
    st.subheader("📚 보안 테스트용 예제 프로젝트")
    
    # 예제 카테고리
    example_category = st.selectbox(
        "카테고리 선택:",
        ["🔴 의도적 취약 프로젝트 (교육용)", "🟡 취약점 데모", "🟢 일반 프로젝트"]
    )
    
    # GitHub 취약 프로젝트 예제들
    vulnerable_projects = {
        "🔴 의도적 취약 프로젝트 (교육용)": {
            "DVWA-Python": {
                "url": "https://github.com/anxolerd/dvwa-flask",
                "description": "Damn Vulnerable Web App - Flask 버전",
                "vulnerabilities": "SQL Injection, XSS, CSRF, Command Injection 등"
            },
            "PyGoat": {
                "url": "https://github.com/adeyosemanputra/pygoat",
                "description": "OWASP PyGoat - 의도적으로 취약한 Python Django 앱",
                "vulnerabilities": "OWASP Top 10 취약점 포함"
            },
            "Vulnerable Flask App": {
                "url": "https://github.com/we45/Vulnerable-Flask-App",
                "description": "보안 교육용 취약한 Flask 애플리케이션",
                "vulnerabilities": "다양한 웹 취약점"
            },
            "Django Vulnerable": {
                "url": "https://github.com/nVisium/django.nV",
                "description": "의도적으로 취약한 Django 애플리케이션",
                "vulnerabilities": "인증, 인가, 인젝션 취약점"
            },
            "Security Shepherd Python": {
                "url": "https://github.com/OWASP/SecurityShepherd",
                "description": "OWASP Security Shepherd - 보안 교육 플랫폼",
                "vulnerabilities": "단계별 보안 취약점"
            }
        },
        "🟡 취약점 데모": {
            "Python Security Examples": {
                "url": "https://github.com/craigz28/python-security",
                "description": "Python 보안 취약점 예제 모음",
                "vulnerabilities": "일반적인 Python 보안 문제"
            },
            "Vulnerable Python": {
                "url": "https://github.com/anxolerd/vulnerable-python",
                "description": "Python 취약점 데모 코드",
                "vulnerabilities": "코드 실행, 역직렬화 등"
            },
            "Bad Python": {
                "url": "https://github.com/mpirnat/lets-be-bad-guys",
                "description": "Python 웹 앱 보안 워크샵 자료",
                "vulnerabilities": "웹 보안 취약점 예제"
            }
        },
        "🟢 일반 프로젝트": {
            "Flask": {
                "url": "https://github.com/pallets/flask",
                "description": "Flask 웹 프레임워크",
                "vulnerabilities": "일반 프로젝트 (취약점 최소)"
            },
            "Django": {
                "url": "https://github.com/django/django",
                "description": "Django 웹 프레임워크",
                "vulnerabilities": "일반 프로젝트 (보안 강화됨)"
            },
            "FastAPI": {
                "url": "https://github.com/tiangolo/fastapi",
                "description": "FastAPI 프레임워크",
                "vulnerabilities": "일반 프로젝트 (현대적 보안)"
            },
            "Requests": {
                "url": "https://github.com/psf/requests",
                "description": "Python HTTP 라이브러리",
                "vulnerabilities": "일반 라이브러리"
            }
        }
    }
    
    # 선택된 카테고리의 프로젝트 표시
    selected_projects = vulnerable_projects.get(example_category, {})
    
    if selected_projects:
        st.info(f"💡 {example_category}의 프로젝트들입니다. 교육 및 테스트 목적으로만 사용하세요.")
        
        # 경량 스타일 (배지/링크 카드)
        st.markdown(
            """
<style>
.proj-badges { display:flex; flex-wrap:wrap; gap:.35rem; margin:.25rem 0 .5rem; }
.proj-badge { background:#f4f6f8; color:#1f2937; border:1px solid #e5e7eb; border-radius:999px; padding:.15rem .55rem; font-size:.85rem; }
.proj-url { background:#ffffff; border:1px solid #e5e7eb; border-radius:8px; padding:.45rem .6rem; }
.proj-url a { color:#1e3a5f; text-decoration:none; word-break:break-all; }
.proj-url a:hover { text-decoration:underline; }
</style>
""",
            unsafe_allow_html=True,
        )
        
        # 프로젝트 카드 형식으로 표시
        for name, project in selected_projects.items():
            with st.expander(f"**{name}**"):
                left, right = st.columns([5, 1])
                with left:
                    st.markdown(f"**설명:** {project['description']}")
                    # 취약점 배지 렌더링
                    _vtxt = project.get('vulnerabilities', '')
                    _items = [v.strip() for v in _vtxt.replace('등', '').split(',') if v.strip()]
                    if _items:
                        _badges = ' '.join([f"<span class='proj-badge'>{v}</span>" for v in _items])
                    else:
                        _badges = f"<span class='proj-badge'>{_vtxt}</span>"
                    st.markdown(f"<div class='proj-badges'>{_badges}</div>", unsafe_allow_html=True)
                    # 링크 카드
                    _url = project['url']
                    st.markdown(f"<div class='proj-url'><a class='proj-link' href='{_url}' target='_blank'>{_url}</a></div>", unsafe_allow_html=True)
                with right:
                    if st.button("분석하기", key=f"analyze_{name}", use_container_width=True):
                        st.session_state.temp_github_url = project['url']
                        st.rerun()
    
    # 로컬 취약 예제 (수정된 버전)
    with st.expander("💾 로컬 취약 예제 (requirements 포함)"):
        st.warning("⚠️ 이 예제들은 교육 목적으로 만들어진 취약한 코드입니다.")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("Flask 취약 앱", key="local_flask"):
                example = get_enhanced_flask_example()
                load_local_example(example)
        
        with col2:
            if st.button("Django 취약 앱", key="local_django"):
                example = get_enhanced_django_example()
                load_local_example(example)
        
        with col3:
            if st.button("FastAPI 취약 앱", key="local_fastapi"):
                example = get_enhanced_fastapi_example()
                load_local_example(example)
    
    # URL 처리
    if 'temp_github_url' in st.session_state:
        github_url = st.session_state.temp_github_url
        del st.session_state.temp_github_url
        download_btn = True
    
    if download_btn and github_url:
        with st.spinner("🔄 GitHub 저장소 다운로드 중..."):
            success, project_files = download_github_project(github_url)
        
        if success:
            st.success("✅ 다운로드 완료!")
            st.session_state.project_files = project_files
            st.session_state.project_name = github_url.split('/')[-1].replace('.git', '')
            st.session_state.analysis_stage = 'files'
            st.rerun()
        else:
            st.error("❌ 다운로드 실패")


def load_local_example(example: Dict):
    """로컬 예제 로드 - requirements 처리 포함"""
    st.session_state.project_files = example['files']
    st.session_state.project_name = example['name']
    
    # requirements.txt 내용 추출 및 세션에 저장
    req_content = ""
    for file_info in example['files']:
        if 'requirements' in file_info['path'].lower():
            req_content = file_info['content']
            break
    
    if req_content:
        st.session_state.requirements_content = req_content
    
    st.session_state.analysis_stage = 'files'
    st.rerun()


def get_enhanced_flask_example() -> Dict:
    """개선된 Flask 취약 예제 - requirements 포함"""
    from ui.vulnerable_examples import get_vulnerable_web_app
    example = get_vulnerable_web_app()
    
    # requirements.txt가 있는지 확인하고 세션에 저장할 수 있도록 수정
    return example


def get_enhanced_django_example() -> Dict:
    """개선된 Django 취약 예제"""
    from ui.vulnerable_examples import get_vulnerable_django_app
    return get_vulnerable_django_app()


def get_enhanced_fastapi_example() -> Dict:
    """개선된 FastAPI 취약 예제"""
    from ui.vulnerable_examples import get_vulnerable_fastapi_app
    return get_vulnerable_fastapi_app()


def download_github_project(github_url: str) -> tuple[bool, List[Dict]]:
    """GitHub 프로젝트 다운로드 및 파일 정보 추출"""
    downloader = ProjectDownloader()
    
    try:
        success, message, project_path = downloader.download_github(github_url)
        
        if not success:
            return False, []
        
        project_files = []
        project_path = Path(project_path)
        
        exclude_dirs = {'venv', '.venv', '__pycache__', '.git', 'node_modules', 
                       'site-packages', 'dist', 'build', '.tox'}
        
        for py_file in project_path.rglob('*.py'):
            if any(exclude in py_file.parts for exclude in exclude_dirs):
                continue
            
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                rel_path = py_file.relative_to(project_path)
                
                project_files.append({
                    'path': str(rel_path),
                    'content': content,
                    'size': len(content.encode('utf-8')),
                    'lines': len(content.splitlines())
                })
            except Exception as e:
                continue
        
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
        tmp_path = Path(tmpdir) / uploaded_file.name
        tmp_path.write_bytes(uploaded_file.getbuffer())
        
        try:
            if uploaded_file.name.endswith('.zip'):
                with zipfile.ZipFile(tmp_path, 'r') as zf:
                    zf.extractall(tmpdir)
            
            elif uploaded_file.name.endswith(('.tar', '.tar.gz', '.tgz')):
                with tarfile.open(tmp_path, 'r:*') as tf:
                    tf.extractall(tmpdir)
            
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
    st.markdown("#### Python 코드")

    if 'monaco_code' not in st.session_state:
        st.session_state.monaco_code = ""

    # 항상 폼 제출 기반(안정) 방식 사용
    with st.form("direct_input_form"):
        code = st_monaco(
            value=st.session_state.monaco_code,
            height="500px",
            language="python",
        )
        submitted = st.form_submit_button("다음 단계 →")

    if submitted:
        content = code if code is not None else st.session_state.monaco_code
        if content:
            st.session_state.monaco_code = content
            project_files = [{
                'path': 'main.py',
                'content': content,
                'size': len(content.encode('utf-8')),
                'lines': len(content.splitlines())
            }]
            st.session_state.project_files = project_files
            st.session_state.project_name = "DirectInput"
            st.session_state.analysis_stage = 'files'
            st.rerun()
        else:
            st.warning("코드를 입력하세요.")


# ui/staged_code_analysis_tab.py
# render_file_selection_stage() 함수 전체 교체

def render_file_selection_stage():
    """2단계: 파일 선택"""
    st.subheader("📂 2단계: 분석할 파일 선택")
    
    if st.button("← 이전 단계"):
        st.session_state.analysis_stage = 'input'
        st.rerun()
    
    project_files = st.session_state.get('project_files', [])
    project_name = st.session_state.get('project_name', 'Unknown')
    
    st.info(f"""
    **프로젝트**: {project_name}  
    **총 파일**: {len(project_files)}개
    """)
    
    if not project_files:
        st.error("파일이 없습니다.")
        return
    
    selector = MemoryFileSelector(project_files)
    selected_paths = selector.render()
    
    st.divider()
    
    if selected_paths:
        st.subheader("⚙️ 분석 옵션")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            analysis_mode = st.selectbox(
                "분석 모드:",
                ["🔥 전체 분석", "🤖 AI 보안 분석", "⚡ 빠른 분석"],
                help="• 전체 분석: AI 보안 분석 + SBOM 생성\n• AI 보안 분석: 취약점 탐지\n• 빠른 분석: SBOM만 생성"
            )
            st.session_state.analysis_mode = analysis_mode
        
        with col2:
            # Claude 우선 사용 옵션
            st.markdown("**AI 엔진 설정**")
            
            # 사용 가능한 엔진 확인
            has_claude = bool(os.getenv("ANTHROPIC_API_KEY"))
            has_gpt = bool(os.getenv("OPENAI_API_KEY"))
            
            if has_claude and has_gpt:
                # 둘 다 있을 때
                use_claude = st.checkbox("Claude 우선 사용", value=True, help="Claude를 메인으로, GPT를 폴백으로 사용")
                st.session_state.use_claude = use_claude
                
                if use_claude:
                    st.caption("🎭 Claude → 🤖 GPT")
                else:
                    st.caption("🤖 GPT 전용")
            elif has_claude:
                # Claude만 있을 때
                st.session_state.use_claude = True
                st.caption("🎭 Claude 사용")
            elif has_gpt:
                # GPT만 있을 때
                st.session_state.use_claude = False
                st.caption("🤖 GPT 사용")
            else:
                # 둘 다 없을 때
                st.error("AI 엔진 없음")
                st.caption("API 키 설정 필요")
        
        with col3:
            st.markdown("**SBOM 옵션**")
            include_sbom = st.checkbox(
                "SBOM 생성", 
                value=True,
                help="Software Bill of Materials를 생성합니다.\nSPDX 2.3 및 CycloneDX 1.4 표준 형식 지원"
            )
            st.session_state.include_sbom = include_sbom
            
            if include_sbom:
                st.caption("📦 SBOM 생성됨")
            else:
                st.caption("⏭️ SBOM 건너뜀")
        
        # 분석 모드 설명
        st.divider()
        
        if analysis_mode == "🔥 전체 분석":
            st.success("""
            ✅ **전체 분석 모드**
            - AI 기반 보안 취약점 탐지
            - SBOM (Software Bill of Materials) 생성
            - 패키지 의존성 분석
            - 취약점 데이터베이스 검사
            """)
        elif analysis_mode == "🤖 AI 보안 분석":
            if include_sbom:
                st.info("""
                ℹ️ **AI 보안 분석 + SBOM**
                - AI 기반 취약점 탐지
                - 수정 코드 제안
                - SBOM 생성 포함
                """)
            else:
                st.warning("""
                ⚠️ **AI 보안 분석만**
                - 취약점 탐지에만 집중
                - SBOM 생성 안 함
                """)
        elif analysis_mode == "⚡ 빠른 분석":
            st.info("""
            ℹ️ **빠른 SBOM 분석**
            - SBOM만 빠르게 생성
            - AI 보안 분석 없음
            - 의존성 파악용
            """)
        
        # 분석 시작 버튼
        st.divider()
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            # 선택된 파일 요약
            selected_count = len(selected_paths)
            total_size = sum(f['size'] for f in project_files if f['path'] in selected_paths)
            
            st.info(f"""
            **분석 준비 완료**
            - 선택된 파일: {selected_count}개
            - 총 크기: {total_size // 1024:.1f}KB
            - 분석 모드: {analysis_mode}
            """)
            
            if st.button(
                "🚀 분석 시작", 
                type="primary", 
                use_container_width=True,
                disabled=(selected_count == 0)
            ):
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
        
        # 도움말
        with st.expander("💡 파일 선택 도움말"):
            st.markdown("""
            **스마트 선택 도구 사용법:**
            1. **전체 선택**: 모든 Python 파일 분석
            2. **주요 파일만**: main.py, app.py, views.py 등 핵심 파일
            3. **작은 파일만**: 10KB 이하의 작은 파일들
            4. **전체 해제**: 선택 초기화
            
            **개별 선택:**
            - 디렉토리별로 그룹화되어 표시됩니다
            - 체크박스로 개별 파일을 선택/해제할 수 있습니다
            
            **고급 필터링:**
            - 파일 크기별 필터
            - 파일명 패턴 검색
            """)


def render_analysis_stage():
    """3단계: 분석 실행"""
    st.subheader("🔍 3단계: 보안 분석 실행")
    
    file_list = st.session_state.get('analysis_file_list', [])
    code = st.session_state.get('analysis_code', '')
    
    st.info(f"""
    **분석 대상**: {len(file_list)}개 파일  
    **코드 크기**: {len(code):,}자 ({len(code)/1024:.1f}KB)
    """)
    
    with st.spinner("분석 중... (최대 30초 소요)"):
        results = run_analysis(
            code=code,
            file_list=file_list,
            mode=st.session_state.get('analysis_mode', '🤖 AI 보안 분석'),
            use_claude=st.session_state.get('use_claude', True),
            include_sbom=st.session_state.get('include_sbom', True)
        )
    
    st.session_state.analysis_results = results
    st.session_state.analysis_stage = 'results'
    st.rerun()


def render_results_stage():
    """4단계: 결과 표시"""
    st.subheader("📊 4단계: 분석 결과")
    
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
    
    results = st.session_state.get('analysis_results', {})
    
    if not results:
        st.error("분석 결과가 없습니다.")
        return
    
    st.success(f"✅ 분석 완료 ({results.get('analysis_time', 0):.1f}초)")
    
    tabs = []
    if 'ai_analysis' in results:
        tabs.append("보안 분석")
    if 'sbom' in results:
        tabs.append("SBOM")
    if results.get('sbom_formats'):
        tabs.append("SBOM 표준")
    tabs.append("다운로드")
    
    if tabs:
        tab_objects = st.tabs(tabs)
        tab_idx = 0
        
        if 'ai_analysis' in results:
            with tab_objects[tab_idx]:
                display_ai_results(results['ai_analysis'])
            tab_idx += 1
        
        if 'sbom' in results:
            with tab_objects[tab_idx]:
                display_sbom_results(results['sbom'])
            tab_idx += 1
        
        if results.get('sbom_formats'):
            with tab_objects[tab_idx]:
                display_sbom_standards(results['sbom_formats'])
            tab_idx += 1
        
        with tab_objects[-1]:
            display_download_options(results)


def run_analysis(code: str, file_list: List[Dict], mode: str, use_claude: bool, include_sbom: bool) -> Dict:
    """분석 실행 - 수정된 버전"""
    from core.formatter import SBOMFormatter
    
    results = {}
    start_time = time.time()
    
    try:
        # SBOM 분석 - 모든 모드에서 실행 가능
        if include_sbom:
            analyzer = SBOMAnalyzer()
            requirements = st.session_state.get('requirements_content', '')
            
            sbom_result = analyzer.analyze(code, requirements, scan_environment=False)
            
            # 개선된 결과 처리
            if sbom_result and 'error' not in sbom_result:
                if 'packages' in sbom_result or sbom_result.get('success'):
                    results['sbom'] = sbom_result
                    
                    try:
                        formatter = SBOMFormatter()
                        project_name = st.session_state.get('project_name', 'Project')
                        packages = sbom_result.get('packages', [])
                        
                        results['sbom_formats'] = {
                            'spdx': formatter.to_spdx(
                                packages,
                                {'project_name': project_name}
                            ),
                            'cyclonedx': formatter.to_cyclonedx(
                                packages,
                                {'project_name': project_name}
                            )
                        }
                    except Exception as fmt_error:
                        st.warning(f"⚠️ SBOM 표준 형식 생성 실패: {fmt_error}")
                else:
                    st.warning("⚠️ SBOM 생성 실패: 패키지 정보를 추출할 수 없습니다")
            elif sbom_result and 'error' in sbom_result:
                st.error(f"❌ SBOM 분석 오류: {sbom_result['error']}")
        
        # AI 보안 분석
        if mode in ["🤖 AI 보안 분석", "🔥 전체 분석"]:
            # use_claude 파라미터 명시적 전달
            print(f"🔍 AI 분석 시작 (use_claude={use_claude})")
            ai_analyzer = ImprovedSecurityAnalyzer(use_claude=use_claude)
            ai_result = ai_analyzer.analyze_security(code, file_list)
            results['ai_analysis'] = ai_result
            
            # 디버그: 발견된 취약점 수 출력
            vuln_count = len(ai_result.get('vulnerabilities', []))
            print(f"📊 분석 완료: {vuln_count}개 취약점 발견")
        
    except Exception as e:
        st.error(f"분석 오류: {e}")
        results['error'] = str(e)
    
    results['analysis_time'] = time.time() - start_time
    results['analyzed_files'] = len(file_list)
    
    return results


def display_ai_results(ai_result: Dict):
    """AI 분석 결과 표시 - 에러 처리 개선"""
    
        # 디버그 출력 추가
    print(f"🔍 UI 받은 데이터: success={ai_result.get('success')}, "
          f"vulns={len(ai_result.get('vulnerabilities', []))}, "
          f"has_error={ai_result.get('has_error')}")
    
    vulnerabilities = ai_result.get('vulnerabilities', [])
    print(f"🔍 vulnerabilities 타입: {type(vulnerabilities)}, 길이: {len(vulnerabilities)}")
    
    if vulnerabilities:
        for i, vuln in enumerate(vulnerabilities):
            print(f"  - 취약점 {i+1}: {vuln.get('type', 'Unknown')}")

    # 에러 체크
    if ai_result.get('has_error'):
        st.error("❌ AI 보안 분석 중 오류 발생")
        
        error_type = ai_result.get('error_type', 'Unknown Error')
        
        # 에러 타입별 상세 메시지
        if error_type == "Parse Error":
            st.warning("""
            **JSON 파싱 오류**
            
            AI가 응답을 생성했지만 형식을 파싱할 수 없습니다.
            가능한 원인:
            - AI 응답 형식 오류
            - 특수 문자 처리 문제
            - 너무 긴 응답
            
            **해결 방법:**
            1. 다시 분석 시도
            2. 코드를 더 작은 부분으로 나누기
            3. 다른 AI 모델 사용 (Claude ↔ GPT)
            """)
            
        elif error_type == "Context Length Error":
            st.warning("""
            **토큰 길이 초과**
            
            코드가 너무 길어 AI가 처리할 수 없습니다.
            
            **해결 방법:**
            1. 중요한 파일만 선택하여 분석
            2. 파일을 여러 번 나누어 분석
            3. GPT-4 또는 Claude 사용 (더 긴 컨텍스트 지원)
            """)
            
        elif error_type == "Analysis Failed":
            st.warning("""
            **분석 실패**
            
            AI가 코드를 분석할 수 없습니다.
            
            **해결 방법:**
            1. 코드 구문 오류 확인
            2. Python 코드인지 확인
            3. 다시 시도
            """)
        
        # 디버그 정보 표시 (선택적)
        with st.expander("🔍 디버그 정보"):
            st.json(ai_result)
        
        return
    
    # 정상 결과 표시
    if not ai_result.get('success'):
        st.error("분석 실패")
        if ai_result.get('summary'):
            st.warning(ai_result['summary'])
        return
    
    # 메트릭 표시
    col1, col2, col3 = st.columns(3)
    
    with col1:
        score = ai_result.get('security_score', 100)
        if score >= 80:
            st.metric("🟢 보안 점수", f"{score}/100")
        elif score >= 60:
            st.metric("🟡 보안 점수", f"{score}/100")
        else:
            st.metric("🔴 보안 점수", f"{score}/100")
    
    with col2:
        vulns = len(ai_result.get('vulnerabilities', []))
        if vulns == 0:
            st.metric("✅ 발견된 취약점", vulns)
        else:
            st.metric("⚠️ 발견된 취약점", vulns)
    
    with col3:
        engine = ai_result.get('analyzed_by', 'AI')
        st.metric("🤖 분석 엔진", engine)
    
    # 요약
    st.info(ai_result.get('summary', ''))
    
    # 이하 취약점 상세 표시 코드...
    
    # 취약점 상세 표시
    vulnerabilities = ai_result.get('vulnerabilities', [])
    
    if vulnerabilities:
        st.subheader("🔍 발견된 취약점")
        
        for idx, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'MEDIUM')
            severity_icon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }.get(severity, '⚪')
            
            location = vuln.get('location', {})
            title = f"{severity_icon} [{idx}] {vuln.get('type', 'Unknown')}"
            if location.get('file'):
                title += f" - {location['file']}:{location.get('line', '?')}"
            
            with st.expander(title, expanded=(idx == 1)):  # 첫 번째 취약점은 펼쳐서 표시
                # 설명
                st.write("### 📋 설명")
                st.write(vuln.get('description', ''))
                
                # 취약한 코드와 수정 코드를 나란히 표시
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("#### ❌ 취약한 코드")
                    if vuln.get('vulnerable_code'):
                        st.code(vuln['vulnerable_code'], language='python')
                    else:
                        st.info("원본 코드를 표시할 수 없습니다")
                
                with col2:
                    st.write("#### ✅ 수정된 코드")
                    if vuln.get('fixed_code'):
                        st.code(vuln['fixed_code'], language='python')
                        
                        # 복사를 위한 텍스트 영역 표시
                        if st.button(f"📋 수정 코드 복사", key=f"copy_btn_{idx}"):
                            st.session_state[f'show_copy_{idx}'] = True
                        
                        # 복사용 텍스트 영역 표시
                        if st.session_state.get(f'show_copy_{idx}', False):
                            st.info("아래 코드를 전체 선택(Ctrl+A) 후 복사(Ctrl+C)하세요.")
                            st.text_area(
                                "복사할 코드:",
                                value=vuln['fixed_code'],
                                height=200,
                                key=f"copy_area_{idx}",
                                help="전체 선택: Ctrl+A, 복사: Ctrl+C"
                            )
                            st.success("수정된 코드를 확인해주세요!")
                            
                            # 닫기 버튼
                            if st.button("닫기", key=f"close_copy_{idx}"):
                                st.session_state[f'show_copy_{idx}'] = False
                                st.rerun()
                    else:
                        st.warning("수정 코드를 생성할 수 없습니다")
                
                # 수정 설명
                if vuln.get('fix_explanation'):
                    st.write("### 💡 수정 설명")
                    st.info(vuln['fix_explanation'])
                
                # 추가 정보들을 탭으로 구성
                tabs = st.tabs(["상세 정보", "공격 시나리오", "권장사항"])
                
                with tabs[0]:
                    # 위치 정보
                    if location:
                        st.write("**📍 위치 정보:**")
                        loc_col1, loc_col2, loc_col3 = st.columns(3)
                        with loc_col1:
                            st.caption(f"파일: {location.get('file', 'unknown')}")
                        with loc_col2:
                            st.caption(f"라인: {location.get('line', '?')}")
                        with loc_col3:
                            st.caption(f"함수: {location.get('function', 'unknown')}")
                        
                        if location.get('code_snippet'):
                            st.write("**📝 문제 코드:**")
                            st.code(location['code_snippet'], language='python')
                    
                    # 데이터 흐름
                    if vuln.get('data_flow'):
                        st.write("**🔄 데이터 흐름:**")
                        st.code(vuln['data_flow'], language='text')
                    
                    # 신뢰도
                    confidence = vuln.get('confidence', 'MEDIUM')
                    confidence_color = {
                        'HIGH': '🟢',
                        'MEDIUM': '🟡', 
                        'LOW': '🔴'
                    }.get(confidence, '⚪')
                    st.write(f"**신뢰도:** {confidence_color} {confidence}")
                    
                    # RAG 근거 (있는 경우)
                    if vuln.get('evidence'):
                        evidence = vuln['evidence']
                        st.write("**📚 가이드라인 근거:**")
                        with st.container():
                            st.success(f"**{evidence.get('source', 'KISIA 가이드라인')}**")
                            st.caption(evidence.get('content', '')[:500] + "...")
                            if evidence.get('page'):
                                st.caption(f"📄 페이지: {evidence['page']}")
                
                with tabs[1]:
                    if vuln.get('exploit_scenario'):
                        st.warning(vuln['exploit_scenario'])
                    else:
                        st.info("공격 시나리오 정보가 없습니다")
                
                with tabs[2]:
                    if vuln.get('recommendation'):
                        st.success(vuln['recommendation'])
                    
                    if vuln.get('additional_context'):
                        st.write("**추가 확인사항:**")
                        st.info(vuln['additional_context'])
                    
                    # 참고 링크 (있는 경우)
                    if vuln.get('references'):
                        st.write("**🔗 참고 자료:**")
                        for ref in vuln['references']:
                            st.markdown(f"- [{ref['title']}]({ref['url']})")
        
        # 전체 취약점 요약 통계
        st.divider()
        st.subheader("📊 취약점 통계")
        
        # 심각도별 통계
        severity_counts = {}
        for vuln in vulnerabilities:
            sev = vuln.get('severity', 'MEDIUM')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        cols = st.columns(4)
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
        
        for i, sev in enumerate(severity_order):
            with cols[i]:
                count = severity_counts.get(sev, 0)
                st.metric(f"{icons[sev]} {sev}", count)
        
        # 취약점 타입별 통계
        type_counts = {}
        for vuln in vulnerabilities:
            vtype = vuln.get('type', 'Unknown')
            type_counts[vtype] = type_counts.get(vtype, 0) + 1
        
        if type_counts:
            st.write("**취약점 유형별 분포:**")
            for vtype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                st.caption(f"• {vtype}: {count}개")
    
    else:
        # 취약점이 없는 경우
        st.success("🎉 축하합니다! 발견된 보안 취약점이 없습니다.")
        
        with st.expander("💡 추가 보안 권장사항"):
            st.write("""
            취약점이 발견되지 않았지만, 다음 사항들을 추가로 확인해보세요:
            
            1. **의존성 업데이트**: 사용 중인 패키지들이 최신 버전인지 확인
            2. **환경 변수**: 민감한 정보가 코드에 하드코딩되지 않았는지 확인
            3. **로깅**: 민감한 정보가 로그에 노출되지 않는지 확인
            4. **인증/인가**: 적절한 접근 제어가 구현되었는지 확인
            5. **입력 검증**: 모든 사용자 입력이 검증되는지 확인
            """)


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
    
    packages = sbom.get('packages', [])
    if packages:
        df_data = []
        for pkg in packages[:20]:
            df_data.append({
                "패키지": pkg.get('name', ''),
                "버전": pkg.get('version', '미확인'),
                "상태": pkg.get('status', '')
            })
        
        if df_data:
            df = pd.DataFrame(df_data)
            st.dataframe(df, use_container_width=True, hide_index=True)


def display_sbom_standards(sbom_formats: Dict):
    """SBOM 표준 형식 표시"""
    st.subheader("SBOM 표준 형식")
    
    tab1, tab2 = st.tabs(["SPDX 2.3", "CycloneDX 1.4"])
    
    with tab1:
        if sbom_formats.get('spdx'):
            st.info("SPDX (Software Package Data Exchange) - 라이선스 중심 표준")
            
            spdx = sbom_formats['spdx']
            
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
            
            with st.expander("📄 전체 JSON 보기"):
                st.json(spdx)
    
    with tab2:
        if sbom_formats.get('cyclonedx'):
            st.info("CycloneDX - 보안 중심 표준 (OWASP)")
            
            cyclone = sbom_formats['cyclonedx']
            
            col1, col2 = st.columns(2)
            with col1:
                st.write("**BOM 정보**")
                st.caption(f"- 형식: {cyclone.get('bomFormat', 'N/A')}")
                st.caption(f"- 스펙 버전: {cyclone.get('specVersion', 'N/A')}")
            
            with col2:
                st.write("**메타데이터**")
                metadata = cyclone.get('metadata', {})
                st.caption(f"- 타임스탬프: {metadata.get('timestamp', 'N/A')[:19]}")
            
            with st.expander("📄 전체 JSON 보기"):
                st.json(cyclone)


def display_download_options(results: Dict):
    """다운로드 옵션"""
    st.subheader("💾 다운로드")
    
    json_str = json.dumps(results, indent=2, default=str, ensure_ascii=False)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.download_button(
            "📥 전체 결과 (JSON)",
            data=json_str,
            file_name=f"analysis_{int(time.time())}.json",
            mime="application/json"
        )

        # AI 판단 설명 보고서 추가
        if 'ai_analysis' in results and results['ai_analysis'].get('vulnerabilities'):
            explanation_report = generate_ai_explanation_report(results)
            st.download_button(
                "📊 AI 판단 설명 보고서",
                data=explanation_report,
                file_name=f"ai_explanation_report_{int(time.time())}.md",
                mime="text/markdown",
                key=f"download_explanation_{int(time.time())}"  # unique_id 대신 timestamp 사용
            )
            
        if 'ai_analysis' in results:
            report = generate_security_report(results)
            st.download_button(
                "📄 보안 보고서 (Markdown)",
                data=report,
                file_name=f"security_report_{int(time.time())}.md",
                mime="text/markdown"
            )
    
    with col2:
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

def generate_ai_explanation_report(results: Dict) -> str:
    """AI 판단 근거 설명 보고서 생성"""
    report = []
    
    # 헤더
    report.append("# 🔍 AI 보안 판단 근거 보고서\n")
    report.append(f"**생성 시간**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    report.append(f"**분석 엔진**: {results['ai_analysis'].get('analyzed_by', 'AI')}\n")
    report.append("---\n")
    
    # 요약
    vulns = results['ai_analysis'].get('vulnerabilities', [])
    score = results['ai_analysis'].get('security_score', 100)
    
    report.append("## 📊 분석 요약\n")
    report.append(f"- **보안 점수**: {score}/100\n")
    report.append(f"- **발견된 취약점**: {len(vulns)}개\n")
    report.append(f"- **분석 시간**: {results.get('analysis_time', 0):.1f}초\n")
    report.append(f"- **분석 파일 수**: {results.get('analyzed_files', 0)}개\n\n")
    
    # 판단 프로세스 설명
    report.append("## 🔄 AI 판단 프로세스\n")
    report.append("```")
    report.append("1. 코드 패턴 분석 → 위험 패턴 탐지")
    report.append("2. LLM 추론 → 취약점 유형 분류 및 심각도 판단")
    report.append("3. RAG 검증 → KISIA 가이드라인 매칭")
    report.append("4. 신뢰도 산출 → 최종 판단")
    report.append("```\n")
    
    # 각 취약점별 상세 설명
    report.append("## 🚨 취약점별 판단 근거\n")
    
    for i, vuln in enumerate(vulns, 1):
        report.append(f"### {i}. {vuln.get('type', 'Unknown')}\n")
        
        # 기본 정보
        severity = vuln.get('severity', 'MEDIUM')
        confidence = vuln.get('confidence', 'MEDIUM')
        location = vuln.get('location', {})
        
        report.append(f"**심각도**: {severity} | **신뢰도**: {confidence}\n")
        report.append(f"**위치**: {location.get('file', 'unknown')}:{location.get('line', '?')}\n\n")
        
        # 판단 근거 섹션
        report.append("#### 📌 왜 이것이 취약점인가?\n")
        report.append(f"{vuln.get('description', '설명 없음')}\n\n")
        
        # 판단 과정
        report.append("#### 🔍 어떻게 판단했는가?\n")
        report.append("1. **패턴 분석**:\n")
        if vuln.get('vulnerable_code'):
            report.append(f"   - 탐지된 위험 코드: `{vuln['vulnerable_code'][:100]}...`\n")
        report.append(f"2. **AI 추론**:\n")
        if vuln.get('reasoning'):
            report.append(f"   - {vuln['reasoning']}\n")
        elif vuln.get('fix_explanation'):
            report.append(f"   - {vuln['fix_explanation']}\n")
        report.append(f"3. **취약점 분류**:\n")
        report.append(f"   - 타입: {vuln.get('type')}\n")
        report.append(f"   - 카테고리: {_get_vulnerability_category(vuln.get('type', ''))}\n")
        
        # 근거
        report.append("#### 📚 판단 근거\n")
        
        # 가이드라인 근거
        if vuln.get('evidence'):
            evidence = vuln['evidence']
            report.append("**공식 가이드라인**:\n")
            report.append(f"- 문서: {evidence.get('document', 'KISIA 가이드')}\n")
            report.append(f"- 페이지: {evidence.get('page', 'N/A')}\n")
            if evidence.get('content'):
                report.append(f"- 내용: {evidence['content'][:200]}...\n")
        else:
            report.append("- AI 자체 판단 (가이드라인 매칭 없음)\n")
        
        # 신뢰도 계산
        report.append("\n#### 📈 신뢰도 산출\n")
        confidence_score = _calculate_confidence_score(vuln)
        report.append(f"```\n{confidence_score['formula']}\n")
        report.append(f"최종 신뢰도: {confidence_score['score']}%\n```\n")
        
        # 공격 시나리오
        if vuln.get('exploit_scenario'):
            report.append("#### ⚠️ 공격 시나리오\n")
            report.append(f"{vuln['exploit_scenario']}\n\n")
        
        # 권장사항
        if vuln.get('recommendation'):
            report.append("#### ✅ 권장 조치\n")
            report.append(f"{vuln['recommendation']}\n\n")
        
        report.append("---\n")
    
    # 종합 판단
    report.append("## 📈 종합 판단\n")
    
    # 심각도 분포
    severity_dist = {}
    for vuln in vulns:
        sev = vuln.get('severity', 'MEDIUM')
        severity_dist[sev] = severity_dist.get(sev, 0) + 1
    
    report.append("### 심각도 분포\n")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if sev in severity_dist:
            bar = '█' * (severity_dist[sev] * 2)
            report.append(f"{sev:8} [{severity_dist[sev]:2}] {bar}\n")
    
    # 신뢰도 통계
    report.append("\n### 신뢰도 분석\n")
    high_conf = sum(1 for v in vulns if v.get('confidence') == 'HIGH')
    med_conf = sum(1 for v in vulns if v.get('confidence') == 'MEDIUM')
    low_conf = sum(1 for v in vulns if v.get('confidence') == 'LOW')
    
    report.append(f"- HIGH 신뢰도: {high_conf}개 ({high_conf/len(vulns)*100:.1f}%)\n")
    report.append(f"- MEDIUM 신뢰도: {med_conf}개 ({med_conf/len(vulns)*100:.1f}%)\n")
    report.append(f"- LOW 신뢰도: {low_conf}개 ({low_conf/len(vulns)*100:.1f}%)\n")
    
    # 판단 기준 설명
    report.append("\n## 📋 판단 기준 설명\n")
    report.append("### 심각도 기준\n")
    report.append("- **CRITICAL**: 즉시 시스템 침해 가능, 데이터 유출 위험\n")
    report.append("- **HIGH**: 인증 우회, 권한 상승 가능\n")
    report.append("- **MEDIUM**: 제한적 영향, 추가 조건 필요\n")
    report.append("- **LOW**: 미미한 영향, 정보 노출\n\n")
    
    report.append("### 신뢰도 기준\n")
    report.append("- **HIGH**: 명확한 취약점, 가이드라인 일치\n")
    report.append("- **MEDIUM**: 상황별 위험, 부분 일치\n")
    report.append("- **LOW**: 잠재적 위험, 추가 검증 필요\n")
    
    return ''.join(report)

def _get_vulnerability_category(vuln_type: str) -> str:
    """취약점 카테고리 분류"""
    categories = {
        'Injection': ['SQL', 'Command', 'LDAP', 'XPath', 'NoSQL', 'OS', 'OGNL'],
        'Authentication': ['Auth', 'Login', 'Session', 'Password', 'Token'],
        'Cryptography': ['Crypto', 'Hash', 'Encryption', 'Random'],
        'Configuration': ['Config', 'Debug', 'Setting', 'Permission'],
        'Input Validation': ['XSS', 'CSRF', 'Validation', 'Sanitization'],
    }
    
    vuln_type_lower = vuln_type.lower()
    for category, keywords in categories.items():
        for keyword in keywords:
            if keyword.lower() in vuln_type_lower:
                return category
    
    return '기타'

def _calculate_confidence_score(vuln: Dict) -> Dict:
    """신뢰도 점수 계산 및 공식 반환"""
    score = 0
    factors = []
    
    # 1. 기본 신뢰도 (30%)
    base_confidence = vuln.get('confidence', 'MEDIUM')
    if base_confidence == 'HIGH':
        score += 30
        factors.append("기본 신뢰도(HIGH): 30%")
    elif base_confidence == 'MEDIUM':
        score += 20
        factors.append("기본 신뢰도(MEDIUM): 20%")
    else:
        score += 10
        factors.append("기본 신뢰도(LOW): 10%")
    
    # 2. 코드 패턴 매칭 (30%)
    if vuln.get('vulnerable_code'):
        score += 30
        factors.append("코드 패턴 매칭: 30%")
    
    # 3. 가이드라인 근거 (40%)
    if vuln.get('evidence'):
        score += 40
        factors.append("가이드라인 근거: 40%")
    elif vuln.get('reasoning'):
        score += 20
        factors.append("AI 추론 근거: 20%")
    
    formula = " + ".join(factors)
    
    return {
        'score': min(score, 100),
        'formula': formula
    }