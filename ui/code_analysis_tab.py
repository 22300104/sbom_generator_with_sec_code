"""
개선된 통합 코드 분석 탭 - 취약점 예제 추가, 제한 해제, 스마트 필터링
"""
import streamlit as st
import json
import pandas as pd
import os
import time
import tempfile
from pathlib import Path
from typing import Dict, Optional, List

from core.analyzer import SBOMAnalyzer
from core.formatter import SBOMFormatter
from core.project_downloader import ProjectDownloader
from security.vulnerability import check_vulnerabilities_enhanced

# LLM 분석기는 조건부 임포트
try:
    from core.llm_analyzer import LLMSecurityAnalyzer
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    print("Warning: LLMSecurityAnalyzer not available")


def render_code_analysis_tab():
    """통합 코드 분석 탭"""
    st.header("🔍 보안 분석")
    
    # 세션 상태 초기화
    if 'input_method' not in st.session_state:
        st.session_state.input_method = "📝 코드 직접 입력"
    if 'analysis_code' not in st.session_state:
        st.session_state.analysis_code = None
    if 'analysis_requirements' not in st.session_state:
        st.session_state.analysis_requirements = ""
    if 'analysis_project_name' not in st.session_state:
        st.session_state.analysis_project_name = "MyProject"
    
    # 입력 방법 선택
    input_method = st.radio(
        "입력 방법 선택:",
        ["📝 코드 직접 입력", "🔗 GitHub URL", "📦 파일 업로드"],
        horizontal=True,
        key="input_method_radio",
        index=["📝 코드 직접 입력", "🔗 GitHub URL", "📦 파일 업로드"].index(st.session_state.input_method)
    )
    
    # 입력 방법이 변경되었는지 확인
    if input_method != st.session_state.input_method:
        st.session_state.input_method = input_method
    
    # 각 입력 방법에 따른 처리
    code_to_analyze = None
    requirements = ""
    project_name = "MyProject"
    
    if input_method == "📝 코드 직접 입력":
        code_to_analyze, requirements, project_name = handle_direct_input()
        
    elif input_method == "🔗 GitHub URL":
        code_to_analyze, requirements, project_name = handle_github_input()
        
    elif input_method == "📦 파일 업로드":
        code_to_analyze, requirements, project_name = handle_file_upload()
    
    # 새로운 코드가 있으면 세션에 저장
    if code_to_analyze:
        st.session_state.analysis_code = code_to_analyze
        st.session_state.analysis_requirements = requirements
        st.session_state.analysis_project_name = project_name
    
    # 저장된 코드가 있으면 분석 옵션 표시
    if st.session_state.analysis_code:
        st.divider()
        analyze_code_common(
            st.session_state.analysis_code,
            st.session_state.analysis_requirements,
            st.session_state.analysis_project_name
        )


def handle_direct_input():
    """직접 코드 입력 처리"""
    col1, col2 = st.columns([1, 1])
    
    # 세션 상태에서 이전 값 가져오기
    if 'direct_code' not in st.session_state:
        st.session_state.direct_code = ""
    if 'direct_requirements' not in st.session_state:
        st.session_state.direct_requirements = ""
    
    with col1:
        st.subheader("Python 코드")
        
        # 예제 선택
        example = st.selectbox(
            "예제:",
            ["직접 입력", "취약한 코드", "안전한 코드", "웹 애플리케이션 취약점"],
            key="example_selector"
        )
        
        # 예제 선택시 코드 변경
        if example == "취약한 코드":
            if st.button("예제 로드", key="load_vulnerable"):
                st.session_state.direct_code = get_vulnerable_example()
        elif example == "안전한 코드":
            if st.button("예제 로드", key="load_safe"):
                st.session_state.direct_code = get_safe_example()
        elif example == "웹 애플리케이션 취약점":
            if st.button("예제 로드", key="load_web_vulns"):
                st.session_state.direct_code = get_web_vulnerable_example()
        
        code = st.text_area(
            "코드 입력:",
            height=400,
            value=st.session_state.direct_code,
            placeholder="Python 코드를 입력하세요...",
            key="code_input_area"
        )
        
        # 코드가 변경되면 세션에 저장
        if code != st.session_state.direct_code:
            st.session_state.direct_code = code
    
    with col2:
        st.subheader("requirements.txt (선택)")
        requirements = st.text_area(
            "패키지 정보:",
            height=400,
            value=st.session_state.direct_requirements,
            placeholder="pandas==2.0.0\nnumpy>=1.24.0\n...",
            key="req_input_area"
        )
        
        # requirements가 변경되면 세션에 저장
        if requirements != st.session_state.direct_requirements:
            st.session_state.direct_requirements = requirements
    
    return code, requirements, "DirectInput"


def handle_github_input():
    """GitHub URL 입력 처리 - 취약점 예제 추가"""
    st.subheader("GitHub 저장소 분석")
    
    # 세션 상태 초기화
    if 'github_url_input' not in st.session_state:
        st.session_state.github_url_input = ""
    if 'github_result' not in st.session_state:
        st.session_state.github_result = None
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        github_url = st.text_input(
            "저장소 URL:",
            value=st.session_state.github_url_input,
            placeholder="https://github.com/owner/repository",
            key="github_url_field"
        )
        
        # URL이 변경되면 저장
        if github_url != st.session_state.github_url_input:
            st.session_state.github_url_input = github_url
    
    with col2:
        st.write("")  # 여백
        st.write("")  # 여백
        download_btn = st.button("📥 다운로드", type="primary", key="github_download_btn")
    
    # 예제 URL - 취약점이 많은 프로젝트 추가
    with st.expander("📌 예제 저장소"):
        st.write("**🟢 일반 프로젝트:**")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Flask 예제", key="flask_example"):
                st.session_state.github_url_input = "https://github.com/pallets/flask"
                st.rerun()
            if st.button("FastAPI 예제", key="fastapi_example"):
                st.session_state.github_url_input = "https://github.com/tiangolo/fastapi"
                st.rerun()
        with col2:
            if st.button("Django 프로젝트", key="django_example"):
                st.session_state.github_url_input = "https://github.com/django/django"
                st.rerun()
            if st.button("Streamlit 예제", key="streamlit_example"):
                st.session_state.github_url_input = "https://github.com/streamlit/streamlit"
                st.rerun()
        
        st.write("**🔴 취약점 데모 프로젝트:**")
        col3, col4 = st.columns(2)
        with col3:
            if st.button("OWASP WebGoat Python", key="webgoat_example"):
                st.session_state.github_url_input = "https://github.com/OWASP/WebGoat-Python"
                st.rerun()
            if st.button("DVPWA (취약한 Python 웹앱)", key="dvpwa_example"):
                st.session_state.github_url_input = "https://github.com/anxolerd/dvpwa"
                st.rerun()
        with col4:
            if st.button("SecLists (보안 테스트)", key="seclists_example"):
                st.session_state.github_url_input = "https://github.com/danielmiessler/SecLists"
                st.rerun()
            if st.button("Python Security 예제", key="python_security_example"):
                st.session_state.github_url_input = "https://github.com/OWASP/Python-Security"
                st.rerun()
        
        st.write("**⚡ 소규모 취약점 데모:**")
        col5, col6 = st.columns(2)
        with col5:
            if st.button("SQL Injection 데모", key="sqli_demo"):
                st.session_state.github_url_input = "https://github.com/sqlmapproject/testenv"
                st.rerun()
            if st.button("XSS 데모", key="xss_demo"):
                st.session_state.github_url_input = "https://github.com/cure53/XSSChallengeWiki"
                st.rerun()
        with col6:
            if st.button("취약한 Flask 앱", key="vulnerable_flask"):
                st.session_state.github_url_input = "https://github.com/we45/Vulnerable-Flask-App"
                st.rerun()
            if st.button("Python 악성코드 샘플", key="malware_sample"):
                st.session_state.github_url_input = "https://github.com/rshipp/awesome-malware-analysis"
                st.rerun()
    
    # 다운로드 처리
    if download_btn and st.session_state.github_url_input:
        downloader = ProjectDownloader()
        
        with st.spinner("🔄 GitHub 저장소 다운로드 중..."):
            success, message, project_path = downloader.download_github(st.session_state.github_url_input)
        
        if success:
            st.success(f"✅ {message}")
            
            # 프로젝트 파일 분석 - 스마트 필터링 적용
            with st.spinner("📂 프로젝트 파일 분석 중..."):
                project_data = smart_analyze_project_files(downloader, Path(project_path))
            
            # 정보 표시
            with st.expander("📊 프로젝트 정보", expanded=True):
                display_project_stats(project_data)
            
            # 정리
            downloader.cleanup()
            
            # 프로젝트 이름 추출
            project_name = st.session_state.github_url_input.split('/')[-1].replace('.git', '')
            
            # 결과 저장
            st.session_state.github_result = (
                project_data['combined_code'],
                project_data['combined_requirements'],
                project_name
            )
            
            return project_data['combined_code'], project_data['combined_requirements'], project_name
        else:
            st.error(f"❌ {message}")
    
    # 이전 결과가 있으면 반환
    if st.session_state.github_result:
        return st.session_state.github_result
    
    return None, None, None


def smart_analyze_project_files(downloader: ProjectDownloader, project_path: Path) -> Dict:
    """스마트한 프로젝트 파일 분석 - 실제 사용자 코드만 분석"""
    
    # 제외할 경로 패턴 (더 상세하게)
    EXCLUDE_PATTERNS = [
        'venv', 'env', '.venv', '.env',  # 가상환경
        '__pycache__', '.pyc', '.pyo',   # 캐시
        '.git', '.gitignore',            # Git
        'node_modules', 'bower_components',  # JS 의존성
        'dist', 'build', '.build',       # 빌드 결과물
        'migrations',                    # Django 마이그레이션
        'tests', 'test_', '_test',       # 테스트 파일
        'docs', 'documentation',         # 문서
        'examples', 'example',           # 예제 (프레임워크의 예제)
        'vendor', 'third_party',         # 서드파티
        '.tox', '.pytest_cache',         # 테스트 도구
        'site-packages',                 # 설치된 패키지
        'templates/admin',               # Django admin 템플릿
        'static/admin',                  # Django admin static
        '.coverage', 'htmlcov',          # 커버리지 도구
    ]
    
    # 우선순위 파일 (중요한 사용자 코드)
    PRIORITY_FILES = [
        'main.py', 'app.py', 'manage.py', 'wsgi.py', 'asgi.py',
        'views.py', 'models.py', 'forms.py', 'urls.py', 'settings.py',
        'api.py', 'routes.py', 'handlers.py', 'controllers.py',
        'tasks.py', 'celery.py', 'worker.py',
        'auth.py', 'authentication.py', 'permissions.py',
        'serializers.py', 'schemas.py', 'validators.py',
    ]
    
    # 사용자 작성 코드 패턴
    USER_CODE_PATTERNS = [
        'app/', 'src/', 'project/', 'web/', 'api/', 'core/',
        'backend/', 'frontend/', 'server/', 'client/',
        'services/', 'utils/', 'helpers/', 'lib/', 'common/',
    ]
    
    result = {
        'files': [],
        'combined_code': '',
        'combined_requirements': '',
        'statistics': {
            'total_files': 0,
            'analyzed_files': 0,
            'skipped_files': 0,
            'excluded_files': 0,
            'total_lines': 0,
            'user_code_lines': 0,
        }
    }
    
    # requirements 파일들 읽기
    req_contents = []
    for req_file in ['requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt', 'Pipfile', 'pyproject.toml']:
        req_path = project_path / req_file
        if req_path.exists():
            try:
                with open(req_path, 'r', encoding='utf-8', errors='ignore') as f:
                    if req_file == 'Pipfile':
                        req_contents.append(downloader._parse_pipfile(f.read()))
                    elif req_file == 'pyproject.toml':
                        req_contents.append(downloader._parse_pyproject(f.read()))
                    else:
                        req_contents.append(f.read())
            except:
                pass
    
    result['combined_requirements'] = '\n'.join(req_contents)
    
    # Python 파일 수집
    all_py_files = list(project_path.rglob('*.py'))
    result['statistics']['total_files'] = len(all_py_files)
    
    # 파일 분류
    priority_files = []
    user_code_files = []
    other_files = []
    
    for py_file in all_py_files:
        try:
            rel_path = py_file.relative_to(project_path)
            rel_path_str = str(rel_path).lower()
            
            # 제외 패턴 체크
            if any(pattern in rel_path_str for pattern in EXCLUDE_PATTERNS):
                result['statistics']['excluded_files'] += 1
                continue
            
            # 우선순위 파일
            if py_file.name in PRIORITY_FILES:
                priority_files.append(py_file)
            # 사용자 코드 경로
            elif any(pattern in rel_path_str for pattern in USER_CODE_PATTERNS):
                user_code_files.append(py_file)
            # 루트 레벨의 Python 파일 (보통 중요함)
            elif '/' not in rel_path_str:
                priority_files.append(py_file)
            else:
                other_files.append(py_file)
                
        except Exception:
            result['statistics']['skipped_files'] += 1
            continue
    
    # 분석할 파일 선정 (제한 없음, 하지만 우선순위 적용)
    files_to_analyze = []
    
    # 1. 우선순위 파일 (모두 포함)
    files_to_analyze.extend(priority_files)
    
    # 2. 사용자 코드 파일들
    files_to_analyze.extend(user_code_files)
    
    # 3. 기타 파일들 (크기가 너무 크지 않은 것들만)
    for f in other_files:
        try:
            if f.stat().st_size < 1024 * 1024:  # 1MB 이하만
                files_to_analyze.append(f)
        except:
            continue
    
    # 파일 크기별 정렬 (작은 파일 우선)
    files_to_analyze.sort(key=lambda x: x.stat().st_size if x.exists() else 0)
    
    # 코드 결합
    all_code = []
    
    for py_file in files_to_analyze:
        try:
            with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
                
                # 빈 파일이나 너무 작은 파일 스킵
                if len(code.strip()) < 50:
                    continue
                
                rel_path = py_file.relative_to(project_path)
                
                # 파일 정보 저장
                result['files'].append({
                    'path': str(rel_path),
                    'name': py_file.name,
                    'lines': len(code.splitlines()),
                    'size': py_file.stat().st_size,
                    'category': get_file_category(py_file, rel_path)
                })
                
                # 코드 결합 (파일 구분자 포함)
                all_code.append(f"# ===== File: {rel_path} =====\n{code}\n")
                
                result['statistics']['analyzed_files'] += 1
                result['statistics']['total_lines'] += len(code.splitlines())
                
                # 사용자 코드인지 확인
                if is_user_code(py_file, rel_path):
                    result['statistics']['user_code_lines'] += len(code.splitlines())
                
        except Exception as e:
            result['statistics']['skipped_files'] += 1
            continue
    
    result['combined_code'] = '\n'.join(all_code)
    
    return result


def get_file_category(py_file: Path, rel_path: Path) -> str:
    """파일 카테고리 판정"""
    rel_path_str = str(rel_path).lower()
    file_name = py_file.name.lower()
    
    if file_name in ['main.py', 'app.py', 'manage.py']:
        return 'entry_point'
    elif file_name in ['views.py', 'models.py', 'forms.py', 'urls.py']:
        return 'core_logic'
    elif 'auth' in file_name or 'permission' in file_name:
        return 'security'
    elif 'api' in rel_path_str or 'routes' in file_name:
        return 'api'
    elif 'utils' in rel_path_str or 'helper' in rel_path_str:
        return 'utility'
    elif 'test' in file_name:
        return 'test'
    else:
        return 'other'


def is_user_code(py_file: Path, rel_path: Path) -> bool:
    """사용자가 작성한 코드인지 판단"""
    rel_path_str = str(rel_path).lower()
    
    # 명확한 사용자 코드 패턴
    user_patterns = ['app/', 'src/', 'views.py', 'models.py', 'main.py', 'api/']
    
    # 명확한 시스템/라이브러리 코드 패턴
    system_patterns = ['site-packages/', 'venv/', 'migrations/', 'admin/']
    
    for pattern in system_patterns:
        if pattern in rel_path_str:
            return False
    
    for pattern in user_patterns:
        if pattern in rel_path_str:
            return True
    
    # 루트 레벨의 .py 파일은 대부분 사용자 코드
    if '/' not in rel_path_str:
        return True
    
    return False


def display_project_stats(project_data: Dict):
    """프로젝트 통계 표시"""
    stats = project_data['statistics']
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("총 Python 파일", stats['total_files'])
    with col2:
        st.metric("분석 대상", stats['analyzed_files'])
    with col3:
        st.metric("총 라인", f"{stats['total_lines']:,}")
    with col4:
        st.metric("사용자 코드 라인", f"{stats['user_code_lines']:,}")
    
    # 파일 분포
    if project_data['files']:
        st.write("**파일 분석 결과:**")
        
        # 카테고리별 통계
        categories = {}
        for file_info in project_data['files']:
            cat = file_info['category']
            if cat not in categories:
                categories[cat] = {'count': 0, 'lines': 0}
            categories[cat]['count'] += 1
            categories[cat]['lines'] += file_info['lines']
        
        category_names = {
            'entry_point': '🚀 진입점',
            'core_logic': '🧠 핵심 로직',
            'security': '🔒 보안',
            'api': '🌐 API',
            'utility': '🔧 유틸리티',
            'test': '🧪 테스트',
            'other': '📄 기타'
        }
        
        for cat, stats in categories.items():
            cat_name = category_names.get(cat, cat)
            st.write(f"  • {cat_name}: {stats['count']}개 파일, {stats['lines']:,}줄")


def handle_file_upload():
    """파일 업로드 처리"""
    st.subheader("파일 업로드")
    
    # 세션 상태 초기화
    if 'file_result' not in st.session_state:
        st.session_state.file_result = None
    
    file_type = st.radio(
        "파일 종류:",
        ["Python 파일 (.py)", "압축 파일 (.zip, .tar.gz)"],
        horizontal=True,
        key="file_type_radio"
    )
    
    if file_type == "Python 파일 (.py)":
        uploaded_files = st.file_uploader(
            "Python 파일 선택:",
            type=['py'],
            accept_multiple_files=True,
            key="py_file_uploader"
        )
        
        if uploaded_files:
            all_code = []
            requirements = ""
            
            for file in uploaded_files:
                content = file.read().decode('utf-8')
                all_code.append(f"# ===== File: {file.name} =====\n{content}\n")
            
            combined_code = '\n'.join(all_code)
            st.success(f"✅ {len(uploaded_files)}개 파일 로드 완료")
            
            # 결과 저장
            st.session_state.file_result = (combined_code, requirements, "UploadedFiles")
            return combined_code, requirements, "UploadedFiles"
    
    else:  # 압축 파일
        uploaded_file = st.file_uploader(
            "압축 파일 선택:",
            type=['zip', 'tar', 'gz', 'bz2'],
            key="archive_uploader"
        )
        
        if uploaded_file:
            # 임시 파일로 저장
            with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded_file.name).suffix) as tmp:
                tmp.write(uploaded_file.getbuffer())
                tmp_path = tmp.name
            
            downloader = ProjectDownloader()
            
            with st.spinner("📦 압축 파일 추출 중..."):
                success, message, project_path = downloader.extract_archive(tmp_path)
            
            # 임시 파일 삭제
            try:
                os.unlink(tmp_path)
            except:
                pass
            
            if success:
                st.success(f"✅ {message}")
                
                # 스마트 프로젝트 분석
                with st.spinner("📂 파일 분석 중..."):
                    project_data = smart_analyze_project_files(downloader, Path(project_path))
                
                # 정보 표시
                with st.expander("📊 프로젝트 정보", expanded=True):
                    display_project_stats(project_data)
                
                # 정리
                downloader.cleanup()
                
                # 결과 저장
                result = (project_data['combined_code'], project_data['combined_requirements'], uploaded_file.name)
                st.session_state.file_result = result
                return result
            else:
                st.error(f"❌ {message}")
    
    # 이전 결과가 있으면 반환
    if st.session_state.file_result:
        return st.session_state.file_result
    
    return None, None, None


def analyze_code_common(code: str, requirements: str, project_name: str):
    """공통 분석 로직 - 제한 해제"""
    
    # 코드 정보
    lines = len(code.splitlines())
    chars = len(code)
    
    st.info(f"""
    📊 **분석 대상**
    - 프로젝트: {project_name}
    - 코드 크기: {chars:,}자 ({chars/1024:.1f}KB)
    - 라인 수: {lines:,}줄
    """)
    
    # 분석 옵션
    st.subheader("⚙️ 분석 옵션")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        analysis_mode = st.selectbox(
            "분석 모드:",
            ["⚡ 빠른 분석", "🤖 AI 보안 분석", "🔥 전체 분석"],
            key="analysis_mode_select"
        )
    
    with col2:
        scan_env = st.checkbox("🔍 환경 스캔", value=False, key="scan_env_check")
    
    with col3:
        # 코드 크기 제한 옵션 (기본값을 훨씬 크게)
        if chars > 500000:  # 500KB 이상일 때만 제한 옵션 표시
            st.warning(f"⚠️ 코드가 매우 큽니다 ({chars/1024:.1f}KB)")
            use_limit = st.checkbox("크기 제한 적용", value=False, key="use_code_limit")
            if use_limit:
                max_code_size = st.number_input(
                    "최대 분석 크기 (KB):", 
                    100, 
                    2000, 
                    500,
                    key="max_code_size_input"
                ) * 1024
            else:
                max_code_size = None
        else:
            max_code_size = None
            st.success(f"✅ 크기 제한 없음")
    
    # 분석 버튼
    if st.button("🚀 분석 시작", type="primary", use_container_width=True, key="start_analysis_btn"):
        # 코드 크기 조정 (선택적)
        original_size = len(code)
        if max_code_size and len(code) > max_code_size:
            st.warning(f"⚠️ 코드가 제한 크기를 초과하여 {max_code_size/1024:.0f}KB만 분석합니다.")
            code = code[:max_code_size]
        
        # 분석 실행
        run_analysis(code, requirements, project_name, analysis_mode, scan_env, original_size)
    
    # 이전 분석 결과가 있으면 표시
    if 'last_analysis_results' in st.session_state:
        st.divider()
        st.subheader("📊 이전 분석 결과")
        display_results(st.session_state.last_analysis_results)


def run_analysis(code: str, requirements: str, project_name: str, mode: str, scan_env: bool, original_size: int):
    """실제 분석 실행"""
    
    # 초기화
    analyzer = SBOMAnalyzer()
    formatter = SBOMFormatter()
    llm_analyzer = None
    
    # LLM 분석기 초기화
    if mode in ["🤖 AI 보안 분석", "🔥 전체 분석"]:
        if os.getenv("OPENAI_API_KEY") and LLM_AVAILABLE:
            try:
                llm_analyzer = LLMSecurityAnalyzer()
            except Exception as e:
                st.warning(f"⚠️ AI 분석기 초기화 실패: {e}")
    
    results = {}
    start_time = time.time()
    
    # Progress
    progress = st.progress(0)
    status = st.empty()
    
    try:
        # 1. SBOM 분석
        if mode in ["⚡ 빠른 분석", "🔥 전체 분석"]:
            status.text("📦 SBOM 분석 중...")
            progress.progress(30)
            
            sbom_result = analyzer.analyze(code, requirements, scan_environment=scan_env)
            
            if sbom_result.get("success"):
                results['sbom'] = sbom_result
                
                # SBOM 표준 형식 생성
                if sbom_result.get('packages'):
                    results['sbom_formats'] = {
                        'spdx': formatter.to_spdx(sbom_result['packages'], {'project_name': project_name}),
                        'cyclonedx': formatter.to_cyclonedx(sbom_result['packages'], {'project_name': project_name})
                    }
            
            progress.progress(50)
        
        # 2. 취약점 검사
        if mode == "🔥 전체 분석" and results.get('sbom'):
            status.text("🛡️ 취약점 검사 중...")
            progress.progress(70)
            
            packages = results['sbom'].get('packages', [])
            indirect = results['sbom'].get('indirect_dependencies', [])
            
            if packages:
                vuln_result = check_vulnerabilities_enhanced(packages, indirect, results['sbom'])
                results['vulnerability_scan'] = vuln_result
            
            progress.progress(85)
        
        # 3. AI 보안 분석
        if mode in ["🤖 AI 보안 분석", "🔥 전체 분석"] and llm_analyzer:
            status.text("🤖 AI 보안 분석 중...")
            progress.progress(95)
            
            # 대용량 코드 처리
            if len(code) > 100000:  # 100KB 이상
                status.text("🤖 대용량 코드 분할 분석 중...")
                ai_result = analyze_large_code_with_llm(llm_analyzer, code)
            else:
                ai_result = llm_analyzer.analyze_code_security(code)
            
            results['ai_analysis'] = ai_result
        
        progress.progress(100)
        status.text("✅ 분석 완료!")
        
    except Exception as e:
        st.error(f"❌ 분석 오류: {e}")
    
    finally:
        progress.empty()
        status.empty()
    
    results['analysis_time'] = time.time() - start_time
    results['project_name'] = project_name
    results['original_code_size'] = original_size
    results['analyzed_code_size'] = len(code)
    
    # 결과를 세션에 저장
    st.session_state.last_analysis_results = results
    
    # 결과 표시
    display_results(results)


def analyze_large_code_with_llm(llm_analyzer, code: str) -> Dict:
    """대용량 코드를 청크별로 나누어 분석"""
    
    # 파일별로 분할
    file_chunks = code.split('# ===== File:')
    
    all_vulnerabilities = []
    important_files = []
    
    # 중요한 파일 우선 분석
    priority_patterns = ['main.py', 'app.py', 'views.py', 'models.py', 'auth', 'api', 'security']
    
    for chunk in file_chunks[1:]:  # 첫 번째는 빈 청크
        if not chunk.strip():
            continue
            
        lines = chunk.split('\n')
        file_path = lines[0].strip().replace('=====', '').strip()
        file_code = '\n'.join(lines[1:])
        
        # 중요한 파일인지 확인
        is_important = any(pattern in file_path.lower() for pattern in priority_patterns)
        
        if is_important or len(important_files) < 5:  # 최대 5개 중요 파일
            important_files.append({
                'path': file_path,
                'code': file_code[:50000],  # 파일당 50KB 제한
                'size': len(file_code)
            })
    
    # 중요한 파일들 분석
    for file_info in important_files:
        try:
            result = llm_analyzer.analyze_code_security(
                f"# File: {file_info['path']}\n{file_info['code']}"
            )
            
            if result.get('success'):
                vulns = result['analysis'].get('code_vulnerabilities', [])
                for vuln in vulns:
                    vuln['source_file'] = file_info['path']  # 파일 정보 추가
                    all_vulnerabilities.append(vuln)
                    
        except Exception as e:
            st.warning(f"⚠️ {file_info['path']} 분석 실패: {e}")
            continue
    
    # 결과 통합
    if all_vulnerabilities:
        security_score = _compute_security_score_from_vulns(all_vulnerabilities)
        summary = f"대용량 프로젝트에서 {len(all_vulnerabilities)}개 취약점 발견"
    else:
        security_score = 100
        summary = "대용량 프로젝트 분석 완료 - 주요 취약점 없음"
    
    return {
        'success': True,
        'analysis': {
            'code_vulnerabilities': all_vulnerabilities,
            'security_score': security_score,
            'summary': summary,
            'immediate_actions': generate_actions_from_vulns(all_vulnerabilities),
            'best_practices': generate_practices_from_vulns(all_vulnerabilities),
            'analyzed_files': [f['path'] for f in important_files]
        },
        'metadata': {
            'analysis_type': 'large_code_chunked',
            'total_files_analyzed': len(important_files),
            'total_vulnerabilities': len(all_vulnerabilities)
        }
    }


def generate_actions_from_vulns(vulns: List[Dict]) -> List[str]:
    """취약점에서 즉시 조치사항 생성"""
    actions = []
    critical_vulns = [v for v in vulns if v.get('severity') == 'CRITICAL']
    high_vulns = [v for v in vulns if v.get('severity') == 'HIGH']
    
    for vuln in critical_vulns[:3]:
        file_info = f" ({vuln.get('source_file', '')})" if vuln.get('source_file') else ""
        actions.append(f"🔴 {vuln['type']} 즉시 수정 필요{file_info}")
    
    for vuln in high_vulns[:2]:
        file_info = f" ({vuln.get('source_file', '')})" if vuln.get('source_file') else ""
        actions.append(f"🟠 {vuln['type']} 우선 수정{file_info}")
    
    return actions


def generate_practices_from_vulns(vulns: List[Dict]) -> List[str]:
    """취약점에서 모범 사례 생성"""
    practices = set()
    
    for vuln in vulns:
        vuln_type = vuln.get('type', '')
        if 'SQL' in vuln_type or 'Injection' in vuln_type:
            practices.add("모든 데이터베이스 쿼리에 파라미터 바인딩 사용")
        elif 'XSS' in vuln_type:
            practices.add("모든 사용자 입력에 대한 출력 이스케이프 적용")
        elif 'Secret' in vuln_type or 'Password' in vuln_type:
            practices.add("민감한 정보는 환경 변수나 보안 저장소 사용")
        elif 'Crypto' in vuln_type:
            practices.add("강력한 암호화 알고리즘과 충분한 키 길이 사용")
    
    if not practices:
        practices = {"정기적인 보안 코드 리뷰 실시", "의존성 패키지 정기 업데이트"}
    
    return list(practices)


def _compute_security_score_from_vulns(vulns: List[Dict]) -> int:
    """ImprovedSecurityAnalyzer와 동일한 완화 규칙으로 점수 계산"""
    if not vulns:
        return 100
    score = 100
    for v in vulns:
        sev = v.get('severity', 'MEDIUM')
        conf = v.get('confidence', 'MEDIUM')
        severity_penalty = {
            'CRITICAL': 24,
            'HIGH': 14,
            'MEDIUM': 6,
            'LOW': 2
        }.get(sev, 6)
        confidence_weight = {
            'HIGH': 1.0,
            'MEDIUM': 0.7,
            'LOW': 0.4
        }.get(conf, 0.7)
        score -= int(severity_penalty * confidence_weight)
    return max(0, score)


def display_results(results: Dict):
    """분석 결과 표시 - 개선된 버전"""
    
    if not results:
        return
    
    # 고유 ID 생성 (중복 방지)
    import hashlib
    import time
    result_id = hashlib.md5(f"{results.get('project_name', '')}{time.time()}".encode()).hexdigest()[:8]
    
    # 요약
    analysis_time = results.get('analysis_time', 0)
    original_size = results.get('original_code_size', 0)
    analyzed_size = results.get('analyzed_code_size', 0)
    
    if original_size > analyzed_size:
        size_info = f"({analyzed_size/1024:.1f}KB / {original_size/1024:.1f}KB 분석)"
    else:
        size_info = f"({analyzed_size/1024:.1f}KB 분석)"
    
    st.success(f"✅ 분석 완료 ({analysis_time:.1f}초) {size_info}")
    
    # 메트릭
    col1, col2, col3, col4 = st.columns(4)
    
    if 'sbom' in results:
        sbom = results['sbom']
        with col1:
            st.metric("외부 패키지", sbom['summary'].get('external_packages', 0))
        with col2:
            st.metric("버전 확인", sbom['summary'].get('with_version', 0))
    
    if 'ai_analysis' in results and results['ai_analysis'].get('success'):
        analysis = results['ai_analysis']['analysis']
        with col3:
            st.metric("보안 점수", f"{analysis.get('security_score', 100)}/100")
        with col4:
            vulns = len(analysis.get('code_vulnerabilities', []))
            st.metric("취약점", vulns)
    
    # 상세 결과 탭
    tabs = []
    if 'sbom' in results:
        tabs.append("📦 SBOM")
    if 'ai_analysis' in results:
        tabs.append("🤖 보안 분석")
    if 'vulnerability_scan' in results:
        tabs.append("🛡️ 취약점")
    tabs.append("💾 다운로드")
    
    # 탭에 고유 키 추가
    tab_objects = st.tabs(tabs)
    tab_idx = 0
    
    # SBOM 탭
    if 'sbom' in results:
        with tab_objects[tab_idx]:
            display_sbom_tab(results['sbom'])
        tab_idx += 1
    
    # AI 분석 탭
    if 'ai_analysis' in results:
        with tab_objects[tab_idx]:
            display_ai_tab_improved(results['ai_analysis'])
        tab_idx += 1
    
    # 취약점 탭
    if 'vulnerability_scan' in results:
        with tab_objects[tab_idx]:
            display_vuln_tab(results['vulnerability_scan'])
        tab_idx += 1
    
    # 다운로드 탭 - 고유 ID 전달
    with tab_objects[tab_idx]:
        display_download_tab_with_id(results, result_id)


def display_ai_tab_improved(ai_result):
    """개선된 AI 분석 결과 표시"""
    if not ai_result.get('success'):
        st.error("분석 실패")
        return
    
    analysis = ai_result['analysis']
    vulns = analysis.get('code_vulnerabilities', [])
    
    # 분석 타입 표시
    if ai_result.get('metadata', {}).get('analysis_type') == 'large_code_chunked':
        st.info("📊 대용량 코드 분할 분석 완료")
        analyzed_files = analysis.get('analyzed_files', [])
        if analyzed_files:
            with st.expander("분석된 주요 파일"):
                for file_path in analyzed_files:
                    st.write(f"• {file_path}")
    
    if not vulns:
        st.success("✅ 취약점이 발견되지 않았습니다!")
        return
    
    st.subheader(f"🤖 {len(vulns)}개 취약점 발견")
    
    # 심각도별 통계
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for vuln in vulns:
        sev = vuln.get('severity', 'MEDIUM')
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🔴 CRITICAL", severity_counts['CRITICAL'])
    with col2:
        st.metric("🟠 HIGH", severity_counts['HIGH'])
    with col3:
        st.metric("🟡 MEDIUM", severity_counts['MEDIUM'])
    with col4:
        st.metric("🟢 LOW", severity_counts['LOW'])
    
    # 취약점 상세 표시
    for vuln in vulns:
        severity_icon = {
            'CRITICAL': '🔴', 'HIGH': '🟠',
            'MEDIUM': '🟡', 'LOW': '🟢'
        }.get(vuln.get('severity', 'MEDIUM'), '⚪')
        
        # 제목에 파일 정보 포함
        title = f"{severity_icon} {vuln['type']}"
        if vuln.get('line_numbers'):
            title += f" (라인 {vuln['line_numbers'][0]})"
        if vuln.get('source_file'):
            title += f" - {vuln['source_file']}"
        
        with st.expander(title):
            st.write("**설명:**", vuln.get('description', vuln.get('reasoning', '')))
            
            if vuln.get('vulnerable_code'):
                st.code(vuln['vulnerable_code'], language='python')
            
            if vuln.get('recommendation'):
                st.info(f"**권장사항:** {vuln['recommendation']}")
            
            # 추가 정보 표시
            if vuln.get('attack_scenario'):
                st.warning(f"**공격 시나리오:** {vuln['attack_scenario']}")
            
            if vuln.get('confidence'):
                confidence_color = {
                    'HIGH': '🟢', 'MEDIUM': '🟡', 'LOW': '🔴'
                }.get(vuln['confidence'], '⚪')
                st.caption(f"신뢰도: {confidence_color} {vuln['confidence']}")


def display_sbom_tab(sbom):
    """SBOM 결과 표시"""
    st.subheader("📦 Software Bill of Materials")
    
    if sbom.get('packages'):
        df_data = []
        for pkg in sbom['packages']:
            df_data.append({
                "패키지": pkg['name'],
                "설치명": pkg.get('install_name', pkg['name']),
                "요구 버전": pkg.get('required_version', '-'),
                "실제 버전": pkg.get('actual_version', '미확인'),
                "상태": "✅" if pkg.get('actual_version') else "❌",
                "종속성": pkg.get('dependencies_count', 0)
            })
        
        df = pd.DataFrame(df_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        # 간접 종속성 표시
        if sbom.get('indirect_dependencies'):
            with st.expander(f"📎 간접 종속성 ({len(sbom['indirect_dependencies'])}개)"):
                for dep in sbom['indirect_dependencies'][:20]:  # 상위 20개만
                    st.write(f"• {dep['name']} ({dep.get('version', 'unknown')})")


def display_vuln_tab(vuln_scan):
    """취약점 검사 결과 표시"""
    stats = vuln_scan.get('statistics', {})
    
    st.subheader("🛡️ 알려진 취약점")
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("검사 패키지", stats.get('total_checked', 0))
    with col2:
        st.metric("총 취약점", stats.get('total_vulnerabilities', 0))
    with col3:
        st.metric("CRITICAL", stats.get('critical', 0))
    with col4:
        st.metric("HIGH", stats.get('high', 0))
    
    # 취약한 패키지 상세
    if vuln_scan.get('direct_vulnerabilities'):
        st.write("**취약한 직접 패키지:**")
        for pkg_name, data in vuln_scan['direct_vulnerabilities'].items():
            with st.expander(f"📦 {pkg_name} v{data['version']} ({len(data['vulnerabilities'])}개 취약점)"):
                for vuln in data['vulnerabilities']:
                    severity_color = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
                    color = severity_color.get(vuln['severity'], '⚪')
                    
                    st.write(f"{color} **{vuln['id']}** - {vuln['severity']}")
                    st.caption(vuln['summary'])
                    if vuln.get('fixed_version'):
                        st.success(f"수정 버전: {vuln['fixed_version']}")


def display_download_tab_with_id(results, unique_id):
    """다운로드 옵션 (고유 ID 사용)"""
    st.subheader("💾 다운로드")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # JSON 결과
        json_str = json.dumps(results, indent=2, default=str, ensure_ascii=False)
        st.download_button(
            "📥 전체 결과 (JSON)",
            data=json_str,
            file_name=f"{results['project_name']}_analysis.json",
            mime="application/json",
            key=f"download_json_{unique_id}"
        )
        
        # 보안 분석 요약 다운로드
        if 'ai_analysis' in results:
            summary_report = generate_security_summary(results)
            st.download_button(
                "📄 보안 분석 요약",
                data=summary_report,
                file_name=f"{results['project_name']}_security_summary.md",
                mime="text/markdown",
                key=f"download_summary_{unique_id}"
            )
    
    with col2:
        # SBOM 표준 형식
        if results.get('sbom_formats'):
            if results['sbom_formats'].get('spdx'):
                spdx_json = json.dumps(results['sbom_formats']['spdx'], indent=2, ensure_ascii=False)
                st.download_button(
                    "📥 SPDX 2.3",
                    data=spdx_json,
                    file_name=f"{results['project_name']}_sbom_spdx.json",
                    mime="application/json",
                    key=f"download_spdx_{unique_id}"
                )
            
            if results['sbom_formats'].get('cyclonedx'):
                cyclone_json = json.dumps(results['sbom_formats']['cyclonedx'], indent=2, ensure_ascii=False)
                st.download_button(
                    "📥 CycloneDX 1.4",
                    data=cyclone_json,
                    file_name=f"{results['project_name']}_sbom_cyclonedx.json",
                    mime="application/json",
                    key=f"download_cyclone_{unique_id}"
                )


def generate_security_summary(results: Dict) -> str:
    """보안 분석 요약 보고서 생성"""
    report = []
    report.append(f"# {results['project_name']} 보안 분석 요약\n")
    report.append(f"분석 시간: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    
    if 'ai_analysis' in results and results['ai_analysis'].get('success'):
        analysis = results['ai_analysis']['analysis']
        vulns = analysis.get('code_vulnerabilities', [])
        
        report.append(f"## 📊 요약\n")
        report.append(f"- 보안 점수: {analysis.get('security_score', 100)}/100\n")
        report.append(f"- 발견된 취약점: {len(vulns)}개\n\n")
        
        if vulns:
            # 심각도별 통계
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for vuln in vulns:
                sev = vuln.get('severity', 'MEDIUM')
                if sev in severity_counts:
                    severity_counts[sev] += 1
            
            report.append("### 🚨 심각도별 취약점\n")
            for sev, count in severity_counts.items():
                if count > 0:
                    report.append(f"- {sev}: {count}개\n")
            report.append("\n")
            
            # 상위 취약점
            report.append("### 🔍 주요 취약점\n")
            for vuln in vulns[:10]:  # 상위 10개
                report.append(f"#### {vuln['type']} ({vuln.get('severity', 'MEDIUM')})\n")
                if vuln.get('source_file'):
                    report.append(f"**파일:** {vuln['source_file']}\n")
                if vuln.get('line_numbers'):
                    report.append(f"**라인:** {vuln['line_numbers'][0]}\n")
                report.append(f"**설명:** {vuln.get('description', '')}\n")
                if vuln.get('recommendation'):
                    report.append(f"**권장사항:** {vuln['recommendation']}\n")
                report.append("\n")
        
        # 권장사항
        if analysis.get('immediate_actions'):
            report.append("### ⚡ 즉시 조치사항\n")
            for action in analysis['immediate_actions']:
                report.append(f"- {action}\n")
            report.append("\n")
        
        if analysis.get('best_practices'):
            report.append("### 💡 권장 보안 사례\n")
            for practice in analysis['best_practices']:
                report.append(f"- {practice}\n")
    
    return ''.join(report)


def get_vulnerable_example():
    """취약한 코드 예제"""
    return """import sqlite3
import hashlib
import os
import pickle

def get_user(user_id):
    # SQL 인젝션 취약점
    conn = sqlite3.connect('db.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def search_users(name):
    # 또 다른 SQL 인젝션
    conn = sqlite3.connect('db.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name LIKE '%" + name + "%'"
    cursor.execute(query)
    return cursor.fetchall()

def hash_password(password):
    # 약한 암호화
    return hashlib.md5(password.encode()).hexdigest()

def load_user_data(data):
    # 안전하지 않은 역직렬화
    return pickle.loads(data)

def execute_command(cmd):
    # 명령어 삽입
    os.system(f"echo {cmd}")

# 하드코딩된 비밀
API_KEY = "sk-1234567890"
DATABASE_PASSWORD = "admin123"
SECRET_KEY = "my-secret-key"
"""


def get_safe_example():
    """안전한 코드 예제"""
    return """import sqlite3
import hashlib
import secrets
import os
import json
import subprocess

def get_user(user_id):
    # 파라미터 바인딩 사용 (안전)
    conn = sqlite3.connect('db.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()

def search_users(name):
    # 파라미터화된 쿼리 (안전)
    conn = sqlite3.connect('db.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name LIKE ?"
    cursor.execute(query, (f"%{name}%",))
    return cursor.fetchall()

def hash_password(password):
    # 강력한 해시 함수
    salt = secrets.token_bytes(32)
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

def load_user_data(data):
    # 안전한 JSON 파싱
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return None

def execute_command(cmd):
    # 안전한 명령어 실행
    allowed_commands = ['ls', 'pwd', 'date']
    if cmd in allowed_commands:
        return subprocess.run([cmd], capture_output=True, text=True)
    else:
        raise ValueError("명령어가 허용되지 않습니다")

# 환경 변수 사용
API_KEY = os.environ.get('API_KEY')
DATABASE_PASSWORD = os.environ.get('DB_PASSWORD')
SECRET_KEY = os.environ.get('SECRET_KEY')
"""


def get_web_vulnerable_example():
    """웹 애플리케이션 취약점 예제"""
    return """from flask import Flask, request, render_template_string, session, redirect
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.secret_key = "hardcoded-secret-key"  # 하드코딩된 시크릿

# 데이터베이스 설정
DB_HOST = "localhost"
DB_USER = "admin"
DB_PASS = "password123"  # 하드코딩된 비밀번호

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # SQL 인젝션 취약점
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        session['user_id'] = user[0]
        return redirect('/dashboard')
    else:
        return "로그인 실패"

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    
    # XSS 취약점 - 사용자 입력을 직접 템플릿에 삽입
    template = f"<h1>검색 결과: {keyword}</h1>"
    return render_template_string(template)

@app.route('/profile')
def profile():
    # 인증 확인 없음
    user_id = request.args.get('id')
    
    # 또 다른 SQL 인젝션
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    user = cursor.fetchone()
    
    return f"사용자 정보: {user}"

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    
    # 파일 타입 검증 없음 - 경로 조작 취약점
    filename = file.filename
    filepath = f"/uploads/{filename}"  # 경로 조작 취약점
    file.save(filepath)
    
    return f"파일이 저장되었습니다: {filepath}"

@app.route('/admin')
def admin():
    # 권한 확인 없음
    return "관리자 페이지입니다"

@app.route('/debug')
def debug():
    # 디버그 정보 노출
    return f"환경변수: {os.environ}"

def weak_password_hash(password):
    # 약한 패스워드 해싱
    return hashlib.md5(password.encode()).hexdigest()

def unsafe_eval():
    # 사용자 입력을 eval로 실행
    user_input = request.args.get('calc', '')
    try:
        result = eval(user_input)  # 코드 인젝션 취약점
        return f"결과: {result}"
    except:
        return "오류 발생"

@app.route('/redirect')
def unsafe_redirect():
    # 검증되지 않은 리다이렉트
    url = request.args.get('url')
    return redirect(url)  # 오픈 리다이렉트 취약점

# CSRF 보호 없음
@app.route('/transfer', methods=['POST'])
def transfer_money():
    amount = request.form.get('amount')
    to_account = request.form.get('to')
    
    # 중요한 작업인데 CSRF 토큰 확인 없음
    return f"{amount}원을 {to_account}로 송금했습니다"

if __name__ == '__main__':
    # 디버그 모드로 프로덕션 실행
    app.run(debug=True, host='0.0.0.0')
"""