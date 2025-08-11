"""
통합 코드 분석 탭 - 직접입력/GitHub/파일 모두 지원
"""
import streamlit as st
import json
import pandas as pd
import os
import time
import tempfile
from pathlib import Path
from typing import Dict, Optional

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
    
    # 입력 방법 선택 (key 추가로 상태 유지)
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
        # 입력 방법이 바뀌면 기존 분석 데이터는 유지하되, 새 입력을 받을 준비
    
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
            ["직접 입력", "취약한 코드", "안전한 코드"],
            key="example_selector"
        )
        
        # 예제 선택시 코드 변경
        if example == "취약한 코드":
            if st.button("예제 로드", key="load_vulnerable"):
                st.session_state.direct_code = get_vulnerable_example()
        elif example == "안전한 코드":
            if st.button("예제 로드", key="load_safe"):
                st.session_state.direct_code = get_safe_example()
        
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
    """GitHub URL 입력 처리"""
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
    
    # 예제 URL
    with st.expander("📌 예제 저장소"):
        if st.button("Flask 예제", key="flask_example"):
            st.session_state.github_url_input = "https://github.com/pallets/flask"
            st.rerun()
        if st.button("FastAPI 예제", key="fastapi_example"):
            st.session_state.github_url_input = "https://github.com/tiangolo/fastapi"
            st.rerun()
    
    # 다운로드 처리
    if download_btn and st.session_state.github_url_input:
        downloader = ProjectDownloader()
        
        with st.spinner("🔄 GitHub 저장소 다운로드 중..."):
            success, message, project_path = downloader.download_github(st.session_state.github_url_input)
        
        if success:
            st.success(f"✅ {message}")
            
            # 프로젝트 파일 분석
            with st.spinner("📂 프로젝트 파일 분석 중..."):
                project_data = downloader.analyze_project_files(Path(project_path), max_files=50)
            
            # 정보 표시
            with st.expander("📊 프로젝트 정보", expanded=True):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Python 파일", project_data['statistics']['total_files'])
                with col2:
                    st.metric("총 라인", f"{project_data['statistics']['total_lines']:,}")
                with col3:
                    st.metric("스킵된 파일", project_data['statistics']['skipped_files'])
            
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
                
                # 프로젝트 분석
                with st.spinner("📂 파일 분석 중..."):
                    project_data = downloader.analyze_project_files(Path(project_path), max_files=50)
                
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
    """공통 분석 로직"""
    
    # 코드 정보
    st.info(f"""
    📊 **분석 대상**
    - 프로젝트: {project_name}
    - 코드 크기: {len(code):,}자
    - 라인 수: {len(code.splitlines())}줄
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
        max_code_size = st.number_input(
            "최대 분석 크기:", 
            1000, 
            50000, 
            15000,
            key="max_code_size_input"
        )
    
    # 분석 버튼
    if st.button("🚀 분석 시작", type="primary", use_container_width=True, key="start_analysis_btn"):
        # 코드 크기 조정
        if len(code) > max_code_size:
            st.warning(f"⚠️ 코드가 너무 길어 처음 {max_code_size}자만 분석합니다.")
            code = code[:max_code_size]
        
        # 분석 실행
        run_analysis(code, requirements, project_name, analysis_mode, scan_env)
    
    # 이전 분석 결과가 있으면 표시
    if 'last_analysis_results' in st.session_state:
        st.divider()
        st.subheader("📊 이전 분석 결과")
        display_results(st.session_state.last_analysis_results)


def run_analysis(code: str, requirements: str, project_name: str, mode: str, scan_env: bool):
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
    
    # 결과를 세션에 저장
    st.session_state.last_analysis_results = results
    
    # 결과 표시
    display_results(results)


def display_results(results: Dict):
    """분석 결과 표시"""
    
    if not results:
        return
    
    # 고유 ID 생성 (중복 방지)
    import hashlib
    import time
    result_id = hashlib.md5(f"{results.get('project_name', '')}{time.time()}".encode()).hexdigest()[:8]
    
    # 요약
    st.success(f"✅ 분석 완료 ({results['analysis_time']:.1f}초)")
    
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
            display_ai_tab(results['ai_analysis'])
        tab_idx += 1
    
    # 취약점 탭
    if 'vulnerability_scan' in results:
        with tab_objects[tab_idx]:
            display_vuln_tab(results['vulnerability_scan'])
        tab_idx += 1
    
    # 다운로드 탭 - 고유 ID 전달
    with tab_objects[tab_idx]:
        display_download_tab_with_id(results, result_id)


def display_download_tab_with_id(results, unique_id):
    """다운로드 옵션 (고유 ID 사용)"""
    st.subheader("💾 다운로드")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # JSON 결과
        json_str = json.dumps(results, indent=2, default=str)
        st.download_button(
            "📥 전체 결과 (JSON)",
            data=json_str,
            file_name=f"{results['project_name']}_analysis.json",
            mime="application/json",
            key=f"download_json_{unique_id}"
        )
    
    with col2:
        # SBOM 표준 형식
        if results.get('sbom_formats'):
            if results['sbom_formats'].get('spdx'):
                spdx_json = json.dumps(results['sbom_formats']['spdx'], indent=2)
                st.download_button(
                    "📥 SPDX 2.3",
                    data=spdx_json,
                    file_name=f"{results['project_name']}_sbom_spdx.json",
                    mime="application/json",
                    key=f"download_spdx_{unique_id}"
                )
            
            if results['sbom_formats'].get('cyclonedx'):
                cyclone_json = json.dumps(results['sbom_formats']['cyclonedx'], indent=2)
                st.download_button(
                    "📥 CycloneDX 1.4",
                    data=cyclone_json,
                    file_name=f"{results['project_name']}_sbom_cyclonedx.json",
                    mime="application/json",
                    key=f"download_cyclone_{unique_id}"
                )


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
                "상태": "✅" if pkg.get('actual_version') else "❌"
            })
        
        df = pd.DataFrame(df_data)
        st.dataframe(df, use_container_width=True, hide_index=True)


def display_ai_tab(ai_result):
    """AI 분석 결과 표시"""
    if not ai_result.get('success'):
        st.error("분석 실패")
        return
    
    analysis = ai_result['analysis']
    vulns = analysis.get('code_vulnerabilities', [])
    
    if not vulns:
        st.success("✅ 취약점이 발견되지 않았습니다!")
        return
    
    st.subheader(f"🤖 {len(vulns)}개 취약점 발견")
    
    for vuln in vulns:
        severity_icon = {
            'CRITICAL': '🔴', 'HIGH': '🟠',
            'MEDIUM': '🟡', 'LOW': '🟢'
        }.get(vuln.get('severity', 'MEDIUM'), '⚪')
        
        with st.expander(f"{severity_icon} {vuln['type']} (라인 {vuln.get('line_numbers', ['?'])[0]})"):
            st.write("**설명:**", vuln.get('description', vuln.get('reasoning', '')))
            
            if vuln.get('vulnerable_code'):
                st.code(vuln['vulnerable_code'], language='python')
            
            if vuln.get('recommendation'):
                st.info(f"**권장사항:** {vuln['recommendation']}")


def display_vuln_tab(vuln_scan):
    """취약점 검사 결과 표시"""
    stats = vuln_scan.get('statistics', {})
    
    st.subheader("🛡️ 알려진 취약점")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("검사 패키지", stats.get('total_checked', 0))
    with col2:
        st.metric("총 취약점", stats.get('total_vulnerabilities', 0))
    with col3:
        st.metric("CRITICAL", stats.get('critical', 0))


def display_download_tab(results):
    """다운로드 옵션"""
    st.subheader("💾 다운로드")
    
    # 고유 키 생성을 위한 타임스탬프 또는 해시 사용
    import hashlib
    result_hash = hashlib.md5(str(results).encode()).hexdigest()[:8]
    
    col1, col2 = st.columns(2)
    
    with col1:
        # JSON 결과
        json_str = json.dumps(results, indent=2, default=str)
        st.download_button(
            "📥 전체 결과 (JSON)",
            data=json_str,
            file_name=f"{results['project_name']}_analysis.json",
            mime="application/json",
            key=f"download_json_{result_hash}"  # 고유 키 추가
        )
    
    with col2:
        # SBOM 표준 형식
        if results.get('sbom_formats'):
            if results['sbom_formats'].get('spdx'):
                spdx_json = json.dumps(results['sbom_formats']['spdx'], indent=2)
                st.download_button(
                    "📥 SPDX 2.3",
                    data=spdx_json,
                    file_name=f"{results['project_name']}_sbom_spdx.json",
                    mime="application/json",
                    key=f"download_spdx_{result_hash}"  # 고유 키 추가
                )
            
            if results['sbom_formats'].get('cyclonedx'):
                cyclone_json = json.dumps(results['sbom_formats']['cyclonedx'], indent=2)
                st.download_button(
                    "📥 CycloneDX 1.4",
                    data=cyclone_json,
                    file_name=f"{results['project_name']}_sbom_cyclonedx.json",
                    mime="application/json",
                    key=f"download_cyclone_{result_hash}"  # 고유 키 추가
                )


def get_vulnerable_example():
    """취약한 코드 예제"""
    return """import sqlite3
import hashlib

def get_user(user_id):
    # SQL 인젝션 취약점
    conn = sqlite3.connect('db.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def hash_password(password):
    # 약한 암호화
    return hashlib.md5(password.encode()).hexdigest()

# 하드코딩된 비밀
API_KEY = "sk-1234567890"
"""


def get_safe_example():
    """안전한 코드 예제"""
    return """import sqlite3
import hashlib
import secrets
import os

def get_user(user_id):
    # 파라미터 바인딩 사용 (안전)
    conn = sqlite3.connect('db.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()

def hash_password(password):
    # 강력한 해시 함수
    salt = secrets.token_bytes(32)
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

# 환경 변수 사용
API_KEY = os.environ.get('API_KEY')
"""