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
import textwrap
import re

from ui.memory_file_selector import MemoryFileSelector
from core.improved_llm_analyzer import ImprovedSecurityAnalyzer
from core.analyzer import SBOMAnalyzer
from core.formatter import SBOMFormatter
from core.project_downloader import ProjectDownloader
from core.mcp_github_client import MCPGithubClient
from core.github_branch_analyzer import GitHubBranchAnalyzer
from core.agent_slot_filler import AgentSlotFiller


def _inject_analysis_css():
    """보안 분석 UI 전용 CSS 주입 (항상)"""
    st.markdown(
        """
<style>
/* Container alignment to Streamlit block */
.sa-wrap{margin: 4px 0 10px;}

/* Hero (contained, no overflow) */
.sa-hero{position:relative;border-radius:12px;padding:16px 18px;background:linear-gradient(135deg,#0f172a,#1f2937); box-shadow: var(--shadow-sm)}
.sa-hero .sa-hero-title{display:flex; align-items:center; gap:.5rem; color:#e5e7eb; font-size:1.4rem; font-weight:700}
.sa-hero .material-symbols-outlined{font-size:1.7rem; color:#93c5fd; margin-right:.1rem}
.sa-hero .sa-hero-sub{color:#cbd5e1; font-size:.9rem; margin-top:.15rem}

/* Stepper (rail + animated fill + nodes) */
.sa-stepper{position:relative; margin:10px 0 16px; padding:16px 10px 8px}
.sa-rail{position:absolute; left:18px; right:18px; top:28px; height:3px; background:var(--gray-200); border-radius:999px; overflow:hidden}
.sa-rail-fill{position:absolute; left:0; top:0; height:100%; width:100%; background:linear-gradient(90deg,#2563eb,#22d3ee); background-size:200% 100%; animation:saFlow 4s linear infinite; transform-origin:left; transform:scaleX(var(--sa-scale,0)); transition:transform .6s ease}
.sa-nodes{position:relative; z-index:1; display:flex; justify-content:space-between; gap:8px}
.sa-node{display:flex; flex-direction:column; align-items:center; min-width:0}
.sa-node-circle{width:28px; height:28px; border-radius:999px; display:flex; align-items:center; justify-content:center; font-weight:700; color:#1f2937; background:#e5e7eb; border:2px solid #e5e7eb}
.sa-node-label{font-size:.8rem; color:#475569; margin-top:4px; text-align:center}
.sa-node.completed .sa-node-circle{background:#3b82f6; border-color:#3b82f6; color:#fff}
.sa-node.current .sa-node-circle{background:linear-gradient(135deg,#2563eb,#22d3ee); border-color:#22d3ee; color:#fff; box-shadow:0 0 0 4px rgba(34,211,238,.18); animation:saBlink 1.8s ease-in-out infinite}

/* Cards */
.sa-card{background:#fff; border:1px solid var(--gray-200); border-radius:12px; padding:14px 16px; box-shadow:var(--shadow-sm)}

/* Motion */
.sa-fade-up{animation:saFadeUp .35s ease-out both}
@keyframes saFadeUp{from{opacity:0; transform:translateY(4px)} to{opacity:1; transform:translateY(0)}}

/* Flowing gradient and blinking current node */
@keyframes saFlow{0%{background-position:0% 50%}100%{background-position:100% 50%}}
@keyframes saBlink{0%,100%{filter:brightness(1); box-shadow:0 0 0 2px rgba(34,211,238,.12)}50%{filter:brightness(1.08); box-shadow:0 0 0 8px rgba(34,211,238,.22)}}

@media (max-width: 768px){
  .sa-hero{padding:12px 14px}
  .sa-hero .sa-hero-title{font-size:1.2rem}
  .sa-stepper{grid-template-columns: repeat(4, 1fr); gap:6px}
}
</style>
""",
        unsafe_allow_html=True,
    )


def _render_analysis_stepper(stage_key: str):
    order = ['input', 'files', 'analyze', 'results']
    titles = {'input': '입력', 'files': '파일', 'analyze': '분석', 'results': '결과'}
    idx = order.index(stage_key) if stage_key in order else 0

    # scale 계산: 0~1 사이 (노드 간 동일 간격) - 현재 노드까지 자연스럽게 채움
    total_segments = max(1, len(order) - 1)
    scale = max(0.0, min(1.0, idx / total_segments))

    nodes_html = []
    for i, key in enumerate(order):
        status = 'completed' if i < idx else ('current' if i == idx else '')
        nodes_html.append(
            f"<div class='sa-node {status}'><div class='sa-node-circle'>{i+1}</div><div class='sa-node-label'>{titles.get(key, key)}</div></div>"
        )

    html = textwrap.dedent(
        f"""
        <div class='sa-stepper sa-fade-up' style='--sa-scale:{scale};'>
          <div class='sa-rail'>
            <div class='sa-rail-fill'></div>
          </div>
          <div class='sa-nodes'>
            {''.join(nodes_html)}
          </div>
        </div>
        """
    )
    st.markdown(html, unsafe_allow_html=True)


def render_code_analysis_tab():
    """메인 코드 분석 탭 - 단계별 UI"""
    _inject_analysis_css()
    st.markdown(
        """
<div class="sa-wrap">
  <div class="sa-hero sa-fade-up">
    <div class="sa-hero-title"><span class="material-symbols-outlined">shield_person</span>보안 분석</div>
    <div class="sa-hero-sub">AI 기반 취약점 탐지와 SBOM 생성 워크플로우</div>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )
    if 'analysis_stage' not in st.session_state:
        st.session_state.analysis_stage = 'input'
    st.markdown('<div class="sa-wrap">', unsafe_allow_html=True)
    _render_analysis_stepper(st.session_state.analysis_stage)
    st.markdown('</div>', unsafe_allow_html=True)
    
    # 단계 초기화 (유지)
    if 'analysis_stage' not in st.session_state:
        st.session_state.analysis_stage = 'input'  # input -> files -> analyze -> results
    
    # 디버그 정보 (개발용)
    with st.sidebar:
        st.caption(f"현재 단계: {st.session_state.analysis_stage}")
    
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
    st.markdown('<h3 class="sa-fade-up"><span class="material-symbols-outlined">upload_file</span> 1단계: 소스 코드 입력</h3>', unsafe_allow_html=True)
    
    with st.container():
        st.markdown('<div class="sa-card sa-fade-up">', unsafe_allow_html=True)
        input_method = st.radio(
            "입력 방법 선택:",
            ["Agent Mode", "GitHub URL", "파일 업로드", "직접 입력"],
            horizontal=True
        )
        st.markdown('</div>', unsafe_allow_html=True)
    
    if input_method == "Agent Mode":
        handle_github_mcp_agent()
    elif input_method == "GitHub URL":
        handle_github_input()
    elif input_method == "파일 업로드":
        handle_file_upload()
    elif input_method == "직접 입력":
        handle_direct_input()


def handle_github_mcp_agent():
    """LLM 에이전트: 자연어 → 슬롯 추출(LLM/폴백) → 검증 → 코드 준비 → 분석 이동"""
    st.markdown("#### Agent Mode")

    if 'agent_slots' not in st.session_state:
        st.session_state.agent_slots = {"repo": None, "base": None, "compare": None, "scope": "diff", "analysis": None, "pr_number": None}
    slots = st.session_state.agent_slots

    # 안내 + 예시
    with st.chat_message("assistant"):
        st.markdown(
            """
            원하는 분석 방식을 자연어로 알려주세요. (전부 대화형으로 진행)

            먼저 분석 유형을 정해주세요:
            - 전체 레포지토리 분석: `full repo` 또는 `전체`
            - 브랜치 비교 분석: `branch compare base main compare feature/x` 또는 `브랜치 비교`
            - PR 분석: `pr #123` 또는 `PR 123`

            다음으로 저장소를 알려주세요:
            - `repo owner/repo` 또는 `repo https://github.com/owner/repo`

            브랜치/범위 예시(브랜치 비교 시):
            - `base main, compare feature/auth, 변경사항만`
            - `base develop, compare release/1.2, 전체`
            """
        )
    user_msg = st.chat_input("요청을 입력하세요")
    if user_msg:
        with st.chat_message("user"):
            st.write(user_msg)
        filler = AgentSlotFiller()
        parsed = filler.parse_to_slots(user_msg)
        for k, v in parsed.items():
            if v:
                slots[k] = v
        st.session_state.agent_slots = slots

    # 보완(대화형 유지, 최소 입력만 제공)
    st.divider()
    st.markdown("##### 직접 입력 (선택)")
    repo = st.text_input("저장소(https://github.com/owner/repo 또는 owner/repo)", value=slots.get("repo") or "")
    colb1, colb2, colb3 = st.columns(3)
    with colb1:
        analysis_type = st.selectbox("분석 유형", ["자동 감지", "전체", "브랜치 비교", "PR 분석"], index=0)
    with colb2:
        base = st.text_input("기준 브랜치", value=slots.get("base") or "")
    with colb3:
        compare = st.text_input("비교 브랜치", value=slots.get("compare") or "")
    scope = st.selectbox("분석 범위(브랜치/PR)", ["변경사항만", "변경파일 전체"], index=(0 if (slots.get("scope") in [None, "diff"]) else 1))
    pr_num = st.text_input("PR 번호(선택)", value=slots.get("pr_number") or "")

    # 업데이트 저장
    slots.update({
        "repo": repo if repo else slots.get("repo"),
        "base": base if base else slots.get("base"),
        "compare": compare if compare else slots.get("compare"),
        "scope": ("full" if scope == "변경파일 전체" else "diff"),
        "analysis": ({
            "자동 감지": slots.get("analysis"),
            "전체": "full",
            "브랜치 비교": "branch",
            "PR 분석": "pr",
        }[analysis_type] if analysis_type else slots.get("analysis")),
        "pr_number": pr_num or slots.get("pr_number"),
    })
    st.session_state.agent_slots = slots

    # 분석 유형 결정 및 입력 검증
    analysis_kind = slots.get("analysis")
    if not analysis_kind:
        # 간단 자동화: base/compare가 있으면 branch, pr_number 있으면 pr, 아니면 full
        if slots.get("pr_number"):
            analysis_kind = "pr"
        elif slots.get("base") and slots.get("compare"):
            analysis_kind = "branch"
        else:
            analysis_kind = "full"
        slots["analysis"] = analysis_kind

    # 필수값 검증
    ready = bool(slots.get("repo")) and (
        (analysis_kind == "full") or
        (analysis_kind == "branch" and slots.get("base") and slots.get("compare")) or
        (analysis_kind == "pr" and slots.get("pr_number"))
    )
    if not ready:
        st.info("입력이 부족합니다. repository / (branch: base, compare) / (PR: 번호) 중 필요한 값을 알려주세요.")
        return

    # URL 정규화
    repo_url = slots["repo"]
    if repo_url and '/' in repo_url and not repo_url.startswith('http'):
        repo_url = f"https://github.com/{repo_url}"

    # 토큰/MCP 서버 URL은 UI에서 입력받지 않습니다 (환경변수 사용)

    analyzer = GitHubBranchAnalyzer()
    with st.spinner("저장소 확인 중..."):
        meta = analyzer.get_branches(repo_url)
    if not meta.get('success'):
        st.error(meta.get('error', '저장소 조회 실패'))
        return

    st.success(f"저장소 확인: {meta.get('owner')}/{meta.get('repo')}")

    # 분석 유형별 코드 준비
    code_to_analyze = ''
    file_list = []
    if analysis_kind == 'branch':
        with st.spinner("브랜치 변경 코드 수집 중..."):
            code_diff = analyzer.get_diff_code_only(repo_url, slots["base"], slots["compare"], selected_files=None)
        if not code_diff.get('success'):
            st.error(code_diff.get('error', '코드 준비 실패'))
            return
        code_to_analyze = code_diff.get('combined_added_code', '') if slots.get("scope") == 'diff' else code_diff.get('combined_full_code', '')
        for f in code_diff.get('file_analysis', [])[:100]:
            file_list.append({
                'path': f.get('filename', 'unknown.py'),
                'name': Path(f.get('filename', 'unknown.py')).name,
                'size': len((f.get('full_content') or f.get('added_code', '') or '').encode('utf-8')),
                'lines': len(((f.get('full_content') or f.get('added_code', '') or '')).splitlines()),
            })
    elif analysis_kind == 'pr':
        # PR diff → base/compare 자동 해석이 필요하지만, 간단 버전: GitHub compare API로는 바로 불가.
        # 여기서는 PR 번호 안내만 하고, 추후 확장(별도 PR API로 files 변경 목록 수집) 여지를 남김.
        st.warning("PR 분석은 간단 버전입니다. 우선 브랜치 비교로 진행해주세요 (향후 PR files API 연동 예정).")
        return
    else:
        # full repo 분석은 다운로드 후 스마트 분석 로직으로 대체 가능. 현 버전은 브랜치 비교 중심이므로 안내.
        st.warning("전체 레포 분석은 곧 제공 예정입니다. 우선 브랜치 비교 또는 PR 분석을 사용해주세요.")
        return

    st.session_state.analysis_code = code_to_analyze
    st.session_state.analysis_file_list = file_list
    st.session_state.project_name = meta.get('repo', 'Repository')
    st.session_state.mcp_branch_ctx = {
        'repo_url': repo_url,
        'owner': meta.get('owner'),
        'repo': meta.get('repo'),
        'base_branch': slots['base'],
        'compare_branch': slots['compare'],
        'analyze_scope': ('변경사항만' if slots.get('scope') == 'diff' else '변경파일 전체'),
        'total_files': len(file_list),
    }

    st.info(f"분석 준비 완료: {slots['base']}…{slots['compare']} / 범위: {('변경사항만' if slots.get('scope') == 'diff' else '변경파일 전체')}")
    if st.button("분석 시작", type="primary"):
        # 에이전트 플로우 상태 저장 후, 파일 단계로 잠시 전환(시각적 진행)
        st.session_state.agent_flow = {
            'pending': True,
            'code': code_to_analyze,
            'file_list': file_list,
            'project_name': st.session_state.get('project_name', meta.get('repo', 'Repository')),
            'mcp_branch_ctx': {
                'repo_url': repo_url,
                'owner': meta.get('owner'),
                'repo': meta.get('repo'),
                'base_branch': slots['base'],
                'compare_branch': slots['compare'],
                'analyze_scope': ('변경사항만' if slots.get('scope') == 'diff' else '변경파일 전체'),
                'total_files': len(file_list),
            }
        }
        st.session_state.analysis_stage = 'files'
        st.rerun()
def handle_github_mcp_input():
    """GitHub MCP 기반 입력 처리: 저장소/브랜치 선택 → 파일 수집"""
    st.markdown("#### Agent Mode")

    if 'mcp_connected' not in st.session_state:
        st.session_state.mcp_connected = None

    server_url = st.text_input(
        "MCP 서버 URL (선택)",
        value=os.getenv("MCP_GITHUB_SERVER_URL", ""),
        placeholder="http://localhost:8888",
        key="mcp_server_url",
    )

    github_url = st.text_input(
        "GitHub 저장소 (owner/repo 또는 URL)",
        placeholder="owner/repo 또는 https://github.com/owner/repo",
        key="mcp_repo_input",
    )

    col1, col2, col3 = st.columns([1, 1, 1])
    with col1:
        connect = st.button("MCP 연결", use_container_width=True)
    with col2:
        load_branches = st.button("브랜치 불러오기", type="secondary", use_container_width=True)
    with col3:
        clear_state = st.button("초기화", use_container_width=True)

    client = MCPGithubClient(server_url=server_url)

    if connect:
        st.session_state.mcp_connected = client.connect()
        if st.session_state.mcp_connected:
            st.success("MCP 서버 연결됨 (필요 시 REST 폴백 사용)")
        else:
            st.warning("MCP 서버에 연결하지 못했습니다. GitHub REST 폴백을 사용합니다.")

    if clear_state:
        for key in ['mcp_branches', 'mcp_repo_url', 'mcp_base_branch', 'mcp_compare_branch', 'mcp_branch_files', 'mcp_branch_ctx']:
            if key in st.session_state:
                del st.session_state[key]
        st.info("상태가 초기화되었습니다.")

    if load_branches and github_url:
        if github_url and '/' in github_url and not github_url.startswith('http'):
            repo_url = f"https://github.com/{github_url}"
        else:
            repo_url = github_url

        analyzer = GitHubBranchAnalyzer()
        with st.spinner("브랜치 목록을 불러오는 중..."):
            meta = analyzer.get_branches(repo_url)

        if not meta.get('success'):
            st.error(meta.get('error', '브랜치 조회 실패'))
        else:
            st.session_state.mcp_branches = meta
            st.session_state.mcp_repo_url = repo_url
            st.success(f"{meta.get('repo')} 브랜치 {meta.get('total', 0)}개")

    if st.session_state.get('mcp_branches'):
        meta = st.session_state['mcp_branches']
        branches = [b['name'] for b in meta.get('branches', [])]
        default_branch = meta.get('default_branch') or 'main'

        colb1, colb2, colb3 = st.columns([1, 1, 1])
        with colb1:
            base_branch = st.selectbox(
                "기준 브랜치",
                options=branches,
                index=branches.index(default_branch) if default_branch in branches else 0,
                key="mcp_base_branch_select"
            )
        with colb2:
            compare_branch = st.selectbox(
                "비교 브랜치",
                options=branches,
                index=0 if default_branch not in branches else (1 if len(branches) > 1 else 0),
                key="mcp_compare_branch_select"
            )
        with colb3:
            analyze_scope = st.radio(
                "분석 범위",
                ["변경사항만", "변경파일 전체"],
                horizontal=False,
                key="mcp_analyze_scope"
            )

        if base_branch == compare_branch:
            st.warning("서로 다른 브랜치를 선택하세요.")

        preview = st.button("변경 파일 미리보기")
        if preview and base_branch != compare_branch:
            analyzer = GitHubBranchAnalyzer()
            with st.spinner("변경 파일을 수집 중..."):
                diff = analyzer.get_branch_diff(st.session_state['mcp_repo_url'], base_branch, compare_branch)
            if not diff.get('success'):
                st.error(diff.get('error', 'diff 수집 실패'))
            else:
                st.session_state.mcp_branch_files = diff
                st.info(f"변경 파일: {diff.get('total_files', 0)}개, +{diff.get('total_additions', 0)}/-{diff.get('total_deletions', 0)}")
                if diff.get('files_changed'):
                    for f in diff['files_changed'][:10]:
                        st.caption(f"- {f['filename']} ({f['status']}, +{f['additions']}/-{f['deletions']})")

        start = st.button("이 브랜치로 분석 시작", type="primary")
        if start and base_branch != compare_branch:
            analyzer = GitHubBranchAnalyzer()
            with st.spinner("분석용 코드 준비 중..."):
                code_diff = analyzer.get_diff_code_only(
                    st.session_state['mcp_repo_url'],
                    base_branch,
                    compare_branch,
                    selected_files=None,
                )
            if not code_diff.get('success'):
                st.error(code_diff.get('error', '코드 준비 실패'))
            else:
                if st.session_state.get('mcp_analyze_scope') == '변경사항만':
                    code_to_analyze = code_diff.get('combined_added_code', '')
                else:
                    code_to_analyze = code_diff.get('combined_full_code', '')

                file_list = []
                for f in code_diff.get('file_analysis', [])[:100]:
                    file_list.append({
                        'path': f.get('filename', 'unknown.py'),
                        'name': Path(f.get('filename', 'unknown.py')).name,
                        'size': len((f.get('full_content') or f.get('added_code', '') or '').encode('utf-8')),
                        'lines': len(((f.get('full_content') or f.get('added_code', '') or '')).splitlines()),
                    })

                st.session_state.analysis_code = code_to_analyze
                st.session_state.analysis_file_list = file_list
                st.session_state.project_name = meta.get('repo', 'Repository')
                st.session_state.mcp_branch_ctx = {
                    'repo_url': st.session_state['mcp_repo_url'],
                    'owner': meta.get('owner'),
                    'repo': meta.get('repo'),
                    'base_branch': base_branch,
                    'compare_branch': compare_branch,
                    'analyze_scope': st.session_state.get('mcp_analyze_scope'),
                    'total_files': len(file_list),
                }
                st.session_state.analysis_stage = 'analyze'
                st.rerun()


# ui/staged_code_analysis_tab.py
# handle_github_input() 함수 수정

def handle_github_input():
    """GitHub 입력 처리 - 개선된 예제 구조"""
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        github_url = st.text_input(
            "GitHub 저장소 URL:",
            placeholder="https://github.com/owner/repository",
            key="github_url_field"
        )
    
    with col2:
        st.write("")
        st.write("")
        download_btn = st.button("다운로드", type="primary", use_container_width=True)
    
    # 예제 드롭다운 (첫 페이지 예시 최소화: PyGoat, Vulnerable Flask App, Django Vulnerable)
    st.markdown("#### 예제 저장소")
    example_choice = st.selectbox(
        "예제 선택:",
        [
            "선택 안함",
            "PyGoat (Django)",
            "Vulnerable Flask App (Flask)",
            "Django Vulnerable (nVisium)"
        ],
        key="example_repo_select"
    )
    example_urls = {
        "PyGoat (Django)": "https://github.com/adeyosemanputra/pygoat",
        "Vulnerable Flask App (Flask)": "https://github.com/we45/Vulnerable-Flask-App",
        "Django Vulnerable (nVisium)": "https://github.com/nVisium/django.nV",
    }
    if example_choice != "선택 안함":
        st.session_state.github_url_field = example_urls[example_choice]
        st.rerun()
    
    if download_btn and st.session_state.get('github_url_field'):
        github_url = st.session_state.get('github_url_field', '')
        with st.spinner("GitHub 저장소 다운로드 중..."):
            success, project_files = download_github_project(github_url)
        
        if success:
            st.success("다운로드 완료!")
            st.session_state.project_files = project_files
            st.session_state.project_name = github_url.split('/')[-1].replace('.git', '')
            st.session_state.analysis_stage = 'files'
            st.rerun()
        else:
            st.error("다운로드 실패")


 


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
                st.success("파일 추출 완료!")
                st.session_state.project_files = project_files
                st.session_state.project_name = uploaded_file.name.split('.')[0]
                st.session_state.analysis_stage = 'files'
                st.rerun()
            else:
                st.error("압축 해제 실패")


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
    st.markdown('<h3 class="sa-fade-up"><span class="material-symbols-outlined">folder_open</span> 2단계: 분석할 파일 선택</h3>', unsafe_allow_html=True)
    
    # 에이전트 플로우에서 바로 넘어온 경우: 진행 애니메이션 후 자동 전환
    agent_flow = st.session_state.get('agent_flow')
    if agent_flow and agent_flow.get('pending'):
        with st.spinner('에이전트가 파일을 준비 중...'):
            import time as _t
            prog = st.progress(0)
            for p in range(0, 101, 10):
                prog.progress(p)
                _t.sleep(0.08)
        # 준비된 코드/파일 반영 후 분석 단계로 이동
        st.session_state.analysis_code = agent_flow.get('code', '')
        st.session_state.analysis_file_list = agent_flow.get('file_list', [])
        st.session_state.project_name = agent_flow.get('project_name', 'Repository')
        st.session_state.mcp_branch_ctx = agent_flow.get('mcp_branch_ctx')
        st.session_state.agent_flow['pending'] = False
        st.session_state.analysis_stage = 'analyze'
        st.rerun()

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
    with st.container():
        st.markdown('<div class="sa-card sa-fade-up">', unsafe_allow_html=True)
        selected_paths = selector.render()
        st.markdown('</div>', unsafe_allow_html=True)
    
    st.divider()
    
    if selected_paths:
        st.markdown('<h3><span class="material-symbols-outlined">tune</span> 분석 옵션</h3>', unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            analysis_mode = st.selectbox(
                "분석 모드:",
                ["전체 분석", "AI 보안 분석", "빠른 분석"],
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
                    st.caption("Claude → GPT")
                else:
                    st.caption("GPT 전용")
            elif has_claude:
                # Claude만 있을 때
                st.session_state.use_claude = True
                st.caption("Claude 사용")
            elif has_gpt:
                # GPT만 있을 때
                st.session_state.use_claude = False
                st.caption("GPT 사용")
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
                st.caption("SBOM 생성됨")
            else:
                st.caption("SBOM 건너뜀")
        
        # 분석 모드 설명
        st.divider()
        
        if analysis_mode == "전체 분석":
            st.info("전체 분석 모드")
        elif analysis_mode == "AI 보안 분석":
            st.warning("AI 보안 분석만")
        elif analysis_mode == "빠른 분석":
            st.info("빠른 분석 모드: SBOM만 생성")
        
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
                "분석 시작", 
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
    st.markdown('<h3 class="sa-fade-up"><span class="material-symbols-outlined">play_circle</span> 3단계: 보안 분석 실행</h3>', unsafe_allow_html=True)
    
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
            mode=st.session_state.get('analysis_mode', 'AI 보안 분석'),
            use_claude=st.session_state.get('use_claude', True),
            include_sbom=st.session_state.get('include_sbom', True)
        )
    
    st.session_state.analysis_results = results
    st.session_state.analysis_stage = 'results'
    st.rerun()


def render_results_stage():
    """4단계: 결과 표시"""
    st.markdown('<h3 class="sa-fade-up"><span class="material-symbols-outlined">insights</span> 4단계: 분석 결과</h3>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("처음으로"):
            reset_analysis_state()
            st.rerun()
    
    with col2:
        if st.button("파일 다시 선택"):
            st.session_state.analysis_stage = 'files'
            st.rerun()
    
    with col3:
        if st.button("다시 분석"):
            st.session_state.analysis_stage = 'analyze'
            st.rerun()

    # PR 생성 버튼 (MCP 브랜치 컨텍스트가 있을 때만 표시)
    mcp_ctx = st.session_state.get('mcp_branch_ctx')
    if mcp_ctx:
        st.divider()
        st.markdown('#### GitHub PR 생성')
        default_title = f"Security analysis for {mcp_ctx.get('compare_branch')} → {mcp_ctx.get('base_branch')}"
        pr_title = st.text_input('PR 제목', value=default_title, key='mcp_pr_title')
        pr_body = st.text_area('PR 본문 (선택사항)', value='', key='mcp_pr_body')
        draft = st.checkbox('Draft PR로 생성 (자동 머지 방지 권장)', value=True, key='mcp_pr_draft')
        if st.button('수정 코드로 PR 보내기(스냅샷)', type='primary', use_container_width=True):
            client = MCPGithubClient()
            owner = mcp_ctx.get('owner')
            repo = mcp_ctx.get('repo')
            base = mcp_ctx.get('base_branch')
            # 원본 파일 맵(분석 코드) - 경로 추론용
            code_blob = st.session_state.get('analysis_code', '')
            analysis_map: Dict[str, str] = {}
            if code_blob:
                pattern = r"# ===== File: (.*?) =====\n"
                parts = re.split(pattern, code_blob)
                if len(parts) >= 3:
                    it = iter(parts[1:])
                    for path, content in zip(it, it):
                        p = path.strip()
                        if p:
                            analysis_map[p] = content

            # AI 취약점 목록
            ai = st.session_state.get('analysis_results', {}).get('ai_analysis', {})
            vulns = ai.get('vulnerabilities', []) if isinstance(ai, dict) else []
            if not vulns:
                st.warning('적용할 수정 코드가 없습니다.')
                return

            analyzer = GitHubBranchAnalyzer()
            repo_url = mcp_ctx.get('repo_url')

            # 대상 파일 경로 집합 수집
            candidate_paths: Dict[str, str] = {}  # map of resolved_path -> base content

            def _resolve_path(file_hint: str) -> str:
                if not file_hint:
                    return ''
                # 정확 경로 우선
                if file_hint in analysis_map:
                    return file_hint
                # 파일명 매칭
                for p in analysis_map.keys():
                    if p.endswith('/' + file_hint) or os.path.basename(p) == os.path.basename(file_hint):
                        return p
                return file_hint  # 마지막 수단: 힌트 그대로

            # 우선 대상 파일 집합 도출
            for v in vulns:
                f = (v.get('location') or {}).get('file')
                if f:
                    rp = _resolve_path(f)
                    candidate_paths[rp] = ''

            # 베이스 브랜치의 원본 내용 로드 (실패시 분석 맵 폴백)
            for rp in list(candidate_paths.keys()):
                base_content = analyzer._get_file_content(repo_url, base, rp)
                if not base_content and rp in analysis_map:
                    base_content = analysis_map[rp]
                candidate_paths[rp] = base_content or ''

            # 패치 적용: 파일별로 모아 1회만 커밋
            changed_files: Dict[str, str] = {}

            def _apply_once(content: str, old: str, new: str) -> tuple[str, bool]:
                if not content or not old or not new:
                    return content, False
                idx = content.find(old)
                if idx == -1:
                    return content, False
                return content.replace(old, new, 1), True

            for v in vulns:
                fixed = v.get('fixed_code')
                if not fixed:
                    continue
                loc = v.get('location') or {}
                file_hint = loc.get('file')
                old_snippet = v.get('vulnerable_code') or loc.get('code_snippet')
                if not file_hint or not old_snippet:
                    continue
                rp = _resolve_path(file_hint)
                original = changed_files.get(rp) or candidate_paths.get(rp, '')
                new_content, ok = _apply_once(original, old_snippet, fixed)
                if ok:
                    changed_files[rp] = new_content

            if not changed_files:
                st.warning('적용 가능한 수정이 없습니다. 파일 경로나 코드 스니펫을 확인하세요.')
                return

            final_title = pr_title if not draft else (f"[DRAFT] {pr_title}")
            with st.spinner('스냅샷 브랜치 생성 및 변경 파일 업로드 중...'):
                resp = client.create_snapshot_branch_and_pr(
                    owner=owner,
                    repo=repo,
                    base_branch=base,
                    title=final_title,
                    body=pr_body,
                    files=changed_files,
                    draft=draft,
                )
            if resp.get('success'):
                st.success(f"스냅샷 PR 생성됨: {resp.get('url')}")
            else:
                st.error(resp.get('error', '스냅샷 PR 생성 실패'))
    
    st.divider()
    
    results = st.session_state.get('analysis_results', {})
    
    if not results:
        st.error("분석 결과가 없습니다.")
        return
    
    st.success(f"분석 완료 ({results.get('analysis_time', 0):.1f}초)")
    
    # 분석 이후 Q&A 진입 버튼
    col_qa1, col_qa2, col_qa3 = st.columns([1, 2, 1])
    with col_qa2:
        if st.button("분석한 프로젝트 Q&A로 이동", type="secondary", use_container_width=True):
            st.session_state.show_qa = True
            st.session_state.qa_project_name = st.session_state.get('project_name', 'Project')
            st.rerun()
    
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
        if mode in ["AI 보안 분석", "전체 분석"]:
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
        st.error("AI 보안 분석 중 오류 발생")
        
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
        with st.expander("디버그 정보"):
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
        st.markdown('<h3><span class="material-symbols-outlined">bug_report</span> 발견된 취약점</h3>', unsafe_allow_html=True)
        
        for idx, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'MEDIUM')
            severity_icon = {
                'CRITICAL': 'CRIT',
                'HIGH': 'HIGH',
                'MEDIUM': 'MED',
                'LOW': 'LOW'
            }.get(severity, 'NA')
            
            location = vuln.get('location', {})
            title = f"{severity_icon} [{idx}] {vuln.get('type', 'Unknown')}"
            if location.get('file'):
                title += f" - {location['file']}:{location.get('line', '?')}"
            
            with st.expander(title, expanded=(idx == 1)):  # 첫 번째 취약점은 펼쳐서 표시
                # 설명
                st.write("### 설명")
                st.write(vuln.get('description', ''))
                
                # 취약한 코드와 수정 코드를 나란히 표시
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("#### 취약한 코드")
                    if vuln.get('vulnerable_code'):
                        st.code(vuln['vulnerable_code'], language='python')
                    else:
                        st.info("원본 코드를 표시할 수 없습니다")
                
                with col2:
                    st.write("#### 수정된 코드")
                    if vuln.get('fixed_code'):
                        st.code(vuln['fixed_code'], language='python')
                    else:
                        st.warning("수정 코드를 생성할 수 없습니다")
                
                # 수정 설명
                if vuln.get('fix_explanation'):
                    st.write("### 수정 설명")
                    st.info(vuln['fix_explanation'])
                
                # 추가 정보들을 탭으로 구성
                tabs = st.tabs(["상세 정보", "공격 시나리오", "권장사항"])
                
                with tabs[0]:
                    # 위치 정보
                    if location:
                        st.write("**위치 정보:**")
                        loc_col1, loc_col2, loc_col3 = st.columns(3)
                        with loc_col1:
                            st.caption(f"파일: {location.get('file', 'unknown')}")
                        with loc_col2:
                            st.caption(f"라인: {location.get('line', '?')}")
                        with loc_col3:
                            st.caption(f"함수: {location.get('function', 'unknown')}")
                        
                        if location.get('code_snippet'):
                            st.write("**문제 코드:**")
                            st.code(location['code_snippet'], language='python')
                    
                    # 데이터 흐름
                    if vuln.get('data_flow'):
                        st.write("**데이터 흐름:**")
                        st.code(vuln['data_flow'], language='text')
                    
                    # 신뢰도
                    confidence = vuln.get('confidence', 'MEDIUM')
                    confidence_color = {
                        'HIGH': 'LOW',
                        'MEDIUM': 'MED', 
                        'LOW': 'CRIT'
                    }.get(confidence, 'NA')
                    st.write(f"**신뢰도:** {confidence_color} {confidence}")
                    
                    # RAG 근거 (있는 경우)
                    if vuln.get('evidence'):
                        evidence = vuln['evidence']
                        st.write("**가이드라인 근거:**")
                        with st.container():
                            st.success(f"**{evidence.get('source', 'KISA 가이드라인')}**")
                            st.caption(evidence.get('content', '')[:500] + "...")
                            if evidence.get('page'):
                                st.caption(f"페이지: {evidence['page']}")
                
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
        st.markdown('<h3><span class="material-symbols-outlined">leaderboard</span> 취약점 통계</h3>', unsafe_allow_html=True)
        
        # 심각도별 통계
        severity_counts = {}
        for vuln in vulnerabilities:
            sev = vuln.get('severity', 'MEDIUM')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        cols = st.columns(4)
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        icons = {'CRITICAL': 'CRIT', 'HIGH': 'HIGH', 'MEDIUM': 'MED', 'LOW': 'LOW'}
        
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
        st.success("발견된 보안 취약점이 없습니다.")
        
        with st.expander("추가 보안 권장사항"):
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
    
    st.markdown('<h3><span class="material-symbols-outlined">deployed_code</span> Software Bill of Materials</h3>', unsafe_allow_html=True)
    
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
            
            with st.expander("전체 JSON 보기"):
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
            
            with st.expander("전체 JSON 보기"):
                st.json(cyclone)


def display_download_options(results: Dict):
    """다운로드 옵션"""
    st.markdown('<h3><span class="material-symbols-outlined">download</span> 다운로드</h3>', unsafe_allow_html=True)
    
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
                "AI 판단 설명 보고서",
                data=explanation_report,
                file_name=f"ai_explanation_report_{int(time.time())}.md",
                mime="text/markdown",
                key=f"download_explanation_{int(time.time())}"  # unique_id 대신 timestamp 사용
            )
            
        if 'ai_analysis' in results:
            report = generate_security_report(results)
            st.download_button(
                "보안 보고서 (Markdown)",
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
                    "SPDX 2.3 형식",
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
                    "CycloneDX 1.4 형식",
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
    
    report.append("## 분석 요약\n")
    report.append(f"- **보안 점수**: {score}/100\n")
    report.append(f"- **발견된 취약점**: {len(vulns)}개\n")
    report.append(f"- **분석 시간**: {results.get('analysis_time', 0):.1f}초\n")
    report.append(f"- **분석 파일 수**: {results.get('analyzed_files', 0)}개\n\n")
    
    # 판단 프로세스 설명
    report.append("## AI 판단 프로세스\n")
    report.append("```")
    report.append("1. 코드 패턴 분석 → 위험 패턴 탐지")
    report.append("2. LLM 추론 → 취약점 유형 분류 및 심각도 판단")
    report.append("3. RAG 검증 → KISA 가이드라인 매칭")
    report.append("4. 신뢰도 산출 → 최종 판단")
    report.append("```\n")
    
    # 각 취약점별 상세 설명
    report.append("## 취약점별 판단 근거\n")
    
    for i, vuln in enumerate(vulns, 1):
        report.append(f"### {i}. {vuln.get('type', 'Unknown')}\n")
        
        # 기본 정보
        severity = vuln.get('severity', 'MEDIUM')
        confidence = vuln.get('confidence', 'MEDIUM')
        location = vuln.get('location', {})
        
        report.append(f"**심각도**: {severity} | **신뢰도**: {confidence}\n")
        report.append(f"**위치**: {location.get('file', 'unknown')}:{location.get('line', '?')}\n\n")
        
        # 판단 근거 섹션
        report.append("#### 왜 이것이 취약점인가?\n")
        report.append(f"{vuln.get('description', '설명 없음')}\n\n")
        
        # 판단 과정
        report.append("#### 어떻게 판단했는가?\n")
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
        report.append("#### 판단 근거\n")
        
        # 가이드라인 근거
        if vuln.get('evidence'):
            evidence = vuln['evidence']
            report.append("**공식 가이드라인**:\n")
            report.append(f"- 문서: {evidence.get('document', 'KISA 가이드')}\n")
            report.append(f"- 페이지: {evidence.get('page', 'N/A')}\n")
            if evidence.get('content'):
                report.append(f"- 내용: {evidence['content'][:200]}...\n")
        else:
            report.append("- AI 자체 판단 (가이드라인 매칭 없음)\n")
        
        # 신뢰도 계산
        report.append("\n#### 신뢰도 산출\n")
        confidence_score = _calculate_confidence_score(vuln)
        report.append(f"```\n{confidence_score['formula']}\n")
        report.append(f"최종 신뢰도: {confidence_score['score']}%\n```\n")
        
        # 공격 시나리오
        if vuln.get('exploit_scenario'):
            report.append("#### 공격 시나리오\n")
            report.append(f"{vuln['exploit_scenario']}\n\n")
        
        # 권장사항
        if vuln.get('recommendation'):
            report.append("#### 권장 조치\n")
            report.append(f"{vuln['recommendation']}\n\n")
        
        report.append("---\n")
    
    # 종합 판단
    report.append("## 종합 판단\n")
    
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