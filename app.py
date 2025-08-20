"""
SBOM Security Analyzer - Professional Security Analysis Platform
고급 보안 분석 및 취약점 탐지 플랫폼
"""
import streamlit as st
import os
import base64
from dotenv import load_dotenv

# 환경 변수 로드
load_dotenv()

# 페이지 설정
st.set_page_config(
    page_title="SBOMiner | 보안 분석 플랫폼",
    page_icon="ui/assets/logo.png",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': None,
        'Report a bug': None,
        'About': "SBOMiner - Enterprise Security Analysis Platform"
    }
)

# 글로벌 스타일 시스템
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,400,0,0');
.material-symbols-outlined {
  font-family: 'Material Symbols Outlined';
  font-variation-settings: 'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24;
  display: inline-block;
  vertical-align: -0.24em;
  font-size: 1.25em;
  margin-right: 0.35rem;
}
/* =================================
   글로벌 변수 및 기본 설정
   ================================= */
:root {
  /* 브랜드 컬러 - 전문적 팔레트 */
  --primary-blue: #1e293b;
  --primary-blue-light: #334155;
  --accent-blue: #3b82f6;
  --accent-slate: #64748b;
  --accent-green: #059669;
  --accent-red: #dc2626;
  
  /* 뉴트럴 컬러 */
  --gray-50: #f8fafc;
  --gray-100: #f1f5f9;
  --gray-200: #e2e8f0;
  --gray-300: #cbd5e1;
  --gray-400: #94a3b8;
  --gray-500: #64748b;
  --gray-600: #475569;
  --gray-700: #334155;
  --gray-800: #1e293b;
  --gray-900: #0f172a;
  
  /* 시맨틱 컬러 - 절제된 톤 */
  --success: #059669;
  --warning: #d97706;
  --error: #dc2626;
  --info: #3b82f6;
  
  /* 그림자 */
  --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
  --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
  --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
  
  /* 글꼴 */
  --font-mono: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', 'Source Code Pro', monospace;
  /* 사이드바 호버 슬라이드 변수 */
  --sidebar-expanded-width: 320px;
  --sidebar-collapsed-handle: 18px;
  --sidebar-transition: 0.25s;
}

/* =================================
   전역 레이아웃 개선
   ================================= */
html, body {
  margin: 0 !important;
  padding: 0 !important;
}

.stApp header[data-testid="stHeader"] {
  height: 0 !important;
  min-height: 0 !important;
  background: transparent !important;
}

.main > div {
  padding-top: 0rem;
  padding-bottom: 1.5rem;
}
/* 상단 컨테이너 기본 여백 추가 축소 */
.stApp .main .block-container {
  padding-top: 0rem !important;
  margin-top: 0rem !important;
}

/* 헤더 스타일링 */
.main h1 {
  font-size: 2.5rem !important;
  font-weight: 700 !important;
  color: var(--gray-900) !important;
  margin-bottom: 0.5rem !important;
  background: linear-gradient(135deg, var(--primary-blue) 0%, var(--accent-cyan) 100%);
  -webkit-background-clip: text !important;
  -webkit-text-fill-color: transparent !important;
  background-clip: text !important;
}

.main h2 {
  font-size: 1.875rem !important;
  font-weight: 600 !important;
  color: var(--gray-800) !important;
  margin: 1.5rem 0 1rem 0 !important;
  border-bottom: 2px solid var(--gray-200);
  padding-bottom: 0.5rem;
}

.main h3 {
  font-size: 1.5rem !important;
  font-weight: 600 !important;
  color: var(--gray-700) !important;
  margin: 1.25rem 0 0.75rem 0 !important;
}

/* =================================
   버튼 시스템 - 전문적 스타일
   ================================= */
.stButton > button {
  background: var(--gray-700) !important;
  color: white !important;
  border: 1px solid var(--gray-600) !important;
  border-radius: 0.5rem !important;
  padding: 0.6rem 1.2rem !important;
  font-weight: 500 !important;
  font-size: 0.875rem !important;
  transition: all 0.15s ease !important;
  box-shadow: none !important;
  letter-spacing: 0.01em !important;
}

.stButton > button:hover {
  background: var(--gray-600) !important;
  border-color: var(--gray-500) !important;
  transform: none !important;
  box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1) !important;
}

.stButton > button:active {
  background: var(--gray-800) !important;
  transform: none !important;
  box-shadow: inset 0 1px 2px 0 rgb(0 0 0 / 0.1) !important;
}

/* Primary 버튼 */
div[data-testid="stButton"] button[kind="primary"] {
  background: var(--accent-blue) !important;
  border-color: var(--accent-blue) !important;
  box-shadow: none !important;
}

div[data-testid="stButton"] button[kind="primary"]:hover {
  background: #2563eb !important;
  border-color: #2563eb !important;
  box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1) !important;
}

/* =================================
   탭 시스템
   ================================= */
.stTabs [data-baseweb="tab-list"] {
  background: var(--gray-50);
  border-radius: 1rem;
  padding: 0.25rem;
  border: 1px solid var(--gray-200);
  margin-bottom: 1.5rem;
}

.stTabs [data-baseweb="tab"] {
  color: var(--gray-600) !important;
  font-weight: 500 !important;
  padding: 0.75rem 1.5rem !important;
  border-radius: 0.75rem !important;
  transition: all 0.2s ease !important;
  border: none !important;
}

.stTabs [aria-selected="true"] {
  background: white !important;
  color: var(--primary-blue) !important;
  font-weight: 600 !important;
  box-shadow: var(--shadow-sm) !important;
  border: 1px solid var(--gray-200) !important;
}

.stTabs [data-baseweb="tab"]:hover:not([aria-selected="true"]) {
  background: white !important;
  color: var(--gray-700) !important;
}

/* =================================
   카드 및 컨테이너
   ================================= */
div[data-testid="metric-container"] {
  background: white !important;
  border: 1px solid var(--gray-200) !important;
  border-radius: 1rem !important;
  padding: 1.5rem !important;
  box-shadow: var(--shadow-sm) !important;
  transition: all 0.2s ease !important;
}

div[data-testid="metric-container"]:hover {
  box-shadow: var(--shadow-md) !important;
  border-color: var(--accent-cyan) !important;
}

/* 메트릭 값 스타일링 */
div[data-testid="metric-container"] [data-testid="metric-value"] {
  font-size: 2rem !important;
  font-weight: 700 !important;
  color: var(--primary-blue) !important;
}

div[data-testid="metric-container"] [data-testid="metric-label"] {
  font-size: 0.875rem !important;
  font-weight: 500 !important;
  color: var(--gray-600) !important;
  text-transform: uppercase !important;
  letter-spacing: 0.05em !important;
}

/* =================================
   알림 및 상태 메시지
   ================================= */
div[data-baseweb="notification"] {
  border-radius: 0.75rem !important;
  border: none !important;
  box-shadow: var(--shadow-sm) !important;
}

div[data-baseweb="notification"][kind="success"] {
  background: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%) !important;
  border-left: 4px solid var(--success) !important;
  color: #065f46 !important;
}

div[data-baseweb="notification"][kind="warning"] {
  background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%) !important;
  border-left: 4px solid var(--warning) !important;
  color: #92400e !important;
}

div[data-baseweb="notification"][kind="error"] {
  background: linear-gradient(135deg, #fef2f2 0%, #fecaca 100%) !important;
  border-left: 4px solid var(--error) !important;
  color: #991b1b !important;
}

div[data-baseweb="notification"][kind="info"] {
  background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%) !important;
  border-left: 4px solid var(--info) !important;
  color: #0c4a6e !important;
}

/* =================================
   폼 요소
   ================================= */
.stTextInput input, .stTextArea textarea, .stSelectbox select {
  border: 1.5px solid var(--gray-300) !important;
  border-radius: 0.75rem !important;
  padding: 0.75rem 1rem !important;
  transition: all 0.2s ease !important;
  font-size: 0.875rem !important;
}

.stTextInput input:focus, .stTextArea textarea:focus, .stSelectbox select:focus {
  border-color: var(--accent-cyan) !important;
  box-shadow: 0 0 0 3px rgba(6, 182, 212, 0.1) !important;
  outline: none !important;
}

/* =================================
   사이드바 전문화
   ================================= */
section[data-testid="stSidebar"] {
  background: linear-gradient(180deg, var(--primary-blue) 0%, var(--primary-blue-light) 100%) !important;
  border-right: 1px solid var(--gray-200) !important;
}

section[data-testid="stSidebar"] .css-1d391kg {
  padding: 0.75rem 0.75rem 1rem 0.75rem !important;
}

section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3 {
  color: white !important;
  font-weight: 600 !important;
  margin-top: 0 !important;
}

section[data-testid="stSidebar"] p,
section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] span,
section[data-testid="stSidebar"] div,
section[data-testid="stSidebar"] .stMarkdown {
  color: var(--gray-200) !important;
}

section[data-testid="stSidebar"] .stButton > button {
  background: rgba(255, 255, 255, 0.1) !important;
  border: 1px solid rgba(255, 255, 255, 0.2) !important;
  color: white !important;
  backdrop-filter: blur(10px) !important;
  /* 사이드바 버튼 텍스트 한 줄 유지 및 축소 */
  font-size: 0.8rem !important;
  padding: 0.45rem 0.7rem !important;
  line-height: 1.1 !important;
  white-space: nowrap !important;
}

section[data-testid="stSidebar"] .stButton > button:hover {
  background: rgba(255, 255, 255, 0.2) !important;
  border-color: var(--accent-cyan) !important;
}

/* 사이드바 알림 중앙정렬 및 좌측 보더 제거 */
section[data-testid="stSidebar"] div[data-baseweb="notification"] {
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  text-align: center !important;
  padding: 0.45rem 0.7rem !important;
}

/* 좌측 보더 제거 및 균형 보더 적용 */
section[data-testid="stSidebar"] div[data-baseweb="notification"][kind="success"],
section[data-testid="stSidebar"] div[data-baseweb="notification"][kind="warning"],
section[data-testid="stSidebar"] div[data-baseweb="notification"][kind="error"],
section[data-testid="stSidebar"] div[data-baseweb="notification"][kind="info"] {
  border-left: 0 !important;
  border: 1px solid rgba(255, 255, 255, 0.2) !important;
}

/* 알림 아이콘/리딩 여백 제거 */
/* 알림 아이콘만 숨김 (텍스트 컨테이너는 유지) */
section[data-testid="stSidebar"] div[data-baseweb="notification"] svg {
  display: none !important;
}

/* 사이드바 알림(성공/경고 등)도 한 줄 유지하도록 조정 */
section[data-testid="stSidebar"] div[data-baseweb="notification"] {
  font-size: 0.8rem !important;
  padding: 0.5rem 0.75rem !important;
  white-space: nowrap !important;
  min-height: 32px !important; /* 줄처럼 보이는 현상 방지 */
}

/* 사이드바 호버 시 슬라이드 인/아웃 동작 */
section[data-testid="stSidebar"] {
  width: var(--sidebar-expanded-width) !important;
  position: fixed !important;
  left: 0;
  top: 0;
  bottom: 0;
  padding-top: 0 !important;
  margin-top: 0 !important;
  transform: translateX(calc(-100% + var(--sidebar-collapsed-handle)));
  transition: transform var(--sidebar-transition) ease, box-shadow var(--sidebar-transition) ease;
  z-index: 1100;
}

section[data-testid="stSidebar"]:hover {
  transform: translateX(0);
  box-shadow: var(--shadow-lg);
}

/* 비호버 상태에서도 보이는 세로 핸들 표시 */
section[data-testid="stSidebar"]::after {
  content: "Guide";
  position: absolute;
  right: 0;
  top: 50%;
  transform: translateY(-50%);
  width: var(--sidebar-collapsed-handle);
  height: 120px;
  display: flex;
  align-items: center;
  justify-content: center;
  writing-mode: vertical-rl;
  text-orientation: mixed;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.08em;
  color: #e2e8f0; /* gray-200 */
  background: linear-gradient(180deg, rgba(255,255,255,0.14) 0%, rgba(255,255,255,0.06) 100%),
              linear-gradient(180deg, var(--primary-blue), var(--primary-blue-light));
  backdrop-filter: blur(6px);
  border-radius: 0 8px 8px 0;
  box-shadow: var(--shadow-md);
  border-left: 1px solid rgba(255,255,255,0.18);
  cursor: pointer;
  transition: opacity var(--sidebar-transition) ease, transform var(--sidebar-transition) ease, background-color 0.2s ease;
}

/* 사이드바가 펼쳐지는 동안 핸들은 사라짐 */
section[data-testid="stSidebar"]:hover::after {
  opacity: 0;
  transform: translateY(-50%) translateX(8px);
  pointer-events: none;
}

/* 메인 영역은 핸들(좁은 호버 영역) 만큼만 좌측 여백 확보 */
div[data-testid="stAppViewContainer"] {
  margin-left: 0 !important;
  padding-left: var(--sidebar-collapsed-handle);
  transition: padding-left var(--sidebar-transition) ease;
}

@media (max-width: 768px) {
  section[data-testid="stSidebar"] {
    width: calc(var(--sidebar-expanded-width) - 40px) !important;
  }
}

/* =================================
   코드 블록
   ================================= */
.stCodeBlock {
  border-radius: 0.75rem !important;
  border: 1px solid var(--gray-200) !important;
  box-shadow: var(--shadow-sm) !important;
}

/* =================================
   Expander 스타일링
   ================================= */
.streamlit-expanderHeader {
  background: var(--gray-50) !important;
  border: 1px solid var(--gray-200) !important;
  border-radius: 0.75rem !important;
  padding: 1rem 1.5rem !important;
  font-weight: 600 !important;
  color: var(--gray-800) !important;
  transition: all 0.2s ease !important;
}

.streamlit-expanderHeader:hover {
  background: var(--gray-100) !important;
  border-color: var(--accent-cyan) !important;
}

.streamlit-expanderContent {
  border: 1px solid var(--gray-200) !important;
  border-top: none !important;
  border-radius: 0 0 0.75rem 0.75rem !important;
  padding: 1.5rem !important;
  background: white !important;
}

/* =================================
   데이터프레임 스타일링
   ================================= */
.dataframe {
  border-radius: 0.75rem !important;
  overflow: hidden !important;
  border: 1px solid var(--gray-200) !important;
  box-shadow: var(--shadow-sm) !important;
}

/* =================================
   반응형 디자인
   ================================= */
@media (max-width: 768px) {
  .main h1 {
    font-size: 2rem !important;
  }
  
  .main h2 {
    font-size: 1.5rem !important;
  }
  
  div[data-testid="metric-container"] {
    padding: 1rem !important;
  }
  
  .stButton > button {
    padding: 0.5rem 1rem !important;
    font-size: 0.8rem !important;
  }
}

/* =================================
   애니메이션 효과
   ================================= */
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

.main > div > div {
  animation: fadeIn 0.5s ease-out;
}

/* =================================
   스크롤바 커스터마이징
   ================================= */
::-webkit-scrollbar {
  width: 8px;
}

::-webkit-scrollbar-track {
  background: var(--gray-100);
  border-radius: 4px;
}

::-webkit-scrollbar-thumb {
  background: var(--gray-400);
  border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
  background: var(--gray-500);
}
</style>
""",
    unsafe_allow_html=True,
)

# UI 모듈
from ui.staged_code_analysis_tab import render_code_analysis_tab
from ui.qa_tab import render_qa_tab

def main():
    logo_b64 = ""
    try:
        with open("ui/assets/logo.png", "rb") as f:
            logo_b64 = base64.b64encode(f.read()).decode("utf-8")
    except Exception:
        logo_b64 = ""

    st.markdown(f"""
    <div style="padding: 0 0 1rem 0; margin-bottom: 0.75rem; display: flex; align-items: center; justify-content: flex-start; gap: 0rem;">
        <img src="data:image/png;base64,{logo_b64}" style="height: 150px; width: auto; border-radius: 12px;"/>
        <div style="display: flex; flex-direction: column; justify-content: center;">
            <h1 class="brand-title" style="font-size: 3rem; margin: 0 0 0.4rem 0;">SBOMiner</h1>
            <p style="font-size: 1.25rem; color: var(--gray-600); margin: 0 0 0.25rem 0;">Enterprise Security Analysis Platform</p>
            <p style="color: var(--gray-500); font-size: 1rem; margin: 0;">AI 기반 보안 취약점 탐지 및 SBOM 생성 플랫폼</p>
        </div>
    </div>
    <style>
    .brand-title {{
      color: #062758 !important;
      -webkit-text-fill-color: #062758 !important;
      background: none !important;
      -webkit-background-clip: initial !important;
      background-clip: initial !important;
    }}
    @media (max-width: 768px) {{
      .stApp .main .block-container > div:first-child img[src^="data:image/png;base64,"] {{
        height: 96px !important;
      }}
    }}
    </style>
    """, unsafe_allow_html=True)

    # 탭 아이콘에 로고를 일괄 주입하는 CSS는 비활성화
    
    # 전문적인 사이드바
    with st.sidebar:
        # 브랜드 헤더
        st.markdown("""
        <div style="text-align: center; padding: 1rem 0 1.2rem 0;">
            <h2 style="color: white; margin: 0; font-size: 1.4rem;">SBOMiner 가이드</h2>
            <p style="color: var(--gray-200); font-size: 0.86rem; margin: 0.4rem 0 0 0;">
                네비게이션 · 시스템
            </p>
        </div>
        """, unsafe_allow_html=True)

        # 간단한 사용 가이드 (네비게이션)
        st.markdown("### 사용 가이드")
        with st.expander("빠른 시작 (3단계)", expanded=False):
            st.caption("1) 1단계 입력: GitHub URL 선택 또는 입력")
            st.caption("2) 2단계 선택: 분석할 파일 선택")
            st.caption("3) 3단계 실행: 분석 시작 → 결과 확인")

        with st.expander("팁"):
            st.caption("- PyGoat, Vulnerable Flask, Django Vulnerable 예제로 시작 가능")
            st.caption("- 대형 프로젝트는 핵심 파일만 선택하여 속도 향상")
        
        # API 키 상태
        has_openai_key = bool(os.getenv("OPENAI_API_KEY"))
        has_claude_key = bool(os.getenv("ANTHROPIC_API_KEY"))
        
        st.markdown("### AI 엔진 상태")
        
        # OpenAI 상태
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**OpenAI (GPT)**")
            if has_openai_key:
                model = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
                st.success("활성화")
                st.caption(f"모델: {model}")
            else:
                st.error("비활성화")
                st.caption("API 키 없음")
        
        with col2:
            st.markdown("**Anthropic (Claude)**")
            if has_claude_key:
                model = os.getenv("ANTHROPIC_MODEL", "claude-3-sonnet-20240229")
                st.success("활성화")
                st.caption(f"모델: {model}")
            else:
                st.warning("비활성화")
                st.caption("API 키 없음")
        
        # API 키가 하나도 없는 경우에만 설정 섹션 표시
        if not has_openai_key and not has_claude_key:
            st.error("AI 엔진이 모두 비활성화 상태입니다")
            st.info("AI 보안 분석을 사용하려면 최소 하나의 API 키가 필요합니다")
            
            with st.expander("API 키 설정"):
                openai_key = st.text_input(
                    "OpenAI API Key:", 
                    type="password", 
                    key="openai_key_input",
                    placeholder="sk-..."
                )
                claude_key = st.text_input(
                    "Anthropic API Key:", 
                    type="password", 
                    key="claude_key_input",
                    placeholder="sk-ant-..."
                )
                
                if st.button("API 키 저장"):
                    if openai_key:
                        os.environ["OPENAI_API_KEY"] = openai_key
                    if claude_key:
                        os.environ["ANTHROPIC_API_KEY"] = claude_key
                    st.rerun()
            
            with st.expander("API 키 설정"):
                api_key = st.text_input(
                    "OpenAI API Key:", 
                    type="password", 
                    key="api_key_input",
                    placeholder="sk-..."
                )
            if api_key:
                os.environ["OPENAI_API_KEY"] = api_key
                st.rerun()
        
        st.divider()
        
        # 기능 개요 - 전문적 레이아웃
        st.markdown("### 플랫폼 기능")
        
        # 기능 카드들
        features = [
            {
                "title": "보안 분석",
                "items": [
                    "AI 기반 취약점 탐지",
                    "정적 코드 분석",
                    "다중 소스 코드 지원",
                    "실시간 분석 결과"
                ]
            },
            {
                "title": "SBOM 생성",
                "items": [
                    "SPDX 2.3 표준",
                    "CycloneDX 1.4 표준",
                    "의존성 분석",
                    "라이선스 추적"
                ]
            },
            {
                "title": "Q&A (분석 후)",
                "items": [
                    "KISA 가이드라인 기반",
                    "RAG 기반 답변",
                    "컨텍스트 인식",
                    "분석 완료 후 버튼으로 진입"
                ]
            }
        ]
        
        for feature in features:
            with st.expander(feature['title']):
                for item in feature['items']:
                    st.markdown(f"• {item}")

        st.divider()

        # 사이드바에서 사용 가이드 바로가기
        if st.button("사용 가이드 열기", use_container_width=True):
            st.session_state.show_qa = False
            st.session_state.show_help = True
            st.rerun()
        
        st.divider()
        
        # 시스템 관리
        st.markdown("### 시스템 관리")
        
        # 단일 관리 동작만 제공 (캐시 초기화)
        if st.button("캐시 초기화", use_container_width=True):
            st.cache_data.clear()
            for key in list(st.session_state.keys()):
                if key != 'api_key_input':
                    del st.session_state[key]
            st.rerun()
        
        # 시스템 정보
        st.markdown("### 시스템 정보")
        st.caption("버전: v2.0.0")
        st.caption("엔진: GPT-4 / Claude-3")
        st.caption("표준: SPDX 2.3, CycloneDX 1.4")
    
    # 메인 뷰: 분석 우선, Q&A/가이드는 버튼 네비게이션
    if st.session_state.get('show_qa'):
        col_back, col_title, _ = st.columns([1, 6, 1])
        with col_back:
            if st.button("← 분석 화면", use_container_width=True):
                st.session_state.show_qa = False
                st.rerun()
        with col_title:
            proj = st.session_state.get('qa_project_name', '')
            if proj:
                st.markdown(f"#### 프로젝트 Q&A · {proj}")
        render_qa_tab()
    elif st.session_state.get('show_help'):
        col_back, _, _ = st.columns([1, 9, 1])
        with col_back:
            if st.button("← 분석 화면", use_container_width=True):
                st.session_state.show_help = False
                st.rerun()
        render_help_tab()
    else:
        render_code_analysis_tab()


def render_help_tab():
    """전문적인 도움말 탭 - 순수 사용 가이드"""
    
    # 헤더 섹션
    st.markdown("""
    <div style="text-align: center; padding: 1rem 0 2rem 0;">
        <h2>SBOMiner 사용 가이드</h2>
        <p style="color: var(--gray-600); font-size: 1.1rem;">
            보안 분석 플랫폼 사용 방법
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # 퀵 스타트 가이드
    with st.expander("🚀 빠른 시작 가이드", expanded=True):
        st.markdown("""
        ### 3단계로 시작하기
        
        1. **코드 입력** 
           - GitHub URL 입력 → 다운로드 클릭
           - 또는 Python 파일 업로드
           - 또는 코드 직접 입력
        
        2. **파일 선택**
           - 스마트 선택 도구 활용 (전체/주요/작은 파일)
           - 또는 개별 파일 선택
        
        3. **분석 실행**
           - 분석 모드 선택 (전체/AI 보안/빠른 분석)
           - 분석 시작 버튼 클릭
           - 결과 확인 및 다운로드
        """)
    
    # 주요 기능 설명
    st.markdown("## 주요 기능")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 입력 방법
        
        **1. GitHub URL**
        - 공개 저장소 URL 입력
        - 예: `https://github.com/owner/repo`
        - Private 저장소는 지원하지 않음
        
        **2. 파일 업로드**
        - 지원 형식: .py, .zip, .tar, .gz
        - 여러 파일은 압축해서 업로드
        
        **3. 직접 입력**
        - 텍스트 영역에 코드 붙여넣기
        - 단일 파일 분석에 적합
        """)
        
        st.markdown("""
        ### 분석 모드
        
        **전체 분석**
        - AI 보안 분석 + SBOM 생성
        - 가장 완전한 분석
        
        **AI 보안 분석**
        - 취약점 탐지에 집중
        - 수정 코드 제안
        
        **빠른 분석**
        - SBOM만 생성
        - 의존성 파악용
        """)
    
    with col2:
        st.markdown("""
        ### 파일 선택
        
        **스마트 선택 도구**
        - 전체 선택: 모든 파일 분석
        - 주요 파일: main.py, views.py 등
        - 작은 파일: 10KB 이하만
        
        **고급 필터링**
        - 크기별 필터 (10KB, 50KB 기준)
        - 파일명 패턴 검색
        - 디렉토리별 그룹 선택
        """)
        
        st.markdown("""
        ### 결과 다운로드
        
        **다운로드 형식**
        - JSON: 전체 분석 결과
        - Markdown: 보안 보고서
        - SPDX 2.3: 표준 SBOM
        - CycloneDX 1.4: 보안 중심 SBOM
        
        **결과 탭**
        - 보안 분석: 취약점 상세
        - SBOM: 패키지 목록
        - SBOM 표준: 표준 형식 보기
        """)
    
    st.divider()
    
    # 사용 팁
    st.markdown("## 사용 팁")
    
    tips = {
        "성능 최적화": [
            "대용량 프로젝트는 주요 파일만 선택",
            "코드 크기가 클 경우 여러 번 나누어 분석",
            "불필요한 테스트 파일 제외"
        ],
        "분석 정확도": [
            "requirements.txt 파일 포함 권장",
            "전체 컨텍스트가 있는 파일 선택",
            "프레임워크 파일보다 사용자 코드 우선"
        ],
        "결과 활용": [
            "취약점은 심각도순으로 정렬됨",
            "수정 코드는 복사하여 바로 적용 가능",
            "SBOM은 컴플라이언스 문서로 활용"
        ]
    }
    
    cols = st.columns(3)
    for i, (title, items) in enumerate(tips.items()):
        with cols[i]:
            st.markdown(f"**{title}**")
            for item in items:
                st.caption(f"• {item}")
    
    # 제한사항
    with st.expander("제한사항 및 주의사항"):
        st.warning("""
        **제한사항**
        - Private GitHub 저장소 미지원
        - 파일 크기: 최대 100MB
        - Python 코드만 분석 가능
        - 실시간 분석이 아닌 정적 분석
        
        **주의사항**
        - AI 분석 결과는 참고용으로만 사용
        - 모든 취약점을 탐지하지 못할 수 있음
        - 실제 보안 감사는 전문가 검토 필요
        """)
    
    # 문제 해결
    with st.expander("문제 해결"):
        st.markdown("""
        **Q: 분석이 실패합니다**
        - 코드 구문 오류 확인
        - 파일 크기 확인 (너무 큰 경우)
        - API 키 설정 확인
        
        **Q: 결과가 부정확합니다**
        - 더 많은 컨텍스트 파일 포함
        - requirements.txt 추가
        - 다른 AI 모델 시도 (Claude ↔ GPT)
        
        **Q: 다운로드가 안 됩니다**
        - 브라우저 다운로드 설정 확인
        - 팝업 차단 해제
        - 다른 형식으로 시도
        """)
    
    # 버전 정보
    st.divider()
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.caption("**버전:** v2.0.0")
    with col2:
        st.caption("**최종 업데이트:** 2024.12")
    with col3:
        st.caption("**라이선스:** MIT")



if __name__ == "__main__":
    main()