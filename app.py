"""
SBOM Security Analyzer - Professional Security Analysis Platform
고급 보안 분석 및 취약점 탐지 플랫폼
"""
import streamlit as st
import os
from dotenv import load_dotenv

# 환경 변수 로드
load_dotenv()

# 페이지 설정 - 전문적 메타데이터
st.set_page_config(
    page_title="SBOMiner | 보안 분석 플랫폼",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': None,
        'Report a bug': None,
        'About': "SBOMiner - Enterprise Security Analysis Platform"
    }
)

# 전문적인 글로벌 스타일 시스템
st.markdown(
    """
<style>
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
}

/* =================================
   전역 레이아웃 개선
   ================================= */
.main > div {
  padding-top: 2rem;
  padding-bottom: 2rem;
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
  padding: 2rem 1rem !important;
}

section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3 {
  color: white !important;
  font-weight: 600 !important;
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

# UI 모듈 임포트
from ui.staged_code_analysis_tab import render_code_analysis_tab
from ui.qa_tab import render_qa_tab

def main():
    # 헤로 섹션
    st.markdown("""
    <div style="text-align: center; padding: 2rem 0; margin-bottom: 2rem;">
        <h1 style="font-size: 3rem; margin-bottom: 0.5rem;">SBOMiner</h1>
        <p style="font-size: 1.25rem; color: var(--gray-600); margin-bottom: 1rem;">
            Enterprise Security Analysis Platform
        </p>
        <p style="color: var(--gray-500); font-size: 1rem;">
            AI 기반 보안 취약점 탐지 및 SBOM 생성 플랫폼
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # 전문적인 사이드바
    with st.sidebar:
        # 브랜드 헤더
        st.markdown("""
        <div style="text-align: center; padding: 1rem 0 2rem 0;">
            <h2 style="color: white; margin: 0; font-size: 1.5rem;">SBOMiner 시스템</h2>
            <p style="color: var(--gray-200); font-size: 0.9rem; margin: 0.5rem 0 0 0;">
                Security Configuration
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # API 키 상태 - 전문적 표시
        has_api_key = bool(os.getenv("OPENAI_API_KEY"))
        
        st.markdown("### AI 엔진 상태")
        
        if has_api_key:
            model = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
            st.success("AI 엔진 활성화됨")
            
            # 모델 정보 카드
            st.markdown(f"""
            <div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 0.5rem; margin: 1rem 0;">
                <strong>활성 모델:</strong><br>
                <code>{model}</code>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.error("AI 엔진 비활성화")
            st.info("AI 보안 분석을 사용하려면 API 키가 필요합니다")
            
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
                "title": "Q&A",
                "items": [
                    "KISIA 가이드라인 기반",
                    "RAG 기반 답변",
                    "컨텍스트 인식",
                    "실시간 질의응답"
                ]
            }
        ]
        
        for feature in features:
            with st.expander(feature['title']):
                for item in feature['items']:
                    st.markdown(f"• {item}")
        
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
    
    # 메인 탭
    tab1, tab2, tab3 = st.tabs([
        "보안 분석", 
        "Q&A", 
        "사용 가이드"
    ])
    
    with tab1:
        render_code_analysis_tab()
    
    with tab2:
        render_qa_tab()
    
    with tab3:
        render_help_tab()


def render_help_tab():
    """전문적인 도움말 탭"""
    
    # 헤더 섹션
    st.markdown("""
    <div style="text-align: center; padding: 1rem 0 2rem 0;">
        <h2>📖 SBOMiner 사용 가이드</h2>
        <p style="color: var(--gray-600); font-size: 1.1rem;">
            Enterprise Security Analysis Platform 완전 가이드
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # 퀵 스타트 가이드
    with st.expander("🚀 퀵 스타트 가이드", expanded=True):
        st.markdown("""
        ### 3분만에 시작하기
        
        1. **코드 입력** → GitHub URL, 파일 업로드, 또는 직접 입력
        2. **분석 실행** → AI 보안 분석 또는 전체 분석 선택
        3. **결과 확인** → 취약점, SBOM, 권장사항 검토        
        3. **다운로드** → 분석 결과 다운로드
        
        """)
    
    # 주요 기능 상세
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("## 🔍 보안 분석 기능")
        
        # 입력 방법 카드
        with st.container():
            st.markdown("""
            ### 📥 지원 입력 방법
            
            | 방법 | 설명 | 용도 |
            |------|------|------|
            | 🔗 **GitHub URL** | 공개 저장소 분석 | 오픈소스 프로젝트 |
            | 📦 **파일 업로드** | .py, .zip, .tar.gz | 로컬 프로젝트 |
            | 📝 **직접 입력** | 코드 복사/붙여넣기 | 코드 스니펫 테스트 |
            """)
        
        # 분석 모드
        with st.container():
            st.markdown("""
            ### ⚙️ 분석 모드 선택
            
            **🔥 전체 분석** (권장)
            - AI 보안 분석 + SBOM 생성
            - 소요시간: 20-60초
            - 완전한 보안 평가
            
            **🤖 AI 보안 분석**
            - 취약점 탐지 전용
            - 소요시간: 10-30초
            - 빠른 보안 검사
            
            **⚡ 빠른 분석**
            - SBOM 생성만
            - 소요시간: 1-5초
            - 의존성 파악용
            """)
    
    with col2:
        st.markdown("## 🛡️ 탐지 가능한 취약점")
        
        # 취약점 카테고리
        vulnerability_categories = [
            {
                "category": "🔴 Critical",
                "types": [
                    "SQL Injection",
                    "Command Injection", 
                    "Code Execution",
                    "Path Traversal"
                ]
            },
            {
                "category": "🟠 High",
                "types": [
                    "XSS (Cross-Site Scripting)",
                    "CSRF",
                    "Unsafe Deserialization",
                    "Hardcoded Secrets"
                ]
            },
            {
                "category": "🟡 Medium",
                "types": [
                    "Weak Cryptography",
                    "Information Disclosure",
                    "Insecure Random",
                    "Debug Code"
                ]
            },
            {
                "category": "🟢 Low",
                "types": [
                    "Missing Security Headers",
                    "Deprecated Functions",
                    "Code Quality Issues",
                    "Best Practice Violations"
                ]
            }
        ]
        
        for category in vulnerability_categories:
            with st.expander(category["category"]):
                for vuln_type in category["types"]:
                    st.markdown(f"• {vuln_type}")
    
    st.divider()
    
    # SBOM 및 표준 가이드
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("## 📦 SBOM 생성 기능")
        
        st.markdown("""
        ### 지원 표준 형식
        
        **SPDX 2.3** 
        - Linux Foundation 표준
        - 라이선스 중심 접근
        - 오픈소스 생태계 호환성
        - ISO/IEC 5962:2021 표준
        
        **CycloneDX 1.4**
        - OWASP 보안 중심 표준  
        - 취약점 정보 포함
        - DevSecOps 워크플로우 최적화
        - 실시간 위협 인텔리전스
        
        ### 생성되는 정보
        - 직접/간접 종속성 목록
        - 패키지 버전 정보
        - 라이선스 정보
        - 알려진 취약점 매핑
        """)
    
    with col2:
        st.markdown("## 💬 Q&A")
        
        st.markdown("""
        ### RAG 기반 답변 시스템
        
        **지식 베이스**
        - KISIA Python 시큐어코딩 가이드
        - OWASP Top 10 
        - CWE (Common Weakness Enumeration)
        - 최신 보안 모범 사례
        
        **질문 예시**
        - "SQL 인젝션을 방어하는 방법은?"
        - "패스워드는 어떻게 저장해야 하나요?"
        - "XSS 공격을 방지하려면?"
        - "환경변수는 왜 사용해야 하나요?"
        
        **답변 품질**
        - 문서 기반 정확한 답변
        - 실무 적용 가능한 솔루션
        - 코드 예제 포함
        - 출처 및 근거 제시
        """)
    
    st.divider()
    
    # 고급 사용법
    st.markdown("## 고급 사용법")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        ### 성능 최적화
        
        **대용량 프로젝트 (500KB+)**
        - 코드 크기 제한 설정 (100-2000KB)
        - 우선순위 파일 선택 (main.py, app.py 등)
        - 파일 크기별 필터링 (10KB 이하/이상)
        
        **메모리 관리**
        - 사이드바에서 캐시 클리어
        - 세션 상태 초기화
        - 불필요한 파일 제외 (venv, __pycache__ 등)
        
        **분석 모드 활용**
        - 빠른 분석: SBOM만 (1-5초)
        - AI 보안 분석: 취약점 탐지 (10-30초)  
        - 전체 분석: 모든 기능 (20-60초)
        """)
    
    with col2:
        st.markdown("""
        ### 실제 기능 활용
        
        **환경 스캔 기능**
        - 실제 설치된 패키지 버전 확인
        - requirements.txt와 버전 비교
        - 간접 종속성 추적
        
        **SBOM 표준 형식**
        - SPDX 2.3: 라이선스 중심
        - CycloneDX 1.4: 보안 중심
        - JSON 다운로드 지원
        
        **파일 선택 최적화**
        - 스마트 선택 도구 (전체/주요/작은파일)
        - 크기별 필터링 (10KB, 50KB 단위)
        - 패턴 필터링 (models, auth, api 등)
        """)
    
    with col3:
        st.markdown("""
        ### 분석 결과 활용
        
        **다운로드 형식**
        - 전체 결과 (JSON)
        - 보안 분석 요약 (Markdown)
        - SPDX 표준 형식 (JSON)
        - CycloneDX 표준 형식 (JSON)
        
        **대용량 코드 처리**
        - 자동 파일별 분할 분석
        - 중요 파일 우선 처리 (최대 5개)
        - 파일당 50KB 제한
        
        **AI 엔진 선택**
        - GPT 모델 (기본)
        - Claude 모델 (고급 옵션)
        - 컨텍스트 길이 최적화
        """)
    
    # FAQ
    with st.expander("자주 묻는 질문 (FAQ)", expanded=False):
        
        faqs = [
            {
                "q": "파라미터 바인딩이 SQL 인젝션으로 잘못 탐지됩니다",
                "a": "최신 AI 엔진에서 개선되었습니다. `?`나 `%s` 파라미터 바인딩은 안전하게 분류됩니다. 여전히 문제가 있다면 컨텍스트를 더 자세히 제공해주세요."
            },
            {
                "q": "GitHub private 저장소를 분석할 수 있나요?",
                "a": "현재는 공개 저장소만 지원합니다. Private 저장소는 파일 다운로드 후 업로드하거나 코드를 직접 입력해주세요."
            },
            {
                "q": "분석 결과를 어떻게 저장하나요?",
                "a": "분석 완료 후 '다운로드' 탭에서 JSON, SPDX, CycloneDX, Markdown 형식으로 저장할 수 있습니다."
            },
            {
                "q": "개발용 하드코딩도 위험하다고 나오는데요?",
                "a": "개발 환경이라도 하드코딩된 시크릿은 보안 위험입니다. 환경변수나 설정 파일을 사용하는 것을 강력히 권장합니다."
            },
            {
                "q": "AI 분석 결과를 어떻게 신뢰해야 하나요?",
                "a": "AI 분석은 보조 도구입니다. 결과를 참고하되, 항상 전문가 검토를 거치고 실제 환경에서 테스트해보세요."
            },
            {
                "q": "대용량 프로젝트 분석이 실패합니다",
                "a": "파일을 선별하여 분석하거나, 핵심 모듈부터 단계적으로 분석해보세요. 전체 프로젝트보다는 중요한 부분에 집중하는 것이 효과적입니다."
            }
        ]
        
        for i, faq in enumerate(faqs, 1):
            st.markdown(f"**Q{i}: {faq['q']}**")
            st.markdown(f"**A{i}:** {faq['a']}")
            st.markdown("---")
    



if __name__ == "__main__":
    main()