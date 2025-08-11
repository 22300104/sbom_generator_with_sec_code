# ui/code_analysis_tab.py
"""
Enhanced Code analysis tab UI with GPT-first integration
"""
import streamlit as st
import json
import pandas as pd
from core.analyzer import SBOMAnalyzer
from core.formatter import SBOMFormatter
from core.llm_analyzer import LLMSecurityAnalyzer
from security.vulnerability import check_vulnerabilities_enhanced
import time
import os

def render_code_analysis_tab():
    """강화된 코드 분석 탭 - GPT 중심"""
    st.header("🔍 AI 기반 코드 보안 분석")
    
    # 분석기 초기화
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = SBOMAnalyzer()
    if 'formatter' not in st.session_state:
        st.session_state.formatter = SBOMFormatter()
    
    # LLM 분석기 초기화 체크
    llm_available = False
    if os.getenv("OPENAI_API_KEY"):
        if 'llm_analyzer' not in st.session_state:
            try:
                st.session_state.llm_analyzer = LLMSecurityAnalyzer()
                llm_available = True
            except Exception as e:
                st.warning(f"⚠️ LLM 분석기 초기화 실패: {e}")
        else:
            llm_available = True
    else:
        st.warning("⚠️ OpenAI API 키가 설정되지 않았습니다. 일부 기능이 제한됩니다.")
    
    analyzer = st.session_state.analyzer
    formatter = st.session_state.formatter
    llm_analyzer = st.session_state.llm_analyzer if llm_available else None
    
    # 분석 모드 선택
    col1, col2 = st.columns([2, 1])
    with col1:
        analysis_mode = st.radio(
            "분석 모드 선택",
            ["⚡ 빠른 분석 (SBOM + 취약점)", "🤖 AI 보안 분석 (GPT + RAG)", "🔥 전체 분석 (All)"],
            horizontal=True,
            help="AI 보안 분석은 OpenAI API 키가 필요합니다"
        )
    
    with col2:
        if llm_available and llm_analyzer:
            st.success(f"✅ GPT 모델: {llm_analyzer.model}")
            if llm_analyzer.rag_available:
                st.success("✅ RAG: KISIA 가이드")
        else:
            st.error("❌ AI 분석 불가")
    
    # 입력 영역
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("📄 Python 코드")
        
        # 예제 코드 선택
        example_code = st.selectbox(
            "예제 선택",
            ["직접 입력", "취약한 코드 예제", "안전한 코드 예제"],
            key="example_selector"
        )
        
        if example_code == "취약한 코드 예제":
            default_code = get_vulnerable_example()
        elif example_code == "안전한 코드 예제":
            default_code = get_safe_example()
        else:
            default_code = ""
        
        code_input = st.text_area(
            "코드를 입력하세요:",
            height=400,
            value=default_code,
            key="code_input",
            placeholder="import pandas as pd\nimport numpy as np\n..."
        )
    
    with col2:
        st.subheader("📦 requirements.txt")
        
        req_input = st.text_area(
            "requirements.txt 내용:",
            height=400,
            placeholder="pandas==2.0.0\nnumpy>=1.24.0\n...",
            key="req_input"
        )
    
    # 분석 버튼
    if st.button("🔍 보안 분석 시작", type="primary", use_container_width=True):
        if not code_input:
            st.warning("코드를 입력해주세요.")
            return
        
        # 진행 상태 표시
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        results = {}
        
        try:
            # 1단계: SBOM 생성 (모든 모드에서 실행)
            if analysis_mode in ["⚡ 빠른 분석 (SBOM + 취약점)", "🔥 전체 분석 (All)"]:
                status_text.text("📊 SBOM 생성 중...")
                progress_bar.progress(20)
                
                sbom_result = analyzer.analyze(code_input, req_input, scan_environment=True)
                
                if not sbom_result.get("success"):
                    st.error(f"SBOM 생성 실패: {sbom_result.get('error')}")
                    return
                
                results['sbom'] = sbom_result
                
                # 2단계: 취약점 검사
                status_text.text("🔍 패키지 취약점 검사 중...")
                progress_bar.progress(40)
                
                if sbom_result.get('packages') and sbom_result.get('indirect_dependencies'):
                    vuln_result = check_vulnerabilities_enhanced(
                        sbom_result["packages"],
                        sbom_result.get("indirect_dependencies", []),
                        sbom_result
                    )
                    results['vulnerability'] = vuln_result
            
            # 3단계: AI 보안 분석 (선택적)
            if analysis_mode in ["🤖 AI 보안 분석 (GPT + RAG)", "🔥 전체 분석 (All)"]:
                if not llm_available:
                    st.error("AI 분석을 위해 OpenAI API 키를 설정해주세요.")
                else:
                    status_text.text("🤖 AI 보안 분석 중...")
                    progress_bar.progress(60)
                    
                    # 컨텍스트 준비
                    context = {}
                    if 'sbom' in results:
                        context['sbom_summary'] = create_sbom_summary(results['sbom'])
                    
                    # AI 분석 실행
                    ai_result = llm_analyzer.analyze_code_security(code_input, context)
                    results['ai_analysis'] = ai_result
            
            progress_bar.progress(100)
            status_text.text("✅ 분석 완료!")
            time.sleep(0.5)
            progress_bar.empty()
            status_text.empty()
            
            # 결과 표시
            display_analysis_results(results, analysis_mode)
            
        except Exception as e:
            st.error(f"❌ 분석 중 오류 발생: {e}")
            progress_bar.empty()
            status_text.empty()

def display_analysis_results(results, analysis_mode):
    """분석 결과 통합 표시"""
    
    st.success("✅ 보안 분석 완료!")
    
    # 전체 요약
    display_summary_metrics(results)
    
    # 탭으로 결과 구성
    tabs = []
    if 'sbom' in results:
        tabs.append("📊 SBOM")
    if 'vulnerability' in results:
        tabs.append("🛡️ 패키지 취약점")
    if 'ai_analysis' in results:
        tabs.append("🤖 AI 코드 분석")
    tabs.extend(["📋 보고서", "💾 다운로드"])
    
    tab_objects = st.tabs(tabs)
    tab_index = 0
    
    # SBOM 탭
    if '📊 SBOM' in tabs:
        with tab_objects[tab_index]:
            display_sbom_info(results.get('sbom'))
        tab_index += 1
    
    # 패키지 취약점 탭
    if '🛡️ 패키지 취약점' in tabs:
        with tab_objects[tab_index]:
            display_package_vulnerabilities(results.get('vulnerability'))
        tab_index += 1
    
    # AI 코드 분석 탭
    if '🤖 AI 코드 분석' in tabs:
        with tab_objects[tab_index]:
            display_ai_analysis(results.get('ai_analysis'))
        tab_index += 1
    
    # 보고서 탭
    with tab_objects[tab_index]:
        generate_integrated_report(results)
    tab_index += 1
    
    # 다운로드 탭
    with tab_objects[tab_index]:
        provide_download_options(results)

def display_summary_metrics(results):
    """전체 요약 메트릭 표시"""
    
    col1, col2, col3, col4 = st.columns(4)
    
    # SBOM 메트릭
    if 'sbom' in results:
        sbom = results['sbom']
        with col1:
            st.metric(
                "전체 패키지",
                sbom['summary']['external_packages'],
                delta=f"+{sbom['summary'].get('indirect_dependencies', 0)} 간접"
            )
    
    # 패키지 취약점 메트릭
    if 'vulnerability' in results:
        vuln = results['vulnerability'].get('vulnerability_scan', {}).get('statistics', {})
        with col2:
            total_vulns = vuln.get('total_vulnerabilities', 0)
            st.metric(
                "패키지 취약점",
                total_vulns,
                delta="위험" if total_vulns > 0 else "안전",
                delta_color="inverse"
            )
    
    # AI 분석 메트릭
    if 'ai_analysis' in results:
        ai = results['ai_analysis']
        if ai.get('success'):
            analysis = ai['analysis']
            with col3:
                score = analysis.get('security_score', 0)
                st.metric(
                    "보안 점수",
                    f"{score}/100",
                    delta="양호" if score >= 70 else "위험" if score < 40 else "주의",
                    delta_color="normal" if score >= 70 else "inverse"
                )
            
            with col4:
                code_vulns = len(analysis.get('code_vulnerabilities', []))
                st.metric(
                    "코드 취약점",
                    code_vulns,
                    delta="CRITICAL" if any(v.get('severity') == 'CRITICAL' for v in analysis.get('code_vulnerabilities', [])) else None,
                    delta_color="inverse" if code_vulns > 0 else "off"
                )

def display_ai_analysis(ai_result):
    """AI 분석 결과 표시"""
    if not ai_result or not ai_result.get('success'):
        st.error("AI 분석 결과가 없습니다.")
        return
    
    analysis = ai_result['analysis']
    metadata = ai_result.get('metadata', {})
    
    # 분석 정보
    col1, col2, col3 = st.columns(3)
    with col1:
        st.info(f"**모델**: {metadata.get('gpt_model', 'unknown')}")
    with col2:
        st.info(f"**RAG**: {'활성' if metadata.get('rag_available') else '비활성'}")
    with col3:
        st.info(f"**발견**: {metadata.get('total_vulnerabilities', 0)}개")
    
    # 보안 점수
    score = analysis.get('security_score', 0)
    st.metric("🎯 보안 점수", f"{score}/100")
    st.progress(score / 100)
    
    # 발견된 취약점
    vulns = analysis.get('code_vulnerabilities', [])
    if vulns:
        st.subheader(f"⚠️ 발견된 코드 취약점 ({len(vulns)}개)")
        
        # 심각도별 그룹화
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_vulns = [v for v in vulns if v.get('severity') == severity]
            if severity_vulns:
                severity_color = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }[severity]
                
                st.write(f"### {severity_color} {severity} ({len(severity_vulns)}개)")
                
                for vuln in severity_vulns:
                    with st.expander(f"**라인 {vuln.get('line_numbers', ['?'])[0]}**: {vuln['type']}"):
                        st.write(f"**설명**: {vuln.get('description', '')}")
                        
                        # 취약한 코드
                        if vuln.get('vulnerable_code'):
                            st.code(vuln['vulnerable_code'], language='python')
                        
                        # 설명 출처
                        if vuln.get('explanation'):
                            source = vuln.get('explanation_source', '')
                            if source == 'KISIA 가이드라인':
                                st.info(f"📚 **{source}**:\n{vuln['explanation']}")
                            else:
                                st.write(f"🤖 **{source}**:\n{vuln['explanation']}")
                        
                        # 권장 수정
                        if vuln.get('recommended_fix'):
                            st.success(f"✅ **권장 수정**:\n```python\n{vuln['recommended_fix']}\n```")
    else:
        st.success("✅ 코드 취약점이 발견되지 않았습니다!")
    
    # 즉시 조치사항
    if analysis.get('immediate_actions'):
        st.subheader("🚨 즉시 필요한 조치")
        for action in analysis['immediate_actions']:
            st.write(f"• {action}")
    
    # 모범 사례
    if analysis.get('best_practices'):
        st.subheader("💡 권장 보안 사례")
        for practice in analysis['best_practices']:
            st.write(f"• {practice}")

def display_sbom_info(result):
    """SBOM 정보 표시"""
    if not result:
        return
    
    st.subheader("📦 발견된 패키지")
    
    # 패키지 테이블
    if result.get("packages"):
        df_data = []
        for pkg in result["packages"]:
            df_data.append({
                "패키지": pkg["name"],
                "설치명": pkg["install_name"],
                "요구 버전": pkg.get("required_version", "미지정"),
                "실제 버전": pkg.get("actual_version", "미설치"),
                "종속성": pkg.get("dependencies_count", 0),
                "상태": pkg["status"]
            })
        
        df = pd.DataFrame(df_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
    
    # 간접 종속성
    if result.get("indirect_dependencies"):
        with st.expander(f"📎 간접 종속성 ({len(result['indirect_dependencies'])}개)"):
            for dep in result['indirect_dependencies'][:20]:
                st.write(f"• {dep['name']} ({dep.get('version', 'unknown')})")

def display_package_vulnerabilities(result):
    """패키지 취약점 표시"""
    if not result or 'vulnerability_scan' not in result:
        st.info("취약점 검사 결과가 없습니다.")
        return
    
    scan = result['vulnerability_scan']
    stats = scan['statistics']
    
    # 통계
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("검사한 패키지", stats['total_checked'])
    with col2:
        st.metric("발견된 취약점", stats['total_vulnerabilities'])
    with col3:
        st.metric("API 호출", stats['api_calls'])
    
    # 취약점 상세
    if stats['total_vulnerabilities'] > 0:
        st.warning(f"⚠️ {stats['total_vulnerabilities']}개 취약점 발견")
        
        # 직접 패키지 취약점
        if scan.get('direct_vulnerabilities'):
            st.subheader("📦 직접 패키지 취약점")
            for pkg_name, data in scan['direct_vulnerabilities'].items():
                with st.expander(f"{pkg_name} ({data['version']}) - {len(data['vulnerabilities'])}개"):
                    for vuln in data['vulnerabilities']:
                        st.write(f"• **{vuln['severity']}**: {vuln['id']}")
                        st.write(f"  {vuln['summary']}")
                        if vuln.get('fixed_version'):
                            st.success(f"  수정 버전: {vuln['fixed_version']}")
        
        # 간접 종속성 취약점
        if scan.get('indirect_vulnerabilities'):
            st.subheader("📎 간접 종속성 취약점")
            st.write(f"{len(scan['indirect_vulnerabilities'])}개 종속성에서 취약점 발견")
    else:
        st.success("✅ 알려진 패키지 취약점이 없습니다!")

def generate_integrated_report(results):
    """통합 보고서 생성"""
    st.subheader("📋 종합 보안 보고서")
    
    report = f"""# 보안 분석 보고서
생성 시간: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}

## 1. 분석 요약
"""
    
    # SBOM 요약
    if 'sbom' in results:
        sbom = results['sbom']
        report += f"""
### SBOM 분석
- 전체 패키지: {sbom['summary']['external_packages']}개
- 간접 종속성: {sbom['summary'].get('indirect_dependencies', 0)}개
- 버전 확인: {sbom['summary']['with_version']}개
"""
    
    # 패키지 취약점 요약
    if 'vulnerability' in results:
        vuln_stats = results['vulnerability'].get('vulnerability_scan', {}).get('statistics', {})
        report += f"""
### 패키지 취약점
- 검사한 패키지: {vuln_stats.get('total_checked', 0)}개
- 발견된 취약점: {vuln_stats.get('total_vulnerabilities', 0)}개
  - CRITICAL: {vuln_stats.get('critical', 0)}개
  - HIGH: {vuln_stats.get('high', 0)}개
  - MEDIUM: {vuln_stats.get('medium', 0)}개
  - LOW: {vuln_stats.get('low', 0)}개
"""
    
    # AI 분석 요약
    if 'ai_analysis' in results and results['ai_analysis'].get('success'):
        analysis = results['ai_analysis']['analysis']
        report += f"""
### 코드 보안 분석
- 보안 점수: {analysis.get('security_score', 0)}/100
- 코드 취약점: {len(analysis.get('code_vulnerabilities', []))}개
- {analysis.get('summary', '')}
"""
        
        # 주요 발견사항
        critical_vulns = [v for v in analysis.get('code_vulnerabilities', []) if v.get('severity') == 'CRITICAL']
        if critical_vulns:
            report += "\n## 2. 치명적 취약점\n"
            for vuln in critical_vulns:
                report += f"- **라인 {vuln.get('line_numbers', ['?'])[0]}**: {vuln['type']}\n"
                report += f"  - {vuln.get('description', '')}\n"
    
    st.text_area("보고서 내용", report, height=400)
    
    st.download_button(
        "📥 보고서 다운로드",
        data=report,
        file_name=f"security_report_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown"
    )

def provide_download_options(results):
    """다운로드 옵션 제공"""
    st.subheader("💾 결과 다운로드")
    
    col1, col2, col3 = st.columns(3)
    
    # 전체 결과 JSON
    with col1:
        if results:
            st.download_button(
                "📥 전체 결과 (JSON)",
                data=json.dumps(results, indent=2, default=str),
                file_name="analysis_results.json",
                mime="application/json"
            )
    
    # SBOM 다운로드
    with col2:
        if 'sbom' in results:
            st.download_button(
                "📥 SBOM (JSON)",
                data=json.dumps(results['sbom'], indent=2),
                file_name="sbom.json",
                mime="application/json"
            )
    
    # AI 분석 결과
    with col3:
        if 'ai_analysis' in results:
            st.download_button(
                "📥 AI 분석 (JSON)",
                data=json.dumps(results['ai_analysis'], indent=2, default=str),
                file_name="ai_analysis.json",
                mime="application/json"
            )

def create_sbom_summary(sbom_data):
    """SBOM 요약 생성"""
    if not sbom_data:
        return "SBOM 정보 없음"
    
    return {
        'total_packages': sbom_data['summary']['external_packages'],
        'indirect_dependencies': sbom_data['summary'].get('indirect_dependencies', 0),
        'total_vulnerabilities': sbom_data['summary'].get('total_vulnerabilities', 0)
    }

def get_vulnerable_example():
    """취약한 코드 예제"""
    return """import sqlite3
import hashlib
import pickle

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
PASSWORD = "admin123"

def load_data(data):
    # 안전하지 않은 역직렬화
    return pickle.loads(data)
"""

def get_safe_example():
    """안전한 코드 예제"""
    return """import sqlite3
import hashlib
import secrets
import os

def get_user(user_id):
    # 파라미터화된 쿼리
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
PASSWORD = os.environ.get('DB_PASSWORD')
"""