# ui/code_analysis_tab.py
"""
Enhanced Code analysis tab UI - 성능 최적화 및 상태 유지 개선
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
import hashlib

def render_code_analysis_tab():
    """강화된 코드 분석 탭 - 최적화 버전"""
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
            ["⚡ 빠른 분석 (SBOM)", "🤖 AI 보안 분석 (GPT)", "🔥 전체 분석"],
            horizontal=True,
            help="AI 분석이 느리다면 빠른 분석을 먼저 시도하세요"
        )
    
    with col2:
        if llm_available and llm_analyzer:
            st.success(f"✅ GPT: {llm_analyzer.model}")
        else:
            st.error("❌ AI 불가")
    
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
            key="code_input_area",
            placeholder="import pandas as pd\nimport numpy as np\n..."
        )
    
    with col2:
        st.subheader("📦 requirements.txt")
        
        req_input = st.text_area(
            "requirements.txt 내용 (선택):",
            height=400,
            placeholder="pandas==2.0.0\nnumpy>=1.24.0\n...",
            key="req_input_area"
        )
    
    # 코드 해시 생성 (캐싱용)
    code_hash = hashlib.md5((code_input + req_input + analysis_mode).encode()).hexdigest()
    
    # 분석 버튼
    if st.button("🔍 보안 분석 시작", type="primary", use_container_width=True):
        if not code_input:
            st.warning("코드를 입력해주세요.")
            return
        
        # 이미 분석한 결과가 있는지 확인
        if f'analysis_result_{code_hash}' in st.session_state:
            st.info("📌 캐시된 결과를 표시합니다. 재분석하려면 코드를 수정하세요.")
        else:
            # 새로운 분석 실행
            with st.spinner("분석 중... (10-20초 소요)"):
                results = perform_analysis(
                    code_input, 
                    req_input, 
                    analysis_mode, 
                    analyzer, 
                    llm_analyzer, 
                    llm_available
                )
                
                # 결과를 세션에 저장
                st.session_state[f'analysis_result_{code_hash}'] = results
                st.session_state.last_analysis_hash = code_hash
    
    # 저장된 결과 표시
    if 'last_analysis_hash' in st.session_state:
        result_key = f'analysis_result_{st.session_state.last_analysis_hash}'
        if result_key in st.session_state:
            display_cached_results(st.session_state[result_key])

def perform_analysis(code_input, req_input, analysis_mode, analyzer, llm_analyzer, llm_available):
    """실제 분석 수행 - 한 번만 실행"""
    results = {}
    start_time = time.time()
    
    try:
        # SBOM 분석 (빠른 분석 또는 전체 분석)
        if analysis_mode in ["⚡ 빠른 분석 (SBOM)", "🔥 전체 분석"]:
            sbom_result = analyzer.analyze(code_input, req_input, scan_environment=False)  # 환경 스캔 비활성화로 속도 개선
            if sbom_result.get("success"):
                results['sbom'] = sbom_result
        
        # AI 보안 분석 (AI 분석 또는 전체 분석)
        if analysis_mode in ["🤖 AI 보안 분석 (GPT)", "🔥 전체 분석"]:
            if llm_available:
                context = {}
                if 'sbom' in results:
                    context['packages'] = len(results['sbom'].get('packages', []))
                
                ai_result = llm_analyzer.analyze_code_security(code_input, context)
                results['ai_analysis'] = ai_result
    
    except Exception as e:
        st.error(f"❌ 분석 오류: {e}")
    
    results['analysis_time'] = time.time() - start_time
    return results

def display_cached_results(results):
    """캐시된 결과 표시 - 리렌더링 없이"""
    
    # 분석 시간 표시
    if 'analysis_time' in results:
        st.success(f"✅ 분석 완료 (소요시간: {results['analysis_time']:.1f}초)")
    
    # 요약 메트릭
    display_summary_metrics(results)
    
    # 결과가 있을 때만 탭 표시
    if results:
        # AI 분석 결과가 있으면 우선 표시
        if 'ai_analysis' in results and results['ai_analysis'].get('success'):
            display_ai_results_optimized(results['ai_analysis'])
        
        # SBOM 결과
        if 'sbom' in results:
            with st.expander("📊 SBOM 및 패키지 정보", expanded=False):
                display_sbom_info(results['sbom'])
        
        # 다운로드 옵션
        with st.expander("💾 결과 다운로드", expanded=False):
            provide_download_options(results)

def display_ai_results_optimized(ai_result):
    """AI 분석 결과 최적화 표시"""
    if not ai_result or not ai_result.get('success'):
        return
    
    analysis = ai_result['analysis']
    vulns = analysis.get('code_vulnerabilities', [])
    
    if not vulns:
        st.success("✅ 코드 취약점이 발견되지 않았습니다!")
        return
    
    st.subheader(f"⚠️ 발견된 보안 취약점 ({len(vulns)}개)")
    
    # 탭으로 구성 (더 깔끔한 UI)
    tab1, tab2, tab3 = st.tabs(["🔍 취약점 목록", "🔧 수정 코드", "📋 전체 보고서"])
    
    with tab1:
        # 취약점 목록 (간단히)
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_vulns = [v for v in vulns if v.get('severity') == severity]
            if severity_vulns:
                severity_color = {
                    'CRITICAL': '🔴', 'HIGH': '🟠', 
                    'MEDIUM': '🟡', 'LOW': '🟢'
                }[severity]
                
                st.write(f"### {severity_color} {severity} ({len(severity_vulns)}개)")
                
                for vuln in severity_vulns:
                    line = vuln.get('line_numbers', ['?'])[0]
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.write(f"**라인 {line}:** {vuln['type']}")
                        # AI 설명 (간결)
                        st.caption(vuln.get('description', '')[:100])
                    
                    with col2:
                        if st.button("상세", key=f"detail_{severity}_{line}"):
                            st.session_state[f'show_detail_{line}'] = True
                    
                    # 상세 정보 (클릭시만)
                    if st.session_state.get(f'show_detail_{line}', False):
                        with st.container():
                            # 취약한 코드
                            st.code(vuln.get('vulnerable_code', ''), language='python')
                            
                            # AI 설명
                            if vuln.get('ai_description'):
                                st.write("**🤖 AI 분석:**")
                                st.info(vuln.get('ai_description'))
                            
                            # RAG 설명 (있으면)
                            if vuln.get('rag_explanation'):
                                st.write("**📚 KISIA 가이드라인:**")
                                st.success(vuln.get('rag_explanation'))
                            
                            # 영향
                            if vuln.get('impact'):
                                st.write("**⚠️ 공격 시 영향:**")
                                st.warning(vuln.get('impact'))
    
    with tab2:
        # 수정 코드 (전체)
        st.write("### 🔧 취약점 수정 코드")
        
        for vuln in vulns:
            if vuln.get('recommended_fix') and isinstance(vuln['recommended_fix'], dict):
                fix = vuln['recommended_fix']
                line = vuln.get('line_numbers', ['?'])[0]
                
                with st.expander(f"라인 {line}: {vuln['type']}", expanded=False):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write("**Before:**")
                        st.code(fix.get('original_code', ''), language='python')
                    
                    with col2:
                        st.write("**After:**")
                        st.code(fix.get('fixed_code', ''), language='python')
                    
                    if fix.get('description'):
                        st.caption(f"💡 {fix['description']}")
    
    with tab3:
        # 전체 보고서
        generate_simple_report(analysis)

def generate_simple_report(analysis):
    """간단한 보고서 생성"""
    report = f"""# 보안 분석 보고서

## 요약
- 보안 점수: {analysis.get('security_score', 0)}/100
- 발견된 취약점: {len(analysis.get('code_vulnerabilities', []))}개

## 취약점 상세
"""
    
    for vuln in analysis.get('code_vulnerabilities', []):
        report += f"\n### {vuln['type']} (라인 {vuln.get('line_numbers', ['?'])[0]})\n"
        report += f"- 심각도: {vuln.get('severity', 'MEDIUM')}\n"
        report += f"- 설명: {vuln.get('description', '')}\n"
    
    st.text_area("보고서", report, height=400)
    
    st.download_button(
        "📥 보고서 다운로드",
        data=report,
        file_name="security_report.md",
        mime="text/markdown"
    )

def display_summary_metrics(results):
    """요약 메트릭 표시"""
    col1, col2, col3, col4 = st.columns(4)
    
    # AI 분석 메트릭
    if 'ai_analysis' in results and results['ai_analysis'].get('success'):
        analysis = results['ai_analysis']['analysis']
        
        with col1:
            score = analysis.get('security_score', 0)
            st.metric("보안 점수", f"{score}/100")
        
        with col2:
            vulns = len(analysis.get('code_vulnerabilities', []))
            st.metric("코드 취약점", vulns, 
                     delta="위험" if vulns > 0 else "안전",
                     delta_color="inverse")
        
        with col3:
            critical = sum(1 for v in analysis.get('code_vulnerabilities', []) 
                          if v.get('severity') == 'CRITICAL')
            if critical > 0:
                st.metric("치명적", critical, delta_color="inverse")
        
        with col4:
            high = sum(1 for v in analysis.get('code_vulnerabilities', []) 
                      if v.get('severity') == 'HIGH')
            if high > 0:
                st.metric("높음", high, delta_color="inverse")

def display_sbom_info(result):
    """SBOM 정보 간단 표시"""
    if not result:
        return
    
    st.write(f"📦 **패키지 분석 결과**")
    st.write(f"- 발견된 패키지: {result['summary']['external_packages']}개")
    st.write(f"- 버전 확인: {result['summary']['with_version']}개")
    
    if result.get("packages"):
        df_data = []
        for pkg in result["packages"][:10]:  # 상위 10개만
            df_data.append({
                "패키지": pkg["name"],
                "버전": pkg.get("actual_version", "미설치"),
                "상태": pkg["status"]
            })
        
        if df_data:
            df = pd.DataFrame(df_data)
            st.dataframe(df, use_container_width=True, hide_index=True)

def provide_download_options(results):
    """다운로드 옵션 제공"""
    col1, col2 = st.columns(2)
    
    with col1:
        if results:
            st.download_button(
                "📥 전체 결과 (JSON)",
                data=json.dumps(results, indent=2, default=str),
                file_name="analysis_results.json",
                mime="application/json"
            )
    
    with col2:
        if 'ai_analysis' in results:
            analysis = results['ai_analysis'].get('analysis', {})
            if analysis.get('code_vulnerabilities'):
                # 수정 코드만 추출
                fixes = []
                for vuln in analysis['code_vulnerabilities']:
                    if vuln.get('recommended_fix') and isinstance(vuln['recommended_fix'], dict):
                        fixes.append({
                            'line': vuln.get('line_numbers', ['?'])[0],
                            'type': vuln['type'],
                            'fixed_code': vuln['recommended_fix'].get('fixed_code', '')
                        })
                
                if fixes:
                    st.download_button(
                        "📥 수정 코드",
                        data=json.dumps(fixes, indent=2),
                        file_name="fixes.json",
                        mime="application/json"
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
"""