"""
Enhanced Guideline management tab UI
"""
import streamlit as st
import pandas as pd
from rag.guideline_processor import GuidelineProcessor

def render_guideline_tab():
    """가이드라인 탭 렌더링 (개선된 UI)"""
    st.header("📚 가이드라인 RAG 준비")
    
    # 프로세서 초기화 또는 재로드
    if st.button("🔄 PDF 다시 로드"):
        st.session_state.pop('guideline_processor', None)
        st.session_state.pop('guideline_result', None)
        st.rerun()
    
    # 프로세서 초기화
    if 'guideline_processor' not in st.session_state:
        with st.spinner("📄 PDF 파일들을 처리 중..."):
            processor = GuidelineProcessor()
            result = processor.process_all_pdfs()
            st.session_state.guideline_processor = processor
            st.session_state.guideline_result = result
    
    processor = st.session_state.guideline_processor
    result = st.session_state.guideline_result
    
    # 처리 결과 표시
    if result.get("success"):
        st.success(f"✅ {result['files_processed']}개 PDF 파일 처리 완료!")
        
        # 전체 통계
        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.metric("📁 파일 수", result['files_processed'])
        with col2:
            st.metric("📄 총 청크", len(processor.chunks))
        with col3:
            st.metric("📊 총 표", result.get('total_tables', 0))
        with col4:
            st.metric("💻 코드 블록", result.get('total_code_blocks', 0))
        with col5:
            st.metric("📝 총 문자", f"{result['total_chars']:,}")
        
        # 처리 로그 표시
        with st.expander("📋 처리 로그", expanded=False):
            for log in result.get('processing_log', []):
                if "✅" in log:
                    st.success(log)
                elif "❌" in log:
                    st.error(log)
                elif "⚠️" in log:
                    st.warning(log)
                else:
                    st.info(log)
        
        # 문서별 상세 정보
        st.subheader("📑 문서별 상세 정보")
        
        summary = processor.get_processing_summary()
        if summary and summary.get("files"):
            df = pd.DataFrame(summary["files"])
            df.columns = ["파일명", "표 개수", "코드 블록", "문자 수"]
            
            # 스타일 적용
            st.dataframe(
                df.style.highlight_max(subset=["표 개수", "코드 블록", "문자 수"]),
                use_container_width=True
            )
        
        # 청크 미리보기
        st.subheader("🔍 청크 미리보기")
        
        col1, col2 = st.columns([1, 3])
        
        with col1:
            chunk_type = st.selectbox(
                "청크 타입",
                options=["전체", "텍스트", "표/코드 포함"],
                index=0
            )
            
            # 타입별 필터링
            if chunk_type == "텍스트":
                filtered_chunks = [c for c in processor.chunks if c.metadata.get("type") == "text"]
            elif chunk_type == "표/코드 포함":
                filtered_chunks = [c for c in processor.chunks if c.metadata.get("type") == "mixed"]
            else:
                filtered_chunks = processor.chunks
            
            if filtered_chunks:
                chunk_num = st.number_input(
                    f"청크 번호 (총 {len(filtered_chunks)}개)",
                    min_value=0,
                    max_value=len(filtered_chunks)-1,
                    value=0
                )
        
        with col2:
            if filtered_chunks:
                selected_chunk = filtered_chunks[chunk_num]
                
                # 청크 정보 표시
                chunk_info = f"청크 #{selected_chunk.id} | 타입: {selected_chunk.metadata.get('type', 'unknown')} | 크기: {selected_chunk.char_count}자"
                st.info(chunk_info)
                
                # 청크 내용 표시
                st.text_area(
                    "내용",
                    value=selected_chunk.text,
                    height=300,
                    disabled=True
                )
        
        # 검색 테스트
        st.subheader("🔎 검색 테스트")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            test_query = st.text_input(
                "검색어 입력",
                placeholder="예: 비밀번호, 암호화, SQL, 인증"
            )
        
        with col2:
            search_button = st.button("🔍 검색", type="primary", use_container_width=True)
        
        if test_query and search_button:
            with st.spinner("검색 중..."):
                similar_chunks = processor.search_similar_chunks(test_query, top_k=5)
            
            if similar_chunks:
                st.success(f"'{test_query}' 관련 상위 {len(similar_chunks)}개 청크 발견")
                
                for i, chunk in enumerate(similar_chunks, 1):
                    with st.expander(f"결과 #{i}"):
                        # 검색어 하이라이트
                        highlighted_text = chunk.replace(
                            test_query, 
                            f"**{test_query}**"
                        )
                        st.markdown(highlighted_text[:1000] + "..." if len(highlighted_text) > 1000 else highlighted_text)
            else:
                st.info("검색 결과가 없습니다.")
        
        # 다음 단계 안내
        st.divider()
        st.info("💡 다음 단계: ChromaDB에 임베딩 저장 → OpenAI와 연동하여 RAG 시스템 구축")
        
        # 임베딩 준비 버튼
        if st.button("🚀 임베딩 생성 준비", type="secondary"):
            chunks_for_embedding = processor.get_chunks_for_embedding()
            st.success(f"✅ {len(chunks_for_embedding)}개 청크 임베딩 준비 완료!")
            st.session_state.chunks_ready = True
    
    else:
        st.error("❌ PDF 처리 실패")
        if result.get("error"):
            st.error(f"오류: {result['error']}")
        
        # 디버깅 정보
        with st.expander("🔧 디버깅 정보"):
            st.write("Guidelines 디렉토리:", processor.config.GUIDELINE_DIR)
            st.write("처리 로그:", result.get("processing_log", []))