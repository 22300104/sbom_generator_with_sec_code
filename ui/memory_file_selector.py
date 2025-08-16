# ui/memory_file_selector.py
"""
메모리 기반 파일 선택 UI
실제 파일 시스템이 아닌 세션 상태의 데이터를 사용
"""
import streamlit as st
from typing import List, Dict, Tuple

class MemoryFileSelector:
    """메모리 기반 파일 선택기"""
    
    def __init__(self, project_files: List[Dict]):
        """
        Args:
            project_files: 세션에 저장된 파일 정보 리스트
                [{
                    'path': 'src/main.py',
                    'content': '...',
                    'size': 1234,
                    'lines': 50
                }, ...]
        """
        self.project_files = project_files
        
        # 세션 상태 초기화
        if 'selected_files' not in st.session_state:
            st.session_state.selected_files = set()
    
    def render(self) -> List[str]:
        """파일 선택 UI 렌더링"""
        if not self.project_files:
            st.warning("파일이 없습니다.")
            return []
        
        # 통계 계산
        total_files = len(self.project_files)
        total_size = sum(f['size'] for f in self.project_files)
        total_lines = sum(f['lines'] for f in self.project_files)
        
        # 선택된 파일 통계
        selected_files = [f for f in self.project_files if f['path'] in st.session_state.selected_files]
        selected_count = len(selected_files)
        selected_size = sum(f['size'] for f in selected_files)
        selected_lines = sum(f['lines'] for f in selected_files)
        
        # 헤더 정보
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("총 파일", f"{total_files}개")
        with col2:
            st.metric("총 크기", self._format_size(total_size))
        with col3:
            st.metric("총 라인", f"{total_lines:,}줄")
        
        if selected_count > 0:
            st.success(f"""
            ✅ **선택됨**: {selected_count}개 파일 / 
            {self._format_size(selected_size)} / 
            {selected_lines:,}줄
            """)
        else:
            st.info("분석할 파일을 선택해주세요.")
        
        # 빠른 선택 버튼
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("✅ 전체 선택", use_container_width=True):
                st.session_state.selected_files = set(f['path'] for f in self.project_files)
        
        with col2:
            if st.button("❌ 전체 해제", use_container_width=True):
                st.session_state.selected_files = set()
        
        with col3:
            if st.button("⚡ 작은 파일만", use_container_width=True):
                small_files = [f for f in self.project_files if f['size'] < 10000]
                st.session_state.selected_files = set(f['path'] for f in small_files)
        
        with col4:
            if st.button("🎯 주요 파일만", use_container_width=True):
                important_names = ['main.py', 'app.py', 'views.py', 'models.py', 
                                 'auth.py', 'api.py', 'settings.py', 'config.py']
                selected = []
                for f in self.project_files:
                    file_name = f['path'].split('/')[-1]
                    if file_name in important_names or any(imp in f['path'].lower() for imp in ['auth', 'api', 'views']):
                        selected.append(f['path'])
                st.session_state.selected_files = set(selected[:20])
        
        st.divider()
        
        # 검색
        search = st.text_input("🔍 파일 검색", placeholder="파일명 또는 경로...")
        
        # 파일 필터링
        filtered_files = self.project_files
        if search:
            search_lower = search.lower()
            filtered_files = [f for f in self.project_files 
                            if search_lower in f['path'].lower()]
        
        # 파일 목록 표시
        st.write(f"### 파일 목록 ({len(filtered_files)}개)")
        
        # 디렉토리별 그룹화
        grouped = self._group_by_directory(filtered_files)
        
        for dir_name, dir_files in sorted(grouped.items()):
            selected_in_dir = sum(1 for f in dir_files if f['path'] in st.session_state.selected_files)
            
            with st.expander(f"📁 {dir_name} ({len(dir_files)}개 파일, {selected_in_dir}개 선택됨)", 
                           expanded=(selected_in_dir > 0)):
                
                for file_info in dir_files:
                    col1, col2, col3 = st.columns([5, 1, 1])
                    
                    with col1:
                        file_name = file_info['path'].split('/')[-1]
                        is_selected = file_info['path'] in st.session_state.selected_files
                        
                        if st.checkbox(
                            f"📄 {file_name}",
                            value=is_selected,
                            key=f"file_{file_info['path']}"
                        ):
                            st.session_state.selected_files.add(file_info['path'])
                        else:
                            st.session_state.selected_files.discard(file_info['path'])
                    
                    with col2:
                        st.caption(self._format_size(file_info['size']))
                    
                    with col3:
                        st.caption(f"{file_info['lines']}줄")
        
        return list(st.session_state.selected_files)
    
    def _group_by_directory(self, files: List[Dict]) -> Dict[str, List[Dict]]:
        """디렉토리별로 파일 그룹화"""
        grouped = {}
        for f in files:
            parts = f['path'].split('/')
            if len(parts) > 1:
                dir_name = '/'.join(parts[:-1])
            else:
                dir_name = '(root)'
            
            if dir_name not in grouped:
                grouped[dir_name] = []
            grouped[dir_name].append(f)
        
        return grouped
    
    def _format_size(self, size_bytes: int) -> str:
        """파일 크기 포맷"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
    
    def get_selected_code(self) -> Tuple[str, List[Dict]]:
        """선택된 파일의 코드 반환"""
        selected_files = [f for f in self.project_files 
                         if f['path'] in st.session_state.selected_files]
        
        if not selected_files:
            return "", []
        
        # 크기순 정렬
        selected_files.sort(key=lambda x: x['size'])
        
        # 코드 결합
        combined_code = []
        file_list = []
        
        for file_info in selected_files:
            # 파일 구분자
            combined_code.append(f"# ===== File: {file_info['path']} =====")
            combined_code.append(file_info['content'])
            combined_code.append("")
            
            file_list.append({
                'path': file_info['path'],
                'name': file_info['path'].split('/')[-1],
                'size': file_info['size'],
                'lines': file_info['lines']
            })
        
        return "\n".join(combined_code), file_list