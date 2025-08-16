# cleanup_project.py
"""
프로젝트 정리 스크립트
불필요한 파일들을 삭제합니다.
"""
import os
import shutil
from pathlib import Path

def cleanup_project():
    """불필요한 파일 삭제"""
    
    # 삭제할 파일 목록
    files_to_delete = [
        # 테스트 파일
        'test.py',
        'test_gpt_analyzer.py',
        'test_rag_usage.py',
        'scripts/test_chromadb.py',
        'rag/test_rag.py',
        'rag/test_rag_improved.py',
        
        # 사용하지 않는 UI
        'ui/integrated_code_analysis_tab.py',
        'ui/project_analysis_tab.py',
        'ui/file_selector.py',
        
        # 사용하지 않는 Core
        'core/analysis_history.py',
        'core/project_comparator.py',
        'core/llm_analyzer.py',
        
        # 초기 설정 스크립트
        'scripts/prepare_vector.py',
    ]
    
    deleted_files = []
    not_found_files = []
    
    for file_path in files_to_delete:
        full_path = Path(file_path)
        if full_path.exists():
            try:
                full_path.unlink()
                deleted_files.append(file_path)
                print(f"✅ 삭제됨: {file_path}")
            except Exception as e:
                print(f"❌ 삭제 실패: {file_path} - {e}")
        else:
            not_found_files.append(file_path)
            print(f"⚠️ 파일 없음: {file_path}")
    
    # 결과 요약
    print("\n" + "="*50)
    print(f"📊 정리 완료!")
    print(f"  - 삭제된 파일: {len(deleted_files)}개")
    print(f"  - 찾을 수 없는 파일: {len(not_found_files)}개")
    
    # 빈 디렉토리 정리
    clean_empty_dirs()
    
    return deleted_files, not_found_files

def clean_empty_dirs():
    """빈 디렉토리 삭제"""
    for root, dirs, files in os.walk('.', topdown=False):
        for dir_name in dirs:
            dir_path = Path(root) / dir_name
            # __pycache__는 항상 삭제
            if dir_name == '__pycache__':
                try:
                    shutil.rmtree(dir_path)
                    print(f"🗑️ __pycache__ 삭제: {dir_path}")
                except:
                    pass
            # 빈 디렉토리 삭제
            elif not any(dir_path.iterdir()):
                try:
                    dir_path.rmdir()
                    print(f"📁 빈 디렉토리 삭제: {dir_path}")
                except:
                    pass

if __name__ == "__main__":
    print("🧹 프로젝트 정리 시작...")
    print("="*50)
    cleanup_project()