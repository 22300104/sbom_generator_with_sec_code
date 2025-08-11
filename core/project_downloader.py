"""
프로젝트 다운로더 - GitHub 링크 및 압축파일 처리
"""
import os
import shutil
import tempfile
import zipfile
import tarfile
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import re
import subprocess
import json

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False
    print("⚠️ GitPython이 설치되지 않았습니다. pip install GitPython")

try:
    import py7zr
    P7Z_AVAILABLE = True
except ImportError:
    P7Z_AVAILABLE = False

try:
    import rarfile
    RAR_AVAILABLE = True
except ImportError:
    RAR_AVAILABLE = False


class ProjectDownloader:
    """GitHub 저장소 및 압축파일 다운로드/추출"""
    
    def __init__(self):
        self.temp_dir = None
        self.project_path = None
        self.supported_archives = ['.zip', '.tar', '.tar.gz', '.tar.bz2', '.tgz']
        if P7Z_AVAILABLE:
            self.supported_archives.append('.7z')
        if RAR_AVAILABLE:
            self.supported_archives.append('.rar')
    
    def download_github(self, github_url: str) -> Tuple[bool, str, Optional[str]]:
        """
        GitHub 저장소 다운로드
        Returns: (성공여부, 메시지, 프로젝트 경로)
        """
        try:
            # URL 파싱
            parsed = self._parse_github_url(github_url)
            if not parsed:
                return False, "유효한 GitHub URL이 아닙니다.", None
            
            owner, repo, branch, subpath = parsed
            
            # 임시 디렉토리 생성
            self.temp_dir = tempfile.mkdtemp(prefix="sbom_analyzer_")
            
            # 다운로드 방법 선택
            if GIT_AVAILABLE and not subpath:
                # Git clone 사용 (전체 저장소)
                return self._clone_repository(owner, repo, branch)
            else:
                # ZIP 다운로드 사용 (빠르고 가벼움)
                return self._download_as_zip(owner, repo, branch, subpath)
                
        except Exception as e:
            return False, f"다운로드 실패: {str(e)}", None
    
    def extract_archive(self, file_path: str) -> Tuple[bool, str, Optional[str]]:
        """
        압축파일 추출
        Returns: (성공여부, 메시지, 프로젝트 경로)
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return False, "파일이 존재하지 않습니다.", None
            
            # 임시 디렉토리 생성
            self.temp_dir = tempfile.mkdtemp(prefix="sbom_analyzer_")
            extract_path = Path(self.temp_dir) / "extracted"
            extract_path.mkdir(exist_ok=True)
            
            # 확장자별 처리
            suffix = file_path.suffix.lower()
            
            if suffix == '.zip':
                with zipfile.ZipFile(file_path, 'r') as zf:
                    zf.extractall(extract_path)
                    
            elif suffix in ['.tar', '.tar.gz', '.tgz', '.tar.bz2']:
                mode = 'r:gz' if suffix in ['.tar.gz', '.tgz'] else 'r:bz2' if suffix == '.tar.bz2' else 'r'
                with tarfile.open(file_path, mode) as tf:
                    tf.extractall(extract_path)
                    
            elif suffix == '.7z' and P7Z_AVAILABLE:
                with py7zr.SevenZipFile(file_path, mode='r') as zf:
                    zf.extractall(extract_path)
                    
            elif suffix == '.rar' and RAR_AVAILABLE:
                with rarfile.RarFile(file_path) as rf:
                    rf.extractall(extract_path)
            else:
                return False, f"지원하지 않는 파일 형식: {suffix}", None
            
            # 프로젝트 루트 찾기
            self.project_path = self._find_project_root(extract_path)
            
            # 프로젝트 정보 수집
            info = self._analyze_project_structure(self.project_path)
            
            return True, f"추출 완료: {info['summary']}", self.project_path
            
        except Exception as e:
            return False, f"압축 해제 실패: {str(e)}", None
    
    def _parse_github_url(self, url: str) -> Optional[Tuple[str, str, str, Optional[str]]]:
        """
        GitHub URL 파싱
        Returns: (owner, repo, branch, subpath)
        """
        # 다양한 GitHub URL 형식 지원
        patterns = [
            # https://github.com/owner/repo
            r'github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$',
            # https://github.com/owner/repo/tree/branch
            r'github\.com/([^/]+)/([^/]+)/tree/([^/]+)/?(.*)$',
            # https://github.com/owner/repo/blob/branch/path
            r'github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                groups = match.groups()
                if len(groups) == 2:
                    return groups[0], groups[1], 'main', None
                elif len(groups) == 4:
                    return groups[0], groups[1], groups[2], groups[3] or None
        
        return None
    
    def _clone_repository(self, owner: str, repo: str, branch: str) -> Tuple[bool, str, Optional[str]]:
        """Git clone으로 저장소 다운로드"""
        try:
            repo_url = f"https://github.com/{owner}/{repo}.git"
            clone_path = Path(self.temp_dir) / repo
            
            # Clone (shallow clone으로 빠르게)
            git.Repo.clone_from(
                repo_url, 
                clone_path,
                branch=branch,
                depth=1  # shallow clone
            )
            
            self.project_path = clone_path
            info = self._analyze_project_structure(self.project_path)
            
            return True, f"저장소 클론 완료: {info['summary']}", self.project_path
            
        except Exception as e:
            return False, f"Git clone 실패: {str(e)}", None
    
    def _download_as_zip(self, owner: str, repo: str, branch: str, subpath: Optional[str]) -> Tuple[bool, str, Optional[str]]:
        """ZIP 파일로 다운로드"""
        try:
            # GitHub API를 통한 ZIP 다운로드
            zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
            
            # 다운로드
            response = requests.get(zip_url, stream=True, timeout=30)
            if response.status_code == 404:
                # branch가 main이 아닐 수도 있음 (master 시도)
                zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/master.zip"
                response = requests.get(zip_url, stream=True, timeout=30)
            
            response.raise_for_status()
            
            # 저장
            zip_path = Path(self.temp_dir) / f"{repo}.zip"
            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # 압축 해제
            extract_path = Path(self.temp_dir) / "extracted"
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(extract_path)
            
            # 프로젝트 경로 찾기
            self.project_path = self._find_project_root(extract_path)
            
            # subpath가 있으면 해당 경로로 이동
            if subpath and self.project_path:
                subpath_full = self.project_path / subpath
                if subpath_full.exists():
                    self.project_path = subpath_full
            
            info = self._analyze_project_structure(self.project_path)
            
            return True, f"다운로드 완료: {info['summary']}", self.project_path
            
        except Exception as e:
            return False, f"ZIP 다운로드 실패: {str(e)}", None
    
    def _find_project_root(self, extract_path: Path) -> Path:
        """프로젝트 루트 디렉토리 찾기"""
        # 추출된 내용 확인
        contents = list(extract_path.iterdir())
        
        # 단일 디렉토리만 있으면 그것이 프로젝트 루트
        if len(contents) == 1 and contents[0].is_dir():
            return contents[0]
        
        # Python 프로젝트 표시자 찾기
        markers = ['setup.py', 'pyproject.toml', 'requirements.txt', 'manage.py', 'app.py', 'main.py']
        
        # 현재 디렉토리에 마커가 있는지 확인
        for marker in markers:
            if (extract_path / marker).exists():
                return extract_path
        
        # 하위 디렉토리 검색
        for item in contents:
            if item.is_dir():
                for marker in markers:
                    if (item / marker).exists():
                        return item
        
        # 못 찾으면 추출 경로 반환
        return extract_path
    
    def _analyze_project_structure(self, project_path: Path) -> Dict:
        """프로젝트 구조 분석"""
        info = {
            'root': str(project_path),
            'python_files': [],
            'requirements_files': [],
            'config_files': [],
            'total_lines': 0,
            'file_count': 0,
            'has_tests': False,
            'frameworks': [],
            'summary': ''
        }
        
        if not project_path or not project_path.exists():
            return info
        
        # Python 파일 검색
        for py_file in project_path.rglob('*.py'):
            # 가상환경 및 캐시 제외
            if any(skip in str(py_file) for skip in ['venv', '__pycache__', '.git', 'node_modules']):
                continue
            
            rel_path = py_file.relative_to(project_path)
            info['python_files'].append(str(rel_path))
            info['file_count'] += 1
            
            # 라인 수 계산
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    info['total_lines'] += len(f.readlines())
            except:
                pass
            
            # 테스트 파일 확인
            if 'test' in py_file.stem.lower():
                info['has_tests'] = True
            
            # 프레임워크 감지
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1000)  # 처음 1000자만
                    if 'django' in content.lower():
                        info['frameworks'].append('Django')
                    if 'flask' in content.lower():
                        info['frameworks'].append('Flask')
                    if 'fastapi' in content.lower():
                        info['frameworks'].append('FastAPI')
                    if 'streamlit' in content.lower():
                        info['frameworks'].append('Streamlit')
            except:
                pass
        
        # requirements 파일 찾기
        for req_pattern in ['requirements*.txt', 'Pipfile', 'pyproject.toml', 'setup.py']:
            for req_file in project_path.glob(req_pattern):
                info['requirements_files'].append(str(req_file.name))
        
        # 설정 파일 찾기
        for config_pattern in ['.env*', '*.ini', '*.yaml', '*.yml', '*.json']:
            for config_file in project_path.glob(config_pattern):
                if not config_file.name.startswith('.git'):
                    info['config_files'].append(str(config_file.name))
        
        # 중복 제거
        info['frameworks'] = list(set(info['frameworks']))
        
        # 요약 생성
        summary_parts = []
        summary_parts.append(f"Python 파일 {info['file_count']}개")
        summary_parts.append(f"총 {info['total_lines']:,}줄")
        
        if info['frameworks']:
            summary_parts.append(f"프레임워크: {', '.join(info['frameworks'])}")
        if info['has_tests']:
            summary_parts.append("테스트 포함")
        if info['requirements_files']:
            summary_parts.append(f"의존성: {', '.join(info['requirements_files'])}")
        
        info['summary'] = ', '.join(summary_parts)
        
        return info
    
    def analyze_project_files(self, project_path: Path, max_files: int = 100) -> Dict:
        """프로젝트의 모든 Python 파일 분석용 데이터 수집"""
        result = {
            'files': [],
            'combined_code': '',
            'combined_requirements': '',
            'statistics': {
                'total_files': 0,
                'total_lines': 0,
                'skipped_files': 0,
                'large_files': 0
            }
        }
        
        # requirements 파일들 읽기
        req_contents = []
        for req_file in ['requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt']:
            req_path = project_path / req_file
            if req_path.exists():
                try:
                    with open(req_path, 'r', encoding='utf-8', errors='ignore') as f:
                        req_contents.append(f.read())
                except:
                    pass
        
        # Pipfile 처리
        pipfile_path = project_path / 'Pipfile'
        if pipfile_path.exists():
            try:
                with open(pipfile_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # 간단한 파싱 (실제로는 toml 파서 사용 권장)
                    req_contents.append(self._parse_pipfile(content))
            except:
                pass
        
        # pyproject.toml 처리
        pyproject_path = project_path / 'pyproject.toml'
        if pyproject_path.exists():
            try:
                with open(pyproject_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    req_contents.append(self._parse_pyproject(content))
            except:
                pass
        
        result['combined_requirements'] = '\n'.join(req_contents)
        
        # Python 파일들 수집
        all_code = []
        py_files = list(project_path.rglob('*.py'))
        
        # 파일 정렬 (중요한 파일 우선)
        priority_files = ['main.py', 'app.py', 'manage.py', '__init__.py']
        py_files.sort(key=lambda x: (
            0 if x.name in priority_files else 1,
            x.stat().st_size  # 작은 파일 우선
        ))
        
        for py_file in py_files[:max_files]:
            # 제외 경로
            if any(skip in str(py_file) for skip in ['venv', '__pycache__', '.git', 'migrations', 'tests']):
                result['statistics']['skipped_files'] += 1
                continue
            
            try:
                # 파일 크기 체크 (100KB 이상은 스킵)
                if py_file.stat().st_size > 100 * 1024:
                    result['statistics']['large_files'] += 1
                    continue
                
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                    
                    # 파일 정보 저장
                    rel_path = py_file.relative_to(project_path)
                    result['files'].append({
                        'path': str(rel_path),
                        'name': py_file.name,
                        'lines': len(code.splitlines()),
                        'size': py_file.stat().st_size
                    })
                    
                    # 코드 결합 (파일 구분자 포함)
                    all_code.append(f"# ===== File: {rel_path} =====\n{code}\n")
                    
                    result['statistics']['total_files'] += 1
                    result['statistics']['total_lines'] += len(code.splitlines())
                    
            except Exception as e:
                print(f"파일 읽기 실패 {py_file}: {e}")
                continue
        
        result['combined_code'] = '\n'.join(all_code)
        
        return result
    
    def _parse_pipfile(self, content: str) -> str:
        """Pipfile에서 패키지 추출 (간단한 파싱)"""
        packages = []
        in_packages = False
        
        for line in content.split('\n'):
            if '[packages]' in line:
                in_packages = True
                continue
            elif line.startswith('[') and in_packages:
                break
            elif in_packages and '=' in line:
                pkg = line.split('=')[0].strip()
                if pkg:
                    packages.append(pkg)
        
        return '\n'.join(packages)
    
    def _parse_pyproject(self, content: str) -> str:
        """pyproject.toml에서 패키지 추출 (간단한 파싱)"""
        packages = []
        in_deps = False
        
        for line in content.split('\n'):
            if 'dependencies' in line and '=' in line:
                in_deps = True
                continue
            elif line.startswith('[') and in_deps:
                break
            elif in_deps:
                # "package" 형태 추출
                match = re.search(r'"([^"]+)"', line)
                if match:
                    pkg = match.group(1)
                    # 버전 정보 제거
                    pkg = re.split(r'[<>=!]', pkg)[0]
                    if pkg:
                        packages.append(pkg)
        
        return '\n'.join(packages)
    
    def cleanup(self):
        """임시 파일 정리"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except:
                pass


# 테스트 코드
if __name__ == "__main__":
    downloader = ProjectDownloader()
    
    # GitHub URL 테스트
    test_urls = [
        "https://github.com/streamlit/streamlit",
        "https://github.com/django/django/tree/main/django/core",
    ]
    
    for url in test_urls:
        print(f"\nTesting: {url}")
        success, message, path = downloader.download_github(url)
        print(f"Success: {success}")
        print(f"Message: {message}")
        if path:
            print(f"Path: {path}")
            
            # 프로젝트 분석
            data = downloader.analyze_project_files(Path(path), max_files=10)
            print(f"Files analyzed: {data['statistics']['total_files']}")
            print(f"Total lines: {data['statistics']['total_lines']}")
        
        downloader.cleanup()