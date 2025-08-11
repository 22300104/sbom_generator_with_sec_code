"""
개선된 프로젝트 다운로더 - 스마트 필터링 및 사용자 코드 우선 분석
"""
import os
import shutil
import tempfile
import zipfile
import tarfile
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
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


class SmartProjectDownloader:
    """스마트한 프로젝트 다운로더 - 사용자 코드 중심 분석"""
    
    def __init__(self):
        self.temp_dir = None
        self.project_path = None
        self.supported_archives = ['.zip', '.tar', '.tar.gz', '.tar.bz2', '.tgz']
        if P7Z_AVAILABLE:
            self.supported_archives.append('.7z')
        if RAR_AVAILABLE:
            self.supported_archives.append('.rar')
        
        # 확장된 제외 패턴
        self.EXCLUDE_PATTERNS = {
            # 가상환경 및 패키지
            'venv', 'env', '.venv', '.env', 'virtualenv',
            'site-packages', 'dist-packages', 'node_modules',
            
            # 캐시 및 임시 파일
            '__pycache__', '.pyc', '.pyo', '.pyd',
            '.pytest_cache', '.tox', '.coverage', 'htmlcov',
            
            # 버전 관리
            '.git', '.svn', '.hg', '.bzr',
            
            # 빌드 및 배포
            'build', 'dist', '.build', 'target', 'out',
            'bin', 'obj', 'pkg',
            
            # IDE 및 편집기
            '.vscode', '.idea', '.eclipse', '*.swp', '*.swo',
            
            # 문서 및 예제
            'docs', 'documentation', 'doc', 'manual',
            'examples', 'example', 'samples', 'sample',
            'tutorial', 'tutorials', 'demo', 'demos',
            
            # 테스트 (선택적 제외)
            'tests', 'test', 'testing', '__tests__',
            'spec', 'specs', 'fixtures',
            
            # 설정 및 메타데이터
            '.github', '.gitlab', '.circleci', '.travis',
            'vendor', 'third_party', 'external',
            
            # 프레임워크별 제외
            'migrations',  # Django
            'static/admin', 'templates/admin',  # Django admin
            'manage.py',  # Django (때로는 포함하고 싶을 수도)
            
            # 언어별 패키지 관리자
            'bower_components', 'jspm_packages',
            'composer', 'vendor',
            
            # 로그 및 데이터 파일
            'logs', 'log', '*.log',
            'data', 'datasets', '*.db', '*.sqlite',
            
            # 미디어 파일
            'media', 'images', 'img', 'assets/images',
            'uploads', 'files', 'attachments',
        }
        
        # 사용자 코드 식별 패턴
        self.USER_CODE_PATTERNS = {
            # 일반적인 소스 디렉터리
            'src', 'source', 'app', 'application',
            'lib', 'libs', 'library', 'core',
            'common', 'shared', 'utils', 'utilities',
            'helpers', 'services', 'modules',
            
            # 웹 개발
            'web', 'www', 'public', 'static',
            'frontend', 'backend', 'client', 'server',
            'api', 'rest', 'graphql',
            
            # 프레임워크별
            'views', 'models', 'controllers',
            'components', 'pages', 'layouts',
            'middleware', 'decorators',
            
            # 특화 디렉터리
            'business', 'domain', 'logic',
            'config', 'settings', 'configurations',
            'handlers', 'processors', 'workers',
        }
        
        # 우선순위 파일 (반드시 포함)
        self.PRIORITY_FILES = {
            # 진입점
            'main.py', 'app.py', 'run.py', 'start.py',
            'server.py', 'wsgi.py', 'asgi.py',
            
            # Django
            'manage.py', 'settings.py', 'urls.py',
            'views.py', 'models.py', 'forms.py',
            'admin.py', 'serializers.py',
            
            # Flask/FastAPI
            'routes.py', 'blueprints.py', 'api.py',
            'endpoints.py', 'handlers.py',
            
            # 보안 관련
            'auth.py', 'authentication.py', 'authorization.py',
            'permissions.py', 'security.py', 'middleware.py',
            
            # 설정
            'config.py', 'configuration.py', 'env.py',
            'secrets.py', 'constants.py',
            
            # 비즈니스 로직
            'tasks.py', 'celery.py', 'worker.py',
            'services.py', 'utils.py', 'helpers.py',
            
            # 데이터베이스
            'database.py', 'db.py', 'orm.py',
            'schemas.py', 'validators.py',
        }
    
    def download_github(self, github_url: str) -> Tuple[bool, str, Optional[str]]:
        """GitHub 저장소 다운로드"""
        try:
            parsed = self._parse_github_url(github_url)
            if not parsed:
                return False, "유효한 GitHub URL이 아닙니다.", None
            
            owner, repo, branch, subpath = parsed
            
            # 임시 디렉토리 생성
            self.temp_dir = tempfile.mkdtemp(prefix="smart_analyzer_")
            
            # ZIP 다운로드 방법 사용 (더 빠르고 효율적)
            return self._download_as_zip(owner, repo, branch, subpath)
                
        except Exception as e:
            return False, f"다운로드 실패: {str(e)}", None
    
    def _parse_github_url(self, url: str) -> Optional[Tuple[str, str, str, Optional[str]]]:
        """GitHub URL 파싱"""
        patterns = [
            r'github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$',
            r'github\.com/([^/]+)/([^/]+)/tree/([^/]+)/?(.*)$',
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
    
    def _download_as_zip(self, owner: str, repo: str, branch: str, subpath: Optional[str]) -> Tuple[bool, str, Optional[str]]:
        """ZIP 파일로 다운로드"""
        try:
            # GitHub API를 통한 ZIP 다운로드
            zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
            
            response = requests.get(zip_url, stream=True, timeout=30)
            if response.status_code == 404:
                # main이 아닐 수도 있음 (master 시도)
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
            
            # 프로젝트 타입 감지
            project_type = self._detect_project_type(self.project_path)
            info = self._analyze_project_structure(self.project_path)
            
            summary = f"{project_type} 프로젝트 - {info['summary']}"
            
            return True, summary, self.project_path
            
        except Exception as e:
            return False, f"다운로드 실패: {str(e)}", None
    
    def _detect_project_type(self, project_path: Path) -> str:
        """프로젝트 타입 감지"""
        if not project_path or not project_path.exists():
            return "Unknown"
        
        # Django 확인
        if (project_path / 'manage.py').exists():
            return "Django"
        
        # Flask 확인
        flask_patterns = ['app.py', 'application.py', 'run.py']
        for pattern in flask_patterns:
            if (project_path / pattern).exists():
                # Flask인지 더 확실히 확인
                try:
                    with open(project_path / pattern, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(1000)
                        if 'flask' in content.lower():
                            return "Flask"
                except:
                    pass
        
        # FastAPI 확인
        if (project_path / 'main.py').exists():
            try:
                with open(project_path / 'main.py', 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1000)
                    if 'fastapi' in content.lower():
                        return "FastAPI"
            except:
                pass
        
        # Streamlit 확인
        py_files = list(project_path.glob('*.py'))
        for py_file in py_files[:5]:  # 상위 5개 파일만 확인
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1000)
                    if 'streamlit' in content.lower():
                        return "Streamlit"
            except:
                pass
        
        # 일반 Python 프로젝트인지 확인
        if any(project_path.glob('*.py')):
            if (project_path / 'requirements.txt').exists():
                return "Python Package"
            elif (project_path / 'setup.py').exists():
                return "Python Library"
            else:
                return "Python Project"
        
        return "Unknown"
    
    def _find_project_root(self, extract_path: Path) -> Path:
        """프로젝트 루트 디렉토리 찾기"""
        contents = list(extract_path.iterdir())
        
        # 단일 디렉토리만 있으면 그것이 프로젝트 루트
        if len(contents) == 1 and contents[0].is_dir():
            return contents[0]
        
        # Python 프로젝트 표시자 찾기
        markers = [
            'setup.py', 'pyproject.toml', 'requirements.txt', 
            'manage.py', 'app.py', 'main.py', 'run.py'
        ]
        
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
        
        return extract_path
    
    def smart_analyze_project_files(self, project_path: Path, include_tests: bool = False) -> Dict:
        """스마트한 프로젝트 파일 분석 - 사용자 코드 중심"""
        
        result = {
            'files': [],
            'combined_code': '',
            'combined_requirements': '',
            'statistics': {
                'total_files': 0,
                'analyzed_files': 0,
                'skipped_files': 0,
                'excluded_files': 0,
                'total_lines': 0,
                'user_code_lines': 0,
                'framework_lines': 0,
                'test_lines': 0,
            },
            'file_categories': {
                'entry_point': [],
                'core_logic': [],
                'security': [],
                'api': [],
                'utility': [],
                'config': [],
                'test': [],
                'framework': [],
                'other': []
            }
        }
        
        # requirements 파일들 읽기
        result['combined_requirements'] = self._extract_requirements(project_path)
        
        # Python 파일 수집 및 분류
        all_py_files = list(project_path.rglob('*.py'))
        result['statistics']['total_files'] = len(all_py_files)
        
        # 파일 분류
        categorized_files = self._categorize_files(all_py_files, project_path)
        
        # 우선순위에 따라 파일 선택
        selected_files = self._select_files_by_priority(
            categorized_files, 
            include_tests=include_tests
        )
        
        # 코드 결합
        all_code = []
        
        for category, files in selected_files.items():
            result['file_categories'][category] = []
            
            for py_file, rel_path in files:
                try:
                    file_info = self._process_file(py_file, rel_path, project_path)
                    if file_info:
                        result['files'].append(file_info)
                        result['file_categories'][category].append(file_info)
                        
                        # 코드 결합
                        all_code.append(f"# ===== File: {rel_path} ({category}) =====\n{file_info['content']}\n")
                        
                        # 통계 업데이트
                        result['statistics']['analyzed_files'] += 1
                        result['statistics']['total_lines'] += file_info['lines']
                        
                        if category in ['entry_point', 'core_logic', 'security', 'api', 'utility', 'config']:
                            result['statistics']['user_code_lines'] += file_info['lines']
                        elif category == 'test':
                            result['statistics']['test_lines'] += file_info['lines']
                        elif category == 'framework':
                            result['statistics']['framework_lines'] += file_info['lines']
                        
                except Exception as e:
                    result['statistics']['skipped_files'] += 1
                    continue
        
        result['combined_code'] = '\n'.join(all_code)
        
        return result
    
    def _extract_requirements(self, project_path: Path) -> str:
        """requirements 파일들 추출"""
        req_contents = []
        
        req_files = [
            'requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt',
            'requirements-test.txt', 'dev-requirements.txt',
            'Pipfile', 'pyproject.toml', 'setup.py'
        ]
        
        for req_file in req_files:
            req_path = project_path / req_file
            if req_path.exists():
                try:
                    with open(req_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if req_file == 'Pipfile':
                            req_contents.append(self._parse_pipfile(content))
                        elif req_file == 'pyproject.toml':
                            req_contents.append(self._parse_pyproject(content))
                        elif req_file == 'setup.py':
                            req_contents.append(self._parse_setup_py(content))
                        else:
                            req_contents.append(content)
                except:
                    pass
        
        return '\n'.join(req_contents)
    
    def _categorize_files(self, all_files: List[Path], project_path: Path) -> Dict[str, List[Tuple[Path, Path]]]:
        """파일들을 카테고리별로 분류"""
        categories = {
            'priority': [],      # 우선순위 파일들
            'user_code': [],     # 사용자 코드
            'framework': [],     # 프레임워크 관련
            'test': [],          # 테스트 파일
            'excluded': []       # 제외할 파일
        }
        
        for py_file in all_files:
            try:
                rel_path = py_file.relative_to(project_path)
                rel_path_str = str(rel_path).lower()
                file_name = py_file.name.lower()
                
                # 제외 패턴 체크
                if self._should_exclude_file(rel_path_str, file_name):
                    categories['excluded'].append((py_file, rel_path))
                    continue
                
                # 우선순위 파일
                if file_name in self.PRIORITY_FILES:
                    categories['priority'].append((py_file, rel_path))
                # 테스트 파일
                elif self._is_test_file(rel_path_str, file_name):
                    categories['test'].append((py_file, rel_path))
                # 프레임워크 파일
                elif self._is_framework_file(rel_path_str, file_name):
                    categories['framework'].append((py_file, rel_path))
                # 사용자 코드
                elif self._is_user_code(rel_path_str, file_name):
                    categories['user_code'].append((py_file, rel_path))
                else:
                    categories['user_code'].append((py_file, rel_path))  # 기본적으로 사용자 코드로 분류
                    
            except Exception:
                categories['excluded'].append((py_file, py_file.name))
                continue
        
        return categories
    
    def _should_exclude_file(self, rel_path_str: str, file_name: str) -> bool:
        """파일 제외 여부 판단"""
        # 기본 제외 패턴들
        for pattern in self.EXCLUDE_PATTERNS:
            if pattern in rel_path_str or pattern in file_name:
                return True
        
        # 특정 디렉터리 패턴
        exclude_dirs = [
            'migrations/', 'static/admin/', 'templates/admin/',
            'site-packages/', 'dist-packages/', 'node_modules/',
            'venv/', 'env/', '.venv/', '__pycache__/',
        ]
        
        for exclude_dir in exclude_dirs:
            if exclude_dir in rel_path_str:
                return True
        
        # 파일 크기 체크 (너무 큰 파일 제외)
        try:
            if Path(rel_path_str).stat().st_size > 2 * 1024 * 1024:  # 2MB 이상
                return True
        except:
            pass
        
        return False
    
    def _is_test_file(self, rel_path_str: str, file_name: str) -> bool:
        """테스트 파일인지 판단"""
        test_patterns = [
            'test_', '_test.py', 'tests/', '/test/', 'testing/',
            'spec_', '_spec.py', 'specs/', '/spec/',
            'conftest.py', 'pytest.ini'
        ]
        
        for pattern in test_patterns:
            if pattern in rel_path_str or pattern in file_name:
                return True
        
        return False
    
    def _is_framework_file(self, rel_path_str: str, file_name: str) -> bool:
        """프레임워크 파일인지 판단"""
        framework_patterns = [
            'migrations/', 'static/admin/', 'templates/admin/',
            'django/contrib/', 'flask/ext/', 'sqlalchemy/',
        ]
        
        for pattern in framework_patterns:
            if pattern in rel_path_str:
                return True
        
        # Django 마이그레이션 파일
        if 'migrations' in rel_path_str and file_name.startswith('0'):
            return True
        
        return False
    
    def _is_user_code(self, rel_path_str: str, file_name: str) -> bool:
        """사용자 코드인지 판단"""
        # 사용자 코드 패턴 확인
        for pattern in self.USER_CODE_PATTERNS:
            if pattern in rel_path_str:
                return True
        
        # 루트 레벨의 .py 파일은 대부분 사용자 코드
        if '/' not in rel_path_str and file_name.endswith('.py'):
            return True
        
        return False
    
    def _select_files_by_priority(self, categorized_files: Dict, include_tests: bool = False) -> Dict:
        """우선순위에 따라 파일 선택"""
        selected = {
            'entry_point': [],
            'core_logic': [],
            'security': [],
            'api': [],
            'utility': [],
            'config': [],
            'test': [],
            'framework': [],
            'other': []
        }
        
        # 1. 우선순위 파일들 (모두 포함)
        for py_file, rel_path in categorized_files['priority']:
            category = self._get_file_category(py_file.name, str(rel_path))
            selected[category].append((py_file, rel_path))
        
        # 2. 사용자 코드 (크기 제한 적용)
        user_code_files = sorted(
            categorized_files['user_code'],
            key=lambda x: self._get_file_priority_score(x[0], x[1])
        )
        
        for py_file, rel_path in user_code_files:
            category = self._get_file_category(py_file.name, str(rel_path))
            selected[category].append((py_file, rel_path))
        
        # 3. 테스트 파일 (선택적)
        if include_tests:
            for py_file, rel_path in categorized_files['test'][:10]:  # 최대 10개
                selected['test'].append((py_file, rel_path))
        
        # 4. 프레임워크 파일 (소수만)
        for py_file, rel_path in categorized_files['framework'][:5]:  # 최대 5개
            selected['framework'].append((py_file, rel_path))
        
        return selected
    
    def _get_file_priority_score(self, py_file: Path, rel_path: Path) -> int:
        """파일 우선순위 점수 계산 (높을수록 우선)"""
        score = 0
        file_name = py_file.name.lower()
        rel_path_str = str(rel_path).lower()
        
        # 파일명 기반 점수
        if file_name in ['views.py', 'models.py', 'api.py']:
            score += 100
        elif file_name in ['auth.py', 'security.py', 'permissions.py']:
            score += 90
        elif file_name in ['urls.py', 'routes.py', 'handlers.py']:
            score += 80
        elif file_name in ['forms.py', 'serializers.py', 'schemas.py']:
            score += 70
        elif file_name in ['utils.py', 'helpers.py', 'services.py']:
            score += 60
        
        # 경로 기반 점수
        if 'api/' in rel_path_str or 'views/' in rel_path_str:
            score += 50
        elif 'models/' in rel_path_str or 'core/' in rel_path_str:
            score += 40
        elif 'utils/' in rel_path_str or 'helpers/' in rel_path_str:
            score += 30
        
        # 파일 크기 기반 점수 (작은 파일 우선)
        try:
            file_size = py_file.stat().st_size
            if file_size < 10000:  # 10KB 이하
                score += 20
            elif file_size < 50000:  # 50KB 이하
                score += 10
        except:
            pass
        
        return score
    
    def _get_file_category(self, file_name: str, rel_path: str) -> str:
        """파일 카테고리 결정"""
        file_name_lower = file_name.lower()
        rel_path_lower = rel_path.lower()
        
        # 진입점
        if file_name_lower in ['main.py', 'app.py', 'run.py', 'manage.py', 'wsgi.py', 'asgi.py']:
            return 'entry_point'
        
        # 보안 관련
        if any(keyword in file_name_lower for keyword in ['auth', 'security', 'permission', 'middleware']):
            return 'security'
        
        # API 관련
        if any(keyword in rel_path_lower for keyword in ['api/', 'rest/', 'graphql/']):
            return 'api'
        elif file_name_lower in ['api.py', 'routes.py', 'endpoints.py', 'handlers.py']:
            return 'api'
        
        # 핵심 로직
        if file_name_lower in ['views.py', 'models.py', 'forms.py', 'serializers.py']:
            return 'core_logic'
        
        # 설정
        if any(keyword in file_name_lower for keyword in ['config', 'settings', 'env']):
            return 'config'
        
        # 유틸리티
        if any(keyword in file_name_lower for keyword in ['utils', 'helpers', 'common', 'tools']):
            return 'utility'
        
        # 테스트
        if any(keyword in rel_path_lower for keyword in ['test', 'spec']):
            return 'test'
        
        return 'other'
    
    def _process_file(self, py_file: Path, rel_path: Path, project_path: Path) -> Optional[Dict]:
        """개별 파일 처리"""
        try:
            with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # 빈 파일이나 너무 작은 파일 스킵
            if len(content.strip()) < 20:
                return None
            
            lines = content.splitlines()
            
            return {
                'path': str(rel_path),
                'name': py_file.name,
                'lines': len(lines),
                'size': py_file.stat().st_size,
                'content': content,
                'category': self._get_file_category(py_file.name, str(rel_path)),
                'is_user_code': self._is_user_code(str(rel_path).lower(), py_file.name.lower())
            }
            
        except Exception:
            return None
    
    def _parse_pipfile(self, content: str) -> str:
        """Pipfile에서 패키지 추출"""
        packages = []
        in_packages = False
        
        for line in content.split('\n'):
            line = line.strip()
            if '[packages]' in line:
                in_packages = True
                continue
            elif line.startswith('[') and in_packages:
                break
            elif in_packages and '=' in line and not line.startswith('#'):
                pkg = line.split('=')[0].strip().strip('"').strip("'")
                if pkg:
                    packages.append(pkg)
        
        return '\n'.join(packages)
    
    def _parse_pyproject(self, content: str) -> str:
        """pyproject.toml에서 패키지 추출"""
        packages = []
        in_deps = False
        
        for line in content.split('\n'):
            line = line.strip()
            if 'dependencies' in line and '=' in line:
                in_deps = True
                continue
            elif line.startswith('[') and in_deps:
                break
            elif in_deps and '"' in line:
                match = re.search(r'"([^"]+)"', line)
                if match:
                    pkg = match.group(1)
                    pkg = re.split(r'[<>=!~]', pkg)[0].strip()
                    if pkg:
                        packages.append(pkg)
        
        return '\n'.join(packages)
    
    def _parse_setup_py(self, content: str) -> str:
        """setup.py에서 패키지 추출"""
        packages = []
        
        # install_requires에서 패키지 추출
        install_requires_match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
        if install_requires_match:
            requirements_text = install_requires_match.group(1)
            for line in requirements_text.split(','):
                line = line.strip().strip('"').strip("'")
                if line and not line.startswith('#'):
                    pkg = re.split(r'[<>=!~]', line)[0].strip()
                    if pkg:
                        packages.append(pkg)
        
        return '\n'.join(packages)
    
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
            'security_files': [],
            'summary': ''
        }
        
        if not project_path or not project_path.exists():
            return info
        
        # 빠른 스캔으로 기본 정보 수집
        py_files = list(project_path.rglob('*.py'))[:100]  # 최대 100개만 스캔
        
        for py_file in py_files:
            try:
                if any(exclude in str(py_file) for exclude in ['venv', '__pycache__', '.git']):
                    continue
                
                rel_path = py_file.relative_to(project_path)
                info['python_files'].append(str(rel_path))
                info['file_count'] += 1
                
                # 간단한 라인 수 계산
                try:
                    with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = len(f.readlines())
                        info['total_lines'] += lines
                except:
                    pass
                
                # 특수 파일 체크
                file_name = py_file.name.lower()
                if 'test' in file_name or 'test' in str(rel_path).lower():
                    info['has_tests'] = True
                
                if any(sec in file_name for sec in ['auth', 'security', 'permission']):
                    info['security_files'].append(str(rel_path))
                
                # 프레임워크 감지 (파일명 기반)
                if file_name in ['manage.py']:
                    info['frameworks'].append('Django')
                elif file_name in ['app.py', 'application.py'] and 'flask' not in info['frameworks']:
                    # 파일 내용 확인 필요시에만
                    try:
                        with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(500)  # 처음 500자만
                            if 'flask' in content.lower():
                                info['frameworks'].append('Flask')
                            elif 'fastapi' in content.lower():
                                info['frameworks'].append('FastAPI')
                    except:
                        pass
                
            except Exception:
                continue
        
        # requirements 파일 찾기
        req_patterns = ['requirements*.txt', 'Pipfile', 'pyproject.toml', 'setup.py']
        for pattern in req_patterns:
            for req_file in project_path.glob(pattern):
                info['requirements_files'].append(str(req_file.name))
        
        # 중복 제거
        info['frameworks'] = list(set(info['frameworks']))
        
        # 요약 생성
        summary_parts = []
        summary_parts.append(f"Python 파일 {info['file_count']}개")
        if info['total_lines'] > 0:
            summary_parts.append(f"총 {info['total_lines']:,}줄")
        if info['frameworks']:
            summary_parts.append(f"{', '.join(info['frameworks'])}")
        if info['has_tests']:
            summary_parts.append("테스트 포함")
        if info['security_files']:
            summary_parts.append("보안 모듈 포함")
        
        info['summary'] = ', '.join(summary_parts)
        
        return info
    
    def cleanup(self):
        """임시 파일 정리"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except:
                pass


# 기존 호환성을 위한 별칭
ProjectDownloader = SmartProjectDownloader