"""
실제 Python 환경에서 설치된 패키지 스캔 모듈 (개선 버전)
pkg_resources 대신 importlib.metadata 사용
"""
import importlib.metadata
import subprocess
import json
from typing import Dict, List, Optional, Set
import re
import sys

class EnvironmentScanner:
    """실제 설치된 패키지와 종속성을 스캔 (importlib.metadata 사용)"""
    
    def __init__(self):
        self.installed_packages = {}
        self.dependency_tree = {}
    
    def scan_installed_packages(self) -> Dict[str, Dict]:
        """현재 환경에 설치된 모든 패키지 스캔"""
        packages = {}
        
        try:
            # importlib.metadata 사용 (Python 3.8+)
            for dist in importlib.metadata.distributions():
                # 패키지 이름 정규화 (- 를 _ 로, 소문자로)
                package_name = self._normalize_package_name(dist.metadata['Name'])
                
                package_info = {
                    'name': package_name,
                    'version': dist.version,
                    'location': str(dist._path) if hasattr(dist, '_path') else None,
                    'direct_dependencies': []
                }
                
                # 종속성 추출 (Requires-Dist 메타데이터 사용)
                if dist.requires:
                    for req in dist.requires:
                        # "package (>=version)" 형식 파싱
                        dep_name = re.split(r'[<>=!;]', req)[0].strip()
                        dep_name = self._normalize_package_name(dep_name)
                        
                        # 버전 스펙 추출
                        specifier = None
                        if '(' in req and ')' in req:
                            specifier = req[req.index('('):req.index(')')+1]
                        elif any(op in req for op in ['>=', '<=', '==', '>', '<']):
                            specifier = req[len(dep_name):].strip()
                        
                        # 조건부 종속성 무시 (예: ; python_version < "3.8")
                        if ';' not in req:
                            package_info['direct_dependencies'].append({
                                'name': dep_name,
                                'specifier': specifier
                            })
                
                packages[package_name] = package_info
            
            self.installed_packages = packages
            return packages
            
        except Exception as e:
            print(f"환경 스캔 오류: {e}")
            return {}
    
    def _normalize_package_name(self, name: str) -> str:
        """패키지 이름 정규화 (PyPI 표준)"""
        # 소문자로 변환하고 - 를 _ 로 변경
        return name.lower().replace('-', '_')
    
    def get_package_dependencies_tree(self, package_name: str) -> Dict:
        """특정 패키지의 전체 종속성 트리 구성"""
        package_name = self._normalize_package_name(package_name)
        
        if not self.installed_packages:
            self.scan_installed_packages()
        
        if package_name not in self.installed_packages:
            # 별칭 체크 (예: sklearn -> scikit_learn)
            aliases = {
                'sklearn': 'scikit_learn',
                'cv2': 'opencv_python',
                'pil': 'pillow',
                'bs4': 'beautifulsoup4'
            }
            
            if package_name in aliases:
                package_name = aliases[package_name]
            
            if package_name not in self.installed_packages:
                return {'error': f'Package {package_name} not found in environment'}
        
        # pipdeptree 사용 시도
        try:
            # 패키지 이름을 다시 하이픈 형식으로 (pipdeptree용)
            pipdeptree_name = package_name.replace('_', '-')
            result = subprocess.run(
                ['pipdeptree', '-p', pipdeptree_name, '--json'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                tree = json.loads(result.stdout)
                return self._parse_pipdeptree_output(tree)
        except (subprocess.SubprocessError, FileNotFoundError, json.JSONDecodeError):
            pass
        
        # pipdeptree가 없으면 기본 방법 사용
        return self._build_dependency_tree_manual(package_name)
    
    def _parse_pipdeptree_output(self, tree_data: List) -> Dict:
        """pipdeptree JSON 출력 파싱"""
        if not tree_data:
            return {}
        
        root = tree_data[0]
        
        def parse_node(node):
            deps = []
            for dep in node.get('dependencies', []):
                deps.append({
                    'name': self._normalize_package_name(dep['package_name']),
                    'version': dep['installed_version'],
                    'required_version': dep.get('required_version'),
                    'dependencies': parse_node(dep) if dep.get('dependencies') else []
                })
            return deps
        
        return {
            'name': self._normalize_package_name(root['package_name']),
            'version': root['installed_version'],
            'dependencies': parse_node(root)
        }
    
    def _build_dependency_tree_manual(self, package_name: str, visited: Set[str] = None) -> Dict:
        """수동으로 종속성 트리 구성 (순환 참조 방지)"""
        if visited is None:
            visited = set()
        
        package_name = self._normalize_package_name(package_name)
        
        if package_name in visited:
            return {'name': package_name, 'circular_reference': True}
        
        visited.add(package_name)
        
        if package_name not in self.installed_packages:
            return {'name': package_name, 'not_found': True}
        
        pkg_info = self.installed_packages[package_name]
        
        tree = {
            'name': package_name,
            'version': pkg_info['version'],
            'dependencies': []
        }
        
        for dep in pkg_info['direct_dependencies']:
            dep_tree = self._build_dependency_tree_manual(dep['name'], visited.copy())
            tree['dependencies'].append(dep_tree)
        
        return tree
    
    def get_all_dependencies(self, package_name: str) -> Set[str]:
        """패키지의 모든 종속성 목록 (중복 제거)"""
        package_name = self._normalize_package_name(package_name)
        
        # 별칭 처리
        aliases = {
            'sklearn': 'scikit_learn',
            'cv2': 'opencv_python',
            'pil': 'pillow',
            'bs4': 'beautifulsoup4'
        }
        
        if package_name in aliases:
            package_name = aliases[package_name]
        
        tree = self.get_package_dependencies_tree(package_name)
        
        all_deps = set()
        
        def collect_deps(node):
            if isinstance(node, dict):
                if 'name' in node:
                    all_deps.add(node['name'])
                if 'dependencies' in node:
                    for dep in node['dependencies']:
                        collect_deps(dep)
        
        collect_deps(tree)
        all_deps.discard(package_name)  # 자기 자신 제외
        
        return all_deps
    
    def compare_with_requirements(self, requirements_dict: Dict[str, str]) -> Dict:
        """requirements.txt와 실제 설치 버전 비교"""
        if not self.installed_packages:
            self.scan_installed_packages()
        
        comparison = {
            'matched': [],
            'version_mismatch': [],
            'not_installed': [],
            'not_in_requirements': []
        }
        
        # requirements에 있는 패키지 확인
        for req_name, req_version in requirements_dict.items():
            req_name_normalized = self._normalize_package_name(req_name)
            
            # 별칭 체크
            aliases = {
                'scikit-learn': 'scikit_learn',
                'scikit_learn': 'scikit_learn'
            }
            
            check_name = aliases.get(req_name_normalized, req_name_normalized)
            
            if check_name in self.installed_packages:
                installed_version = self.installed_packages[check_name]['version']
                
                if self._version_matches(installed_version, req_version):
                    comparison['matched'].append({
                        'name': req_name,
                        'required': req_version,
                        'installed': installed_version
                    })
                else:
                    comparison['version_mismatch'].append({
                        'name': req_name,
                        'required': req_version,
                        'installed': installed_version
                    })
            else:
                comparison['not_installed'].append({
                    'name': req_name,
                    'required': req_version
                })
        
        # 설치되었지만 requirements에 없는 패키지
        req_names_normalized = {self._normalize_package_name(name) for name in requirements_dict.keys()}
        for installed_name in self.installed_packages:
            if installed_name not in req_names_normalized:
                # requirements에 없는 패키지 (간접 종속성일 가능성)
                pass  # 너무 많아서 생략
        
        return comparison
    
    def _version_matches(self, installed: str, required: str) -> bool:
        """버전 스펙이 일치하는지 확인"""
        if not required or required == installed:
            return True
        
        # 간단한 버전 비교
        if '==' in required:
            return installed == required.replace('==', '').strip()
        elif '>=' in required:
            return self._compare_versions(installed, required.replace('>=', '').strip()) >= 0
        elif '<=' in required:
            return self._compare_versions(installed, required.replace('<=', '').strip()) <= 0
        elif '>' in required:
            return self._compare_versions(installed, required.replace('>', '').strip()) > 0
        elif '<' in required:
            return self._compare_versions(installed, required.replace('<', '').strip()) < 0
        
        return False
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """버전 비교 (-1: v1<v2, 0: v1==v2, 1: v1>v2)"""
        def normalize(v):
            # .post0 같은 suffix 제거
            v = re.sub(r'[^0-9.].*', '', v)
            return [int(x) for x in v.split('.') if x.isdigit()]
        
        try:
            v1_parts = normalize(v1)
            v2_parts = normalize(v2)
            
            # 길이 맞추기
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for p1, p2 in zip(v1_parts, v2_parts):
                if p1 < p2:
                    return -1
                elif p1 > p2:
                    return 1
            
            return 0
        except:
            return 0
    
    def get_stats(self) -> Dict:
        """환경 통계 정보"""
        if not self.installed_packages:
            self.scan_installed_packages()
        
        total_packages = len(self.installed_packages)
        
        # 종속성 개수 계산
        total_dependencies = 0
        for pkg in self.installed_packages.values():
            total_dependencies += len(pkg['direct_dependencies'])
        
        return {
            'total_packages': total_packages,
            'total_dependencies': total_dependencies,
            'python_version': self._get_python_version(),
            'pip_version': self._get_pip_version()
        }
    
    def _get_python_version(self) -> str:
        """Python 버전 확인"""
        return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    
    def _get_pip_version(self) -> str:
        """pip 버전 확인"""
        try:
            # importlib.metadata로 pip 버전 확인
            pip_version = importlib.metadata.version('pip')
            return pip_version
        except:
            try:
                # subprocess 방법
                result = subprocess.run(
                    [sys.executable, '-m', 'pip', '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    match = re.search(r'pip (\d+\.\d+\.\d+)', result.stdout)
                    if match:
                        return match.group(1)
            except:
                pass
        return "unknown"


# 테스트 코드
if __name__ == "__main__":
    scanner = EnvironmentScanner()
    
    print("🔍 환경 스캔 시작 (importlib.metadata 사용)...\n")
    
    # 1. 설치된 패키지 스캔
    packages = scanner.scan_installed_packages()
    print(f"✅ 총 {len(packages)}개 패키지 발견\n")
    
    # 2. 주요 패키지 종속성 확인
    test_packages = ['pandas', 'requests', 'numpy', 'streamlit']
    
    for pkg_name in test_packages:
        normalized_name = scanner._normalize_package_name(pkg_name)
        if normalized_name in packages:
            print(f"📦 {pkg_name} 종속성:")
            deps = scanner.get_all_dependencies(pkg_name)
            if deps:
                print(f"   → {len(deps)}개 종속 패키지: {', '.join(list(deps)[:5])}...")
            else:
                print(f"   → 종속성 없음")
            print()
    
    # 3. 통계
    stats = scanner.get_stats()
    print(f"📊 환경 정보:")
    print(f"   Python: {stats['python_version']}")
    print(f"   pip: {stats['pip_version']}")
    print(f"   총 패키지: {stats['total_packages']}")
    print(f"   총 종속성: {stats['total_dependencies']}")