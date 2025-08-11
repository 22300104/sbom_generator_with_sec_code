"""
Core SBOM analysis logic - 개선 버전
실제 설치된 패키지와 종속성 분석 기능 추가
"""
import ast
import re
from typing import List, Dict, Optional
from config import analyzer_config
from core.models import AnalysisResult, PackageInfo
from core.environment_scanner import EnvironmentScanner  # 새로 추가

class SBOMAnalyzer:
    """SBOM 분석기 - 환경 스캔 기능 통합"""
    
    def __init__(self):
        self.config = analyzer_config
        self.env_scanner = EnvironmentScanner()  # 환경 스캐너 추가
    
    def extract_imports(self, code: str) -> List[Dict]:
        """Python 코드에서 import 문 추출"""
        imports = []
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append({
                            "name": alias.name,
                            "alias": alias.asname,
                            "type": "import"
                        })
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    imports.append({
                        "name": module,
                        "alias": None,
                        "type": "from"
                    })
        except SyntaxError as e:
            return {"error": f"코드 문법 오류: {e}"}
        
        # 중복 제거
        unique_imports = []
        seen = set()
        
        for imp in imports:
            package_name = imp["name"].split(".")[0]
            if package_name and package_name not in seen:
                seen.add(package_name)
                unique_imports.append({
                    "name": package_name,
                    "alias": imp["alias"],
                    "type": imp["type"]
                })
        
        return unique_imports
    
    def parse_requirements(self, requirements_text: str) -> Dict[str, Optional[str]]:
        """requirements.txt 파싱"""
        packages = {}
        
        if not requirements_text:
            return packages
        
        for line in requirements_text.strip().split('\n'):
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            if '==' in line:
                name, version = line.split('==')
                packages[name.strip()] = version.strip()
            elif any(op in line for op in ['>=', '<=', '>', '<']):
                name = re.split('[><=]', line)[0]
                version = line[len(name):]
                packages[name.strip()] = version
            else:
                packages[line.strip()] = None
        
        return packages
    
    def analyze(self, code: str, requirements: str = None, scan_environment: bool = True) -> Dict:
        """메인 분석 함수 - 환경 스캔 옵션 추가"""
        imports = self.extract_imports(code)
        
        if isinstance(imports, dict) and "error" in imports:
            return imports
        
        # requirements.txt 파싱
        req_versions = self.parse_requirements(requirements) if requirements else {}
        
        # 실제 환경 스캔 (새 기능!)
        installed_packages = {}
        env_comparison = None
        
        if scan_environment:
            installed_packages = self.env_scanner.scan_installed_packages()
            if req_versions:
                env_comparison = self.env_scanner.compare_with_requirements(req_versions)
        
        result = []
        all_dependencies = set()  # 모든 종속성 추적
        
        for imp in imports:
            import_name = imp["name"]
            
            if self._is_standard_library(import_name):
                continue
            
            package_name = self._get_package_install_name(import_name)
            package_name_lower = package_name.lower()
            
            # 실제 설치된 버전 확인 (새 기능!)
            actual_version = None
            if package_name_lower in installed_packages:
                actual_version = installed_packages[package_name_lower]['version']
            
            # 종속성 가져오기 (새 기능!)
            dependencies = []
            if scan_environment and package_name_lower in installed_packages:
                deps = self.env_scanner.get_all_dependencies(package_name)
                all_dependencies.update(deps)
                dependencies = list(deps)
            
            package_info = {
                "name": import_name,
                "install_name": package_name,
                "alias": imp["alias"],
                "required_version": req_versions.get(package_name, None),  # requirements.txt 버전
                "actual_version": actual_version,  # 실제 설치 버전 (새 기능!)
                "version": actual_version or req_versions.get(package_name, None),  # 호환성을 위해 유지
                "dependencies": dependencies,  # 종속성 목록 (새 기능!)
                "dependencies_count": len(dependencies),  # 종속성 개수 (새 기능!)
                "vulnerabilities": []
            }
            
            # 버전 상태 설정 (개선됨!)
            if actual_version:
                if package_name in req_versions:
                    if req_versions[package_name]:
                        # requirements와 실제 버전 비교
                        if self.env_scanner._version_matches(actual_version, req_versions[package_name]):
                            package_info["status"] = f"✅ 버전 일치 ({actual_version})"
                        else:
                            package_info["status"] = f"⚠️ 버전 불일치 (요구: {req_versions[package_name]}, 실제: {actual_version})"
                    else:
                        package_info["status"] = f"✅ 설치됨 ({actual_version})"
                else:
                    package_info["status"] = f"📦 설치됨 (requirements 없음, {actual_version})"
            else:
                if package_name in req_versions:
                    package_info["status"] = "❌ 미설치 (requirements에는 있음)"
                else:
                    package_info["status"] = "❓ 미설치"
            
            result.append(package_info)
        
        # 간접 종속성 분석 (새 기능!)
        indirect_dependencies = []
        for dep_name in all_dependencies:
            # 직접 import되지 않은 종속성들
            if not any(p['install_name'].lower() == dep_name for p in result):
                dep_info = installed_packages.get(dep_name, {})
                if dep_info:
                    indirect_dependencies.append({
                        "name": dep_name,
                        "version": dep_info.get('version', 'unknown'),
                        "type": "indirect",
                        "status": "📎 간접 종속성"
                    })
        
        # 환경 정보 추가 (새 기능!)
        env_stats = self.env_scanner.get_stats() if scan_environment else None
        
        return {
            "success": True,
            "packages": result,
            "indirect_dependencies": indirect_dependencies,  # 새 기능!
            "environment_comparison": env_comparison,  # 새 기능!
            "environment_stats": env_stats,  # 새 기능!
            "summary": {
                "total_imports": len(imports),
                "external_packages": len(result),
                "with_version": sum(1 for p in result if p.get("actual_version")),
                "without_version": sum(1 for p in result if not p.get("actual_version")),
                "total_dependencies": len(all_dependencies),  # 새 기능!
                "indirect_dependencies": len(indirect_dependencies),  # 새 기능!
                "version_mismatches": sum(1 for p in result if "불일치" in p.get("status", ""))  # 새 기능!
            }
        }
    
    def _get_package_install_name(self, import_name: str) -> str:
        """import명을 실제 설치 패키지명으로 변환"""
        return self.config.PACKAGE_NAME_MAPPING.get(import_name, import_name)
    
    def _is_standard_library(self, module_name: str) -> bool:
        """Python 표준 라이브러리인지 확인"""
        return module_name in self.config.STDLIB_MODULES