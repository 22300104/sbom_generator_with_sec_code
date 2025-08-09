"""
Core SBOM analysis logic
"""
import ast
import re
from typing import List, Dict, Optional
from config import analyzer_config
from core.models import AnalysisResult, PackageInfo

class SBOMAnalyzer:
    """SBOM 분석기"""
    
    def __init__(self):
        self.config = analyzer_config
    
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
    
    def analyze(self, code: str, requirements: str = None) -> Dict:
        """메인 분석 함수"""
        imports = self.extract_imports(code)
        
        if isinstance(imports, dict) and "error" in imports:
            return imports
        
        versions = self.parse_requirements(requirements) if requirements else {}
        
        result = []
        
        for imp in imports:
            import_name = imp["name"]
            
            if self._is_standard_library(import_name):
                continue
            
            package_name = self._get_package_install_name(import_name)
            
            package_info = {
                "name": import_name,
                "install_name": package_name,
                "alias": imp["alias"],
                "version": versions.get(package_name, None),
                "vulnerabilities": []
            }
            
            # 버전 상태 설정
            if package_name in versions:
                if versions[package_name]:
                    package_info["status"] = "✅ 버전 확인됨"
                else:
                    package_info["status"] = "⚠️ 버전 미상"
            else:
                package_info["status"] = "❓ requirements.txt에 없음"
            
            result.append(package_info)
        
        return {
            "success": True,
            "packages": result,
            "summary": {
                "total_imports": len(imports),
                "external_packages": len(result),
                "with_version": sum(1 for p in result if p["version"]),
                "without_version": sum(1 for p in result if not p["version"])
            }
        }
    
    def _get_package_install_name(self, import_name: str) -> str:
        """import명을 실제 설치 패키지명으로 변환"""
        return self.config.PACKAGE_NAME_MAPPING.get(import_name, import_name)
    
    def _is_standard_library(self, module_name: str) -> bool:
        """Python 표준 라이브러리인지 확인"""
        return module_name in self.config.STDLIB_MODULES