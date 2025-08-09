"""
Backend logic for SBOM Security Analyzer
"""
import ast
import re
from typing import List, Dict, Optional

class SBOMAnalyzer:
    def __init__(self):
        # 패키지명 매핑 (import명 -> 설치명)
        # TODO: 나중에 PyPI API나 LLM으로 자동화
        self.PACKAGE_NAME_MAPPING = {
            "sklearn": "scikit-learn",
            "cv2": "opencv-python",
            "PIL": "pillow",
            "yaml": "pyyaml",
            "bs4": "beautifulsoup4",
        }
    
    def extract_imports(self, code: str) -> List[Dict]:
        """
        Python 코드에서 import 문을 찾아서 추출
        """
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
        """
        requirements.txt 내용을 파싱해서 패키지명과 버전 추출
        """
        packages = {}
        
        if not requirements_text:
            return packages
        
        lines = requirements_text.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            if '==' in line:
                name, version = line.split('==')
                packages[name.strip()] = version.strip()
            elif '>=' in line or '<=' in line or '>' in line or '<' in line:
                name = re.split('[><=]', line)[0]
                version = line[len(name):]
                packages[name.strip()] = version
            else:
                packages[line.strip()] = None
        
        return packages
    
    def _get_package_install_name(self, import_name: str) -> str:
        """import명을 실제 설치 패키지명으로 변환"""
        return self.PACKAGE_NAME_MAPPING.get(import_name, import_name)
    
    def analyze(self, code: str, requirements: str = None) -> Dict:
        """
        메인 분석 함수 - 코드와 requirements를 분석해서 SBOM 정보 생성
        """
        # 1. 코드에서 import 추출
        imports = self.extract_imports(code)
        
        if isinstance(imports, dict) and "error" in imports:
            return imports
        
        # 2. requirements에서 버전 정보 추출
        versions = self.parse_requirements(requirements) if requirements else {}
        
        # 3. import와 버전 정보 매칭
        result = []
        for imp in imports:
            import_name = imp["name"]
            
            # 표준 라이브러리는 제외
            if self._is_standard_library(import_name):
                continue
            
            # import명을 설치 패키지명으로 변환
            package_name = self._get_package_install_name(import_name)
            
            package_info = {
                "name": import_name,
                "install_name": package_name,  # 실제 설치명 추가
                "alias": imp["alias"],
                "version": versions.get(package_name, None)
            }
            
            # 버전 상태 표시
            if package_name in versions:
                if versions[package_name]:
                    package_info["status"] = "✅ 버전 확인됨"
                else:
                    package_info["status"] = "⚠️ 버전 미상"
            else:
                package_info["status"] = "❓ requirements.txt에 없음"
            
            result.append(package_info)
        
        # backend.py의 analyze 함수 마지막 부분
        return {
            "success": True,
            "packages": result,
            "summary": {
                "total_imports": len(imports),
                "external_packages": len(result),  # 이 줄 추가
                "with_version": sum(1 for p in result if p["version"]),
                "without_version": sum(1 for p in result if not p["version"])
            }
        }
    
    def _is_standard_library(self, module_name: str) -> bool:
        """Python 표준 라이브러리인지 확인"""
        stdlib = {
            'os', 'sys', 'json', 're', 'math', 'random', 'datetime',
            'collections', 'itertools', 'functools', 'typing', 'pathlib',
            'urllib', 'http', 'csv', 'io', 'time', 'logging', 'ast'
        }
        return module_name in stdlib

# 테스트
if __name__ == "__main__":
    analyzer = SBOMAnalyzer()
    
    test_code = """
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import os
import json
    """
    
    test_requirements = """
pandas==2.0.0
numpy>=1.24.0
scikit-learn
requests
    """
    
    result = analyzer.analyze(test_code, test_requirements)
    
    # 보기 좋게 출력
    if result["success"]:
        print("\n=== 분석 결과 ===")
        print(f"전체 import: {result['summary']['total_imports']}")
        print(f"외부 패키지: {result['summary']['external_packages']}")
        print(f"버전 확인됨: {result['summary']['with_version']}")
        print(f"버전 미확인: {result['summary']['without_version']}")
        print("\n=== 패키지 목록 ===")
        for pkg in result["packages"]:
            print(f"{pkg['status']} {pkg['name']}")
            if pkg['install_name'] != pkg['name']:
                print(f"   → 설치명: {pkg['install_name']}")
            if pkg['version']:
                print(f"   버전: {pkg['version']}")
            if pkg['alias']:
                print(f"   별칭: {pkg['alias']}")