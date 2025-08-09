"""
Backend logic for SBOM Security Analyzer
"""
import ast
import re
import requests
from typing import List, Dict, Optional
from dataclasses import dataclass
import json

@dataclass
class VulnerabilityInfo:
    """취약점 정보"""
    id: str  # CVE-2021-12345
    summary: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    fixed_version: Optional[str] = None
    published_date: Optional[str] = None

class VulnerabilityChecker:
    """OSV API를 사용한 취약점 검사"""
    
    def __init__(self):
        self.osv_api_url = "https://api.osv.dev/v1/query"
    
    def check_package(self, package_name: str, version: str) -> List[VulnerabilityInfo]:
        """
        패키지의 취약점 검사
        """
        if not version or not package_name:
            return []
        
        # 버전에서 연산자 제거 (>=2.0.0 -> 2.0.0)
        clean_version = re.sub(r'[><=!~^]', '', version).strip()
        
        # 버전이 유효한지 확인
        if not clean_version or not re.match(r'^\d+(\.\d+)*', clean_version):
            print(f"유효하지 않은 버전: {version} -> {clean_version}")
            return []
        
        try:
            # OSV API 요청
            payload = {
                "package": {
                    "name": package_name,
                    "ecosystem": "PyPI"
                },
                "version": clean_version
            }
            
            print(f"  Checking {package_name} {clean_version}...")  # 디버깅용
            
            response = requests.post(
                self.osv_api_url, 
                json=payload,
                timeout=5
            )
            
            if response.status_code != 200:
                print(f"  OSV API 응답 오류: {response.status_code}")
                return []
            
            data = response.json()
            vulnerabilities = []
            
            # OSV 응답에서 취약점 정보 추출
            for vuln in data.get("vulns", []):
                # 심각도 결정
                severity = self._get_severity(vuln)
                
                # 수정된 버전 찾기
                fixed_version = self._get_fixed_version(vuln, package_name)
                
                vuln_info = VulnerabilityInfo(
                    id=vuln.get("id", "Unknown"),
                    summary=vuln.get("summary", vuln.get("details", "No description")),
                    severity=severity,
                    fixed_version=fixed_version,
                    published_date=vuln.get("published", "")
                )
                vulnerabilities.append(vuln_info)
            
            if vulnerabilities:
                print(f"  ⚠️ {len(vulnerabilities)}개 취약점 발견!")
            else:
                print(f"  ✅ 취약점 없음")
            
            return vulnerabilities
            
        except requests.exceptions.Timeout:
            print(f"  OSV API 타임아웃: {package_name}")
            return []
        except Exception as e:
            print(f"  OSV API 오류: {e}")
            return []
    
    def _get_severity(self, vuln_data: dict) -> str:
        """취약점 심각도 판단"""
        # CVSS 점수 기반 심각도
        severity_data = vuln_data.get("severity", [])
        
        for sev in severity_data:
            if sev.get("type") == "CVSS_V3":
                # score가 문자열일 수 있으므로 float로 변환
                try:
                    score = float(sev.get("score", 0))
                    if score >= 9.0:
                        return "CRITICAL"
                    elif score >= 7.0:
                        return "HIGH"
                    elif score >= 4.0:
                        return "MEDIUM"
                    else:
                        return "LOW"
                except (TypeError, ValueError):
                    continue
        
        # CVSS 점수가 없으면 중간으로 설정
        return "MEDIUM"
    
    def _get_fixed_version(self, vuln_data: dict, package_name: str) -> Optional[str]:
        """수정된 버전 찾기"""
        affected = vuln_data.get("affected", [])
        
        for aff in affected:
            if aff.get("package", {}).get("name") == package_name:
                ranges = aff.get("ranges", [])
                for r in ranges:
                    events = r.get("events", [])
                    for event in events:
                        if "fixed" in event:
                            return event["fixed"]
        
        return None

class SBOMAnalyzer:
    def __init__(self):
        # 패키지명 매핑 (import명 -> 설치명)
        self.PACKAGE_NAME_MAPPING = {
            "sklearn": "scikit-learn",
            "cv2": "opencv-python",
            "PIL": "pillow",
            "yaml": "pyyaml",
            "bs4": "beautifulsoup4",
        }
        
        # 취약점 검사기 추가
        self.vulnerability_checker = VulnerabilityChecker()
    
    def extract_imports(self, code: str) -> List[Dict]:
        """Python 코드에서 import 문을 찾아서 추출"""
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
        """requirements.txt 내용을 파싱해서 패키지명과 버전 추출"""
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
    
    def analyze(self, code: str, requirements: str = None, check_vulnerabilities: bool = True) -> Dict:
        """
        메인 분석 함수 - 코드와 requirements를 분석해서 SBOM 정보 생성
        
        Args:
            code: Python 코드
            requirements: requirements.txt 내용
            check_vulnerabilities: 취약점 검사 여부
        """
        # 1. 코드에서 import 추출
        imports = self.extract_imports(code)
        
        if isinstance(imports, dict) and "error" in imports:
            return imports
        
        # 2. requirements에서 버전 정보 추출
        versions = self.parse_requirements(requirements) if requirements else {}
        
        # 3. import와 버전 정보 매칭
        result = []
        total_vulnerabilities = 0
        
        for imp in imports:
            import_name = imp["name"]
            
            # 표준 라이브러리는 제외
            if self._is_standard_library(import_name):
                continue
            
            # import명을 설치 패키지명으로 변환
            package_name = self._get_package_install_name(import_name)
            
            package_info = {
                "name": import_name,
                "install_name": package_name,
                "alias": imp["alias"],
                "version": versions.get(package_name, None),
                "vulnerabilities": []
            }
            
            # 버전 상태 표시
            if package_name in versions:
                if versions[package_name]:
                    package_info["status"] = "✅ 버전 확인됨"
                    
                    # 취약점 검사
                    if check_vulnerabilities:
                        vulns = self.vulnerability_checker.check_package(
                            package_name, 
                            versions[package_name]
                        )
                        if vulns:
                            package_info["vulnerabilities"] = [
                                {
                                    "id": v.id,
                                    "summary": v.summary[:100] + "..." if len(v.summary) > 100 else v.summary,
                                    "severity": v.severity,
                                    "fixed_version": v.fixed_version
                                }
                                for v in vulns
                            ]
                            package_info["status"] = f"⚠️ 취약점 {len(vulns)}개 발견"
                            total_vulnerabilities += len(vulns)
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
                "without_version": sum(1 for p in result if not p["version"]),
                "total_vulnerabilities": total_vulnerabilities,
                "vulnerable_packages": sum(1 for p in result if p["vulnerabilities"])
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
import requests
from sklearn.model_selection import train_test_split
    """
    
    # 일부러 오래된 버전 사용 (취약점 테스트)
    test_requirements = """
pandas==2.0.0
numpy>=1.24.0
requests==2.25.0
scikit-learn
    """
    
    print("취약점 검사 중...")
    result = analyzer.analyze(test_code, test_requirements)
    
    if result["success"]:
        print("\n=== 분석 결과 ===")
        print(f"전체 import: {result['summary']['total_imports']}")
        print(f"외부 패키지: {result['summary']['external_packages']}")
        print(f"발견된 취약점: {result['summary']['total_vulnerabilities']}")
        
        print("\n=== 패키지 목록 ===")
        for pkg in result["packages"]:
            print(f"{pkg['status']} {pkg['name']}")
            if pkg['version']:
                print(f"   버전: {pkg['version']}")
            
            if pkg['vulnerabilities']:
                print(f"   🚨 취약점:")
                for vuln in pkg['vulnerabilities']:
                    print(f"      - {vuln['id']} ({vuln['severity']})")
                    if vuln['fixed_version']:
                        print(f"        수정 버전: {vuln['fixed_version']}")