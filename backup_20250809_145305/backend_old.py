"""
Backend logic for SBOM Security Analyzer
"""
import ast
import re
import requests
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
import uuid

# ============================================
# Data Classes
# ============================================

@dataclass
class VulnerabilityInfo:
    """취약점 정보"""
    id: str  # CVE-2021-12345
    summary: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    fixed_version: Optional[str] = None
    published_date: Optional[str] = None

# ============================================
# Vulnerability Checker
# ============================================

class VulnerabilityChecker:
    """OSV API를 사용한 취약점 검사"""
    
    def __init__(self):
        self.osv_api_url = "https://api.osv.dev/v1/query"
    
    def check_package(self, package_name: str, version: str) -> List[VulnerabilityInfo]:
        """패키지의 취약점 검사"""
        if not version or not package_name:
            return []
        
        # 버전에서 연산자 제거 (>=2.0.0 -> 2.0.0)
        clean_version = re.sub(r'[><=!~^]', '', version).strip()
        
        # 버전이 유효한지 확인
        if not clean_version or not re.match(r'^\d+(\.\d+)*', clean_version):
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
            
            response = requests.post(
                self.osv_api_url, 
                json=payload,
                timeout=5
            )
            
            if response.status_code != 200:
                return []
            
            data = response.json()
            vulnerabilities = []
            
            # OSV 응답에서 취약점 정보 추출
            for vuln in data.get("vulns", []):
                severity = self._get_severity(vuln)
                fixed_version = self._get_fixed_version(vuln, package_name)
                
                vuln_info = VulnerabilityInfo(
                    id=vuln.get("id", "Unknown"),
                    summary=vuln.get("summary", vuln.get("details", "No description")),
                    severity=severity,
                    fixed_version=fixed_version,
                    published_date=vuln.get("published", "")
                )
                vulnerabilities.append(vuln_info)
            
            return vulnerabilities
            
        except (requests.exceptions.Timeout, Exception):
            return []
    
    def _get_severity(self, vuln_data: dict) -> str:
        """취약점 심각도 판단"""
        severity_data = vuln_data.get("severity", [])
        
        for sev in severity_data:
            if sev.get("type") == "CVSS_V3":
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

# ============================================
# SBOM Formatter
# ============================================

class SBOMFormatter:
    """SBOM을 표준 형식으로 변환"""
    
    def to_spdx(self, packages: List[Dict], metadata: Dict = None) -> Dict:
        """SPDX 2.3 형식으로 변환"""
        metadata = metadata or {}
        doc_id = f"SPDXRef-DOCUMENT-{uuid.uuid4().hex[:8]}"
        
        spdx_doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": doc_id,
            "name": metadata.get("project_name", "Python-Project"),
            "documentNamespace": f"https://sbom.example/spdxdocs/{doc_id}",
            "creationInfo": {
                "created": datetime.now().isoformat(),
                "creators": ["Tool: SBOM Security Analyzer-0.1.0"],
                "licenseListVersion": "3.19"
            },
            "packages": []
        }
        
        # 패키지 정보 변환
        for idx, pkg in enumerate(packages):
            spdx_pkg = {
                "SPDXID": f"SPDXRef-Package-{idx}",
                "name": pkg.get("install_name", pkg["name"]),
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "supplier": "NOASSERTION",
                "homepage": f"https://pypi.org/project/{pkg.get('install_name', pkg['name'])}/",
            }
            
            # 버전 정보
            if pkg.get("version"):
                clean_version = re.sub(r'[><=!~^]', '', pkg["version"]).strip()
                spdx_pkg["versionInfo"] = clean_version
            
            # 취약점 정보를 외부 참조로 추가
            if pkg.get("vulnerabilities"):
                spdx_pkg["externalRefs"] = []
                for vuln in pkg["vulnerabilities"]:
                    spdx_pkg["externalRefs"].append({
                        "referenceCategory": "SECURITY",
                        "referenceType": "vulnerability",
                        "referenceLocator": vuln["id"],
                        "comment": f"{vuln['severity']}: {vuln['summary'][:50]}..."
                    })
            
            spdx_doc["packages"].append(spdx_pkg)
        
        # 관계 정보 추가
        spdx_doc["relationships"] = [
            {
                "spdxElementId": doc_id,
                "relatedSpdxElement": f"SPDXRef-Package-{idx}",
                "relationshipType": "DESCRIBES"
            }
            for idx in range(len(packages))
        ]
        
        return spdx_doc
    
    def to_cyclonedx(self, packages: List[Dict], metadata: Dict = None) -> Dict:
        """CycloneDX 1.4 형식으로 변환"""
        metadata = metadata or {}
        
        cyclonedx_doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [
                    {
                        "vendor": "SBOM Security Analyzer",
                        "name": "sbom-analyzer",
                        "version": "0.1.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": metadata.get("project_name", "Python-Project"),
                    "version": metadata.get("project_version", "unknown")
                }
            },
            "components": []
        }
        
        # 컴포넌트 정보 변환
        for pkg in packages:
            component = {
                "type": "library",
                "bom-ref": f"pkg:{pkg.get('install_name', pkg['name'])}",
                "name": pkg.get("install_name", pkg["name"]),
                "purl": f"pkg:pypi/{pkg.get('install_name', pkg['name'])}",
            }
            
            # 버전 정보
            if pkg.get("version"):
                clean_version = re.sub(r'[><=!~^]', '', pkg["version"]).strip()
                component["version"] = clean_version
                component["purl"] += f"@{clean_version}"
            
            # 취약점 정보
            if pkg.get("vulnerabilities"):
                component["vulnerabilities"] = []
                for vuln in pkg["vulnerabilities"]:
                    vuln_info = {
                        "id": vuln["id"],
                        "description": vuln["summary"],
                        "ratings": [
                            {
                                "severity": vuln["severity"].lower(),
                                "method": "other"
                            }
                        ]
                    }
                    
                    if vuln.get("fixed_version"):
                        vuln_info["recommendation"] = f"Update to version {vuln['fixed_version']}"
                    
                    component["vulnerabilities"].append(vuln_info)
            
            cyclonedx_doc["components"].append(component)
        
        # 취약점 요약 추가
        total_vulns = sum(len(pkg.get("vulnerabilities", [])) for pkg in packages)
        if total_vulns > 0:
            cyclonedx_doc["metadata"]["properties"] = [
                {
                    "name": "total_vulnerabilities",
                    "value": str(total_vulns)
                },
                {
                    "name": "vulnerable_components",
                    "value": str(sum(1 for pkg in packages if pkg.get("vulnerabilities")))
                }
            ]
        
        return cyclonedx_doc
    
    def format_sbom(self, packages: List[Dict], format_type: str, metadata: Dict = None) -> Dict:
        """지정된 형식으로 SBOM 변환"""
        format_type = format_type.upper()
        
        if format_type == "SPDX":
            return self.to_spdx(packages, metadata)
        elif format_type == "CYCLONEDX":
            return self.to_cyclonedx(packages, metadata)
        else:
            # Custom JSON 형식은 app.py에서 처리
            raise ValueError(f"Unsupported format: {format_type}")

# ============================================
# Main SBOM Analyzer
# ============================================

class SBOMAnalyzer:
    """메인 SBOM 분석기"""
    
    def __init__(self):
        # 패키지명 매핑 (import명 -> 설치명)
        self.PACKAGE_NAME_MAPPING = {
            "sklearn": "scikit-learn",
            "cv2": "opencv-python",
            "PIL": "pillow",
            "yaml": "pyyaml",
            "bs4": "beautifulsoup4",
        }
        
        # 표준 라이브러리 목록
        self.STDLIB_MODULES = {
            'os', 'sys', 'json', 're', 'math', 'random', 'datetime',
            'collections', 'itertools', 'functools', 'typing', 'pathlib',
            'urllib', 'http', 'csv', 'io', 'time', 'logging', 'ast',
            'copy', 'pickle', 'subprocess', 'threading', 'queue'
        }
        
        # 컴포넌트 초기화
        self.vulnerability_checker = VulnerabilityChecker()
        self.formatter = SBOMFormatter()
    
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
    
    def analyze(self, code: str, requirements: str = None, check_vulnerabilities: bool = True) -> Dict:
        """메인 분석 함수"""
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
    
    def generate_sbom(self, packages: List[Dict], format_type: str, metadata: Dict = None) -> Dict:
        """분석 결과를 지정된 SBOM 형식으로 변환"""
        return self.formatter.format_sbom(packages, format_type, metadata)
    
    def _get_package_install_name(self, import_name: str) -> str:
        """import명을 실제 설치 패키지명으로 변환"""
        return self.PACKAGE_NAME_MAPPING.get(import_name, import_name)
    
    def _is_standard_library(self, module_name: str) -> bool:
        """Python 표준 라이브러리인지 확인"""
        return module_name in self.STDLIB_MODULES

# ============================================
# Test Code
# ============================================

if __name__ == "__main__":
    analyzer = SBOMAnalyzer()
    
    test_code = """
import pandas as pd
import numpy as np
import requests
from sklearn.model_selection import train_test_split
import json  # 표준 라이브러리
    """
    
    test_requirements = """
pandas==2.0.0
numpy>=1.24.0
requests==2.25.0
scikit-learn
    """
    
    print("=" * 50)
    print("SBOM 분석 테스트")
    print("=" * 50)
    
    # 기본 분석
    result = analyzer.analyze(test_code, test_requirements)
    
    if result["success"]:
        print(f"\n✅ 분석 성공!")
        print(f"- 전체 imports: {result['summary']['total_imports']}")
        print(f"- 외부 패키지: {result['summary']['external_packages']}")
        print(f"- 취약점: {result['summary']['total_vulnerabilities']}")
        
        # SBOM 형식 테스트
        print("\n📦 SBOM 형식 변환 테스트:")
        
        for format_type in ["SPDX", "CycloneDX"]:
            sbom = analyzer.generate_sbom(
                result["packages"], 
                format_type,
                {"project_name": "Test-Project", "project_version": "1.0.0"}
            )
            print(f"- {format_type}: ✅ (packages: {len(sbom.get('packages', sbom.get('components', [])))}")


# backend.py에 추가
import os
import PyPDF2
from typing import List, Dict
import glob

class GuidelineLoader:
    """여러 가이드라인 PDF 자동 로더"""
    
    def __init__(self):
        self.guideline_dir = "data/guidelines"
        self.documents = {}  # {파일명: 내용} 형태로 저장
        self.is_loaded = False
    
    def load_all_guidelines(self) -> Dict:
        """guidelines 폴더의 모든 PDF 자동 로드"""
        # .pdf 파일 모두 찾기
        pdf_files = glob.glob(os.path.join(self.guideline_dir, "*.pdf"))
        
        if not pdf_files:
            return {
                "success": False,
                "error": f"PDF 파일이 없습니다: {self.guideline_dir}"
            }
        
        loaded_count = 0
        failed_files = []
        
        for pdf_path in pdf_files:
            # 파일명 추출 (한글 파일명 그대로 사용)
            filename = os.path.basename(pdf_path)
            
            try:
                with open(pdf_path, 'rb') as file:
                    pdf_reader = PyPDF2.PdfReader(file)
                    
                    # 전체 텍스트 추출
                    full_text = ""
                    pages = []
                    
                    for page_num, page in enumerate(pdf_reader.pages, 1):
                        page_text = page.extract_text()
                        pages.append({
                            "page": page_num,
                            "text": page_text
                        })
                        full_text += page_text + "\n"
                    
                    # 문서 저장
                    self.documents[filename] = {
                        "path": pdf_path,
                        "full_text": full_text,
                        "pages": pages,
                        "num_pages": len(pages),
                        "total_chars": len(full_text)
                    }
                    
                    loaded_count += 1
                    print(f"✅ 로드 완료: {filename} ({len(pages)}페이지)")
                    
            except Exception as e:
                print(f"❌ 로드 실패: {filename} - {str(e)}")
                failed_files.append(filename)
        
        self.is_loaded = loaded_count > 0
        
        return {
            "success": self.is_loaded,
            "loaded": loaded_count,
            "failed": len(failed_files),
            "failed_files": failed_files,
            "total_files": len(pdf_files),
            "files": list(self.documents.keys())
        }
    
    def search_in_all(self, keyword: str) -> List[Dict]:
        """모든 가이드라인에서 키워드 검색"""
        if not self.is_loaded:
            self.load_all_guidelines()
        
        results = []
        keyword_lower = keyword.lower()
        
        for filename, doc in self.documents.items():
            for page in doc["pages"]:
                if keyword_lower in page["text"].lower():
                    text = page["text"]
                    index = text.lower().find(keyword_lower)
                    start = max(0, index - 150)
                    end = min(len(text), index + 150 + len(keyword))
                    
                    snippet = text[start:end].strip()
                    if start > 0:
                        snippet = "..." + snippet
                    if end < len(text):
                        snippet = snippet + "..."
                    
                    # 키워드 하이라이트 (간단한 마킹)
                    snippet = snippet.replace(keyword, f"**{keyword}**")
                    
                    results.append({
                        "file": filename,
                        "page": page["page"],
                        "snippet": snippet
                    })
        
        return results
    
    def get_document_list(self) -> List[Dict]:
        """로드된 문서 목록 반환"""
        doc_list = []
        for filename, doc in self.documents.items():
            doc_list.append({
                "filename": filename,
                "pages": doc["num_pages"],
                "characters": doc["total_chars"],
                "size_kb": doc["total_chars"] // 1024  # 대략적인 크기
            })
        return doc_list
    
    def get_document_content(self, filename: str, page: int = None) -> str:
        """특정 문서의 내용 반환"""
        if filename not in self.documents:
            return None
        
        doc = self.documents[filename]
        
        if page:
            # 특정 페이지만
            if 0 < page <= doc["num_pages"]:
                return doc["pages"][page-1]["text"]
        else:
            # 전체 내용
            return doc["full_text"]

# SBOMAnalyzer 클래스 수정
class SBOMAnalyzer:
    def __init__(self):
        # 기존 코드...
        
        # 가이드라인 로더 추가 및 자동 로드
        self.guideline_loader = GuidelineLoader()
        load_result = self.guideline_loader.load_all_guidelines()
        
        if load_result["success"]:
            print(f"\n=== 가이드라인 로드 완료 ===")
            print(f"✅ 성공: {load_result['loaded']}개")
            if load_result['failed'] > 0:
                print(f"❌ 실패: {load_result['failed']}개")