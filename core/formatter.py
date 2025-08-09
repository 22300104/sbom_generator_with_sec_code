"""
SBOM format converters
"""
import re
import uuid
from datetime import datetime
from typing import List, Dict

class SBOMFormatter:
    """SBOM을 표준 형식으로 변환"""
    
    def format_sbom(self, packages: List[Dict], format_type: str, metadata: Dict = None) -> Dict:
        """지정된 형식으로 SBOM 변환"""
        format_type = format_type.upper()
        
        if format_type == "SPDX":
            return self.to_spdx(packages, metadata or {})
        elif format_type == "CYCLONEDX":
            return self.to_cyclonedx(packages, metadata or {})
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def to_spdx(self, packages: List[Dict], metadata: Dict) -> Dict:
        """SPDX 2.3 형식으로 변환"""
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
            "packages": [],
            "relationships": []
        }
        
        for idx, pkg in enumerate(packages):
            spdx_pkg = {
                "SPDXID": f"SPDXRef-Package-{idx}",
                "name": pkg.get("install_name", pkg["name"]),
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "supplier": "NOASSERTION",
                "homepage": f"https://pypi.org/project/{pkg.get('install_name', pkg['name'])}/"
            }
            
            if pkg.get("version"):
                clean_version = re.sub(r'[><=!~^]', '', pkg["version"]).strip()
                spdx_pkg["versionInfo"] = clean_version
            
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
            spdx_doc["relationships"].append({
                "spdxElementId": doc_id,
                "relatedSpdxElement": f"SPDXRef-Package-{idx}",
                "relationshipType": "DESCRIBES"
            })
        
        return spdx_doc
    
    def to_cyclonedx(self, packages: List[Dict], metadata: Dict) -> Dict:
        """CycloneDX 1.4 형식으로 변환"""
        cyclonedx_doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [{"vendor": "SBOM Security Analyzer", "name": "sbom-analyzer", "version": "0.1.0"}],
                "component": {
                    "type": "application",
                    "name": metadata.get("project_name", "Python-Project"),
                    "version": metadata.get("project_version", "unknown")
                }
            },
            "components": []
        }
        
        for pkg in packages:
            component = {
                "type": "library",
                "bom-ref": f"pkg:{pkg.get('install_name', pkg['name'])}",
                "name": pkg.get("install_name", pkg["name"]),
                "purl": f"pkg:pypi/{pkg.get('install_name', pkg['name'])}"
            }
            
            if pkg.get("version"):
                clean_version = re.sub(r'[><=!~^]', '', pkg["version"]).strip()
                component["version"] = clean_version
                component["purl"] += f"@{clean_version}"
            
            if pkg.get("vulnerabilities"):
                component["vulnerabilities"] = []
                for vuln in pkg["vulnerabilities"]:
                    component["vulnerabilities"].append({
                        "id": vuln["id"],
                        "description": vuln["summary"],
                        "ratings": [{"severity": vuln["severity"].lower(), "method": "other"}],
                        "recommendation": f"Update to version {vuln['fixed_version']}" if vuln.get("fixed_version") else None
                    })
            
            cyclonedx_doc["components"].append(component)
        
        return cyclonedx_doc