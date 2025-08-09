"""
Configuration settings for SBOM Security Analyzer
"""
import os
from dataclasses import dataclass
from typing import Set, Dict

@dataclass
class AppConfig:
    """애플리케이션 설정"""
    APP_NAME = "SBOM Security Analyzer"
    VERSION = "0.1.0"
    PAGE_ICON = "🔒"
    LAYOUT = "wide"

@dataclass
class AnalyzerConfig:
    """분석기 설정"""
    # 패키지명 매핑 (import명 -> 설치명)
    PACKAGE_NAME_MAPPING: Dict[str, str] = None
    
    # 표준 라이브러리 목록
    STDLIB_MODULES: Set[str] = None
    
    def __post_init__(self):
        if self.PACKAGE_NAME_MAPPING is None:
            self.PACKAGE_NAME_MAPPING = {
                "sklearn": "scikit-learn",
                "cv2": "opencv-python",
                "PIL": "pillow",
                "yaml": "pyyaml",
                "bs4": "beautifulsoup4",
            }
        
        if self.STDLIB_MODULES is None:
            self.STDLIB_MODULES = {
                'os', 'sys', 'json', 're', 'math', 'random', 'datetime',
                'collections', 'itertools', 'functools', 'typing', 'pathlib',
                'urllib', 'http', 'csv', 'io', 'time', 'logging', 'ast',
                'copy', 'pickle', 'subprocess', 'threading', 'queue'
            }

@dataclass
class VulnerabilityConfig:
    """취약점 검사 설정"""
    OSV_API_URL = "https://api.osv.dev/v1/query"
    TIMEOUT = 5

@dataclass
class RAGConfig:
    """RAG 설정"""
    GUIDELINE_DIR = "data/guidelines"
    CHUNK_SIZE = 1000
    OVERLAP = 200
    TOP_K = 5

# 싱글톤 인스턴스들
app_config = AppConfig()
analyzer_config = AnalyzerConfig()
vulnerability_config = VulnerabilityConfig()
rag_config = RAGConfig()