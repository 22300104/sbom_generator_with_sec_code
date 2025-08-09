"""
Data models for SBOM Security Analyzer
"""
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime

@dataclass
class VulnerabilityInfo:
    """취약점 정보"""
    id: str
    summary: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    fixed_version: Optional[str] = None
    published_date: Optional[str] = None

@dataclass
class PackageInfo:
    """패키지 정보"""
    name: str
    install_name: str
    version: Optional[str]
    alias: Optional[str]
    status: str
    vulnerabilities: List[Dict[str, Any]]

@dataclass
class AnalysisResult:
    """분석 결과"""
    success: bool
    packages: List[Dict[str, Any]]
    summary: Dict[str, int]
    error: Optional[str] = None

@dataclass
class ChunkInfo:
    """텍스트 청크 정보"""
    id: int
    text: str
    char_count: int
    metadata: Optional[Dict[str, Any]] = None