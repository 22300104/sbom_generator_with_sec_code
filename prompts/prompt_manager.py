# prompts/prompt_manager.py
"""
프롬프트 관리 유틸리티
간단한 헬퍼 함수들 제공
"""

from typing import Optional, Dict, Any
import os
from prompts.all_prompts import (
    SYSTEM_PROMPTS,
    SECURITY_PROMPTS,
    RAG_PROMPTS,
    VULNERABILITY_PRINCIPLES,
    build_security_analysis_prompt,
    build_rag_qa_prompt,
    get_system_prompt
)

class PromptManager:
    """중앙 프롬프트 관리자"""
    
    def __init__(self):
        self.cache = {}
        self.overrides = {}
        self._load_env_overrides()
    
    def _load_env_overrides(self):
        """환경변수에서 프롬프트 오버라이드 로드"""
        # 예: PROMPT_OVERRIDE_SECURITY_EXPERT 환경변수가 있으면 사용
        for key in SYSTEM_PROMPTS.keys():
            env_key = f"PROMPT_OVERRIDE_{key.upper()}"
            if os.getenv(env_key):
                self.overrides[key] = os.getenv(env_key)
    
    def get_prompt(self, category: str, prompt_type: str, **kwargs) -> str:
        """프롬프트 가져오기
        
        Args:
            category: "system", "security", "rag" 중 하나
            prompt_type: 프롬프트 타입
            **kwargs: 프롬프트 포맷팅에 필요한 인자
        
        Returns:
            포맷팅된 프롬프트 문자열
        """
        
        # 캐시 키 생성
        cache_key = f"{category}:{prompt_type}"
        
        # 오버라이드 확인
        if cache_key in self.overrides:
            template = self.overrides[cache_key]
        else:
            # 카테고리별 프롬프트 선택
            if category == "system":
                template = SYSTEM_PROMPTS.get(prompt_type)
            elif category == "security":
                template = SECURITY_PROMPTS.get(prompt_type)
            elif category == "rag":
                template = RAG_PROMPTS.get(prompt_type)
            else:
                raise ValueError(f"Unknown category: {category}")
        
        if not template:
            raise ValueError(f"Prompt not found: {category}:{prompt_type}")
        
        # kwargs가 있으면 포맷팅
        if kwargs:
            return template.format(**kwargs)
        
        return template
    
    def get_builder(self, builder_name: str):
        """프롬프트 빌더 함수 가져오기"""
        builders = {
            "security_analysis": build_security_analysis_prompt,
            "rag_qa": build_rag_qa_prompt,
            "system": get_system_prompt
        }
        
        if builder_name not in builders:
            raise ValueError(f"Unknown builder: {builder_name}")
        
        return builders[builder_name]
    
    def set_override(self, category: str, prompt_type: str, content: str):
        """프롬프트 오버라이드 설정 (런타임)"""
        cache_key = f"{category}:{prompt_type}"
        self.overrides[cache_key] = content
    
    def clear_overrides(self):
        """모든 오버라이드 제거"""
        self.overrides = {}
        self._load_env_overrides()
    
    def get_all_prompts(self) -> Dict[str, Dict]:
        """모든 프롬프트 반환 (디버깅용)"""
        return {
            "system": SYSTEM_PROMPTS,
            "security": SECURITY_PROMPTS,
            "rag": RAG_PROMPTS,
            "principles": VULNERABILITY_PRINCIPLES
        }

# 싱글톤 인스턴스
_prompt_manager = None

def get_prompt_manager() -> PromptManager:
    """프롬프트 매니저 싱글톤 인스턴스 반환"""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager()
    return _prompt_manager

# 편의 함수들
def get_prompt(category: str, prompt_type: str, **kwargs) -> str:
    """프롬프트 가져오기 (간편 함수)"""
    return get_prompt_manager().get_prompt(category, prompt_type, **kwargs)

def get_security_prompt(prompt_type: str, **kwargs) -> str:
    """보안 프롬프트 가져오기"""
    return get_prompt_manager().get_prompt("security", prompt_type, **kwargs)

def get_rag_prompt(prompt_type: str, **kwargs) -> str:
    """RAG 프롬프트 가져오기"""
    return get_prompt_manager().get_prompt("rag", prompt_type, **kwargs)

def get_system_prompt_text(prompt_type: str) -> str:
    """시스템 프롬프트 가져오기"""
    return get_prompt_manager().get_prompt("system", prompt_type)