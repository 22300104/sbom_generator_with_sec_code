# rag/improved_rag_search.py
"""
개선된 RAG 검색 시스템
KISIA 구조화 데이터 활용
"""
import chromadb
from typing import Dict, List, Optional
import sys
sys.path.append('.')
from rag.kisia_vulnerability_mapping import KISIAVulnerabilityMapper

class ImprovedRAGSearch:
    """개선된 RAG 검색"""
    
    def __init__(self, vector_db_path: str = "data/vector_db_v2"):
        self.client = chromadb.PersistentClient(path=vector_db_path)
        self.mapper = KISIAVulnerabilityMapper()
        
        # 컬렉션 로드
        self.collections = {
            'vulnerabilities': self.client.get_collection("kisia_vulnerabilities"),
            'code_examples': self.client.get_collection("kisia_code_examples"),
            'recommendations': self.client.get_collection("kisia_recommendations")
        }
    
    def search_vulnerability_evidence(self, ai_vuln_type: str, top_k: int = 3) -> Dict:
        """AI가 발견한 취약점에 대한 KISIA 가이드라인 근거 검색"""
        
        # 1. AI 취약점 타입을 KISIA 타입으로 변환
        kisia_type = self.mapper.get_kisia_type(ai_vuln_type)
        
        if not kisia_type:
            print(f"⚠️ 매핑 실패: {ai_vuln_type} → KISIA 타입 찾을 수 없음")
            # 텍스트 검색으로 폴백
            return self._fallback_text_search(ai_vuln_type, top_k)
        
        print(f"✅ 매핑 성공: {ai_vuln_type} → {kisia_type}")
        
        # 2. 메타데이터 필터로 정확한 문서 검색
        results = {
            'vulnerability': None,
            'unsafe_codes': [],
            'safe_codes': [],
            'recommendations': None,
            'metadata': {}
        }
        
        # 취약점 섹션 검색
        vuln_results = self.collections['vulnerabilities'].query(
            query_texts=[ai_vuln_type],
            where={"english_type": kisia_type},
            n_results=1
        )
        
        if vuln_results['documents'][0]:
            results['vulnerability'] = {
                'content': vuln_results['documents'][0][0],
                'metadata': vuln_results['metadatas'][0][0] if vuln_results['metadatas'][0] else {}
            }
        
        # 코드 예제 검색
        code_results = self.collections['code_examples'].query(
            query_texts=[ai_vuln_type],
            where={"vulnerability_type": kisia_type},
            n_results=4
        )
        
        if code_results['documents'][0]:
            for i, (doc, meta) in enumerate(zip(code_results['documents'][0], code_results['metadatas'][0])):
                if meta.get('code_type') == 'unsafe':
                    results['unsafe_codes'].append({
                        'code': doc,
                        'metadata': meta
                    })
                else:
                    results['safe_codes'].append({
                        'code': doc,
                        'metadata': meta
                    })
        
        # 권장사항 검색
        rec_results = self.collections['recommendations'].query(
            query_texts=[ai_vuln_type],
            where={"vulnerability_type": kisia_type},
            n_results=1
        )
        
        if rec_results['documents'][0]:
            results['recommendations'] = {
                'content': rec_results['documents'][0][0],
                'metadata': rec_results['metadatas'][0][0] if rec_results['metadatas'][0] else {}
            }
        
        # 섹션 정보 추가
        section_info = self.mapper.get_section_info(kisia_type)
        if section_info:
            results['metadata'] = section_info
        
        return results
    
    def _fallback_text_search(self, query: str, top_k: int = 3) -> Dict:
        """텍스트 기반 폴백 검색"""
        print(f"📝 텍스트 검색 폴백: {query}")
        
        results = {
            'vulnerability': None,
            'unsafe_codes': [],
            'safe_codes': [],
            'recommendations': None,
            'metadata': {'fallback': True}
        }
        
        # 텍스트 유사도로 검색
        vuln_results = self.collections['vulnerabilities'].query(
            query_texts=[query],
            n_results=top_k
        )
        
        if vuln_results['documents'][0]:
            results['vulnerability'] = {
                'content': vuln_results['documents'][0][0],
                'metadata': vuln_results['metadatas'][0][0] if vuln_results['metadatas'][0] else {}
            }
        
        return results
    
    def format_evidence_for_llm(self, search_results: Dict) -> str:
        """검색 결과를 LLM용 텍스트로 포맷팅"""
        
        parts = []
        
        # 메타데이터
        if search_results['metadata'] and not search_results['metadata'].get('fallback'):
            meta = search_results['metadata']
            parts.append(f"[KISIA 가이드라인 - {meta.get('section', '')} {meta.get('korean_name', '')}]")
            parts.append(f"페이지: {meta.get('page', 'N/A')}")
        
        # 취약점 설명
        if search_results['vulnerability']:
            parts.append("\n[취약점 설명]")
            content = search_results['vulnerability']['content'][:1000]
            parts.append(content)
        
        # 안전하지 않은 코드
        if search_results['unsafe_codes']:
            parts.append("\n[안전하지 않은 코드 예시]")
            parts.append(search_results['unsafe_codes'][0]['code'][:500])
        
        # 안전한 코드
        if search_results['safe_codes']:
            parts.append("\n[안전한 코드 예시]")
            parts.append(search_results['safe_codes'][0]['code'][:500])
        
        # 권장사항
        if search_results['recommendations']:
            parts.append("\n[권장사항]")
            parts.append(search_results['recommendations']['content'])
        
        return '\n'.join(parts)

# 테스트
if __name__ == "__main__":
    searcher = ImprovedRAGSearch()
    
    # 테스트 케이스
    test_vulnerabilities = [
        "SQL Injection",
        "Hardcoded Password",
        "Command Injection",
        "Weak Cryptography",
        "Insecure Deserialization"
    ]
    
    for vuln in test_vulnerabilities:
        print(f"\n{'='*60}")
        print(f"🔍 검색: {vuln}")
        results = searcher.search_vulnerability_evidence(vuln)
        
        if results['vulnerability']:
            print(f"✅ KISIA 가이드라인 찾음!")
            print(f"  - 섹션: {results['metadata'].get('section', 'N/A')}")
            print(f"  - 이름: {results['metadata'].get('korean_name', 'N/A')}")
            print(f"  - 페이지: {results['metadata'].get('page', 'N/A')}")
            print(f"  - 안전하지 않은 코드: {len(results['unsafe_codes'])}개")
            print(f"  - 안전한 코드: {len(results['safe_codes'])}개")
        else:
            print(f"❌ 가이드라인을 찾을 수 없음")