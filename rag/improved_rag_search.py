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
    
        # search_vulnerability_evidence 메소드 전체를 아래 코드로 교체
    def search_vulnerability_evidence(self, ai_vuln_type: str, top_k: int = 3) -> Dict:
        """
        [하이브리드 방식]
        1. 취약점 타입 매핑을 시도하여 표준 KISIA 타입 획득
        2. 표준 타입이 있으면 get()으로 정확한 정보 조회 (정확성)
        3. 표준 타입이 없거나 get() 실패 시 query()로 유사도 검색 수행 (유연성)
        """
        
        # 1. AI 취약점 타입을 표준 KISIA 타입으로 변환 시도
        kisia_type = self.mapper.get_kisia_type(ai_vuln_type)
        
        results = None

        # 2. 매핑 성공 시: get()으로 정확한 정보 우선 조회
        if kisia_type:
            print(f"✅ 매핑 성공: '{ai_vuln_type}' → '{kisia_type}'. get()으로 직접 조회 시도...")
            results = self._get_exact_evidence(kisia_type)
        
        # 3. 매핑에 실패했거나, get()으로 문서를 찾지 못한 경우: query()로 폴백
        if not results or not results.get('vulnerability'):
            if kisia_type:
                print(f"⚠️ get() 조회 실패. '{ai_vuln_type}' 텍스트로 유사도 검색(query) 실행...")
            else:
                print(f"⚠️ 매핑 실패: '{ai_vuln_type}'. 유사도 검색(query) 실행...")
            
            # _fallback_text_search가 query를 사용하므로 이를 활용
            return self._fallback_text_search(ai_vuln_type, top_k)

        print(f"✅ '{kisia_type}'에 대한 정확한 가이드라인을 찾았습니다.")
        return results

    def _get_exact_evidence(self, kisia_type: str) -> Dict:
        """메타데이터(kisia_type)를 기반으로 get()을 사용해 문서를 직접 조회"""
        
        results = {
            'vulnerability': None, 'unsafe_codes': [], 'safe_codes': [],
            'recommendations': None, 'metadata': {}
        }

        # 취약점 섹션 직접 조회
        vuln_results = self.collections['vulnerabilities'].get(where={"english_type": kisia_type}, limit=1)
        if vuln_results['ids']:
            results['vulnerability'] = {
                'content': vuln_results['documents'][0],
                'metadata': vuln_results['metadatas'][0]
            }

        # 코드 예제 직접 조회
        code_results = self.collections['code_examples'].get(where={"vulnerability_type": kisia_type}, limit=4)
        if code_results['ids']:
            for doc, meta in zip(code_results['documents'], code_results['metadatas']):
                item = {'code': doc, 'metadata': meta}
                (results['unsafe_codes'] if meta.get('code_type') == 'unsafe' else results['safe_codes']).append(item)

        # 권장사항 직접 조회
        rec_results = self.collections['recommendations'].get(where={"vulnerability_type": kisia_type}, limit=1)
        if rec_results['ids']:
            results['recommendations'] = {
                'content': rec_results['documents'][0],
                'metadata': rec_results['metadatas'][0]
            }
        
        # 메타데이터 추가
        section_info = self.mapper.get_section_info(kisia_type)
        if section_info:
            results['metadata'] = section_info

        return results

    # _fallback_text_search 메소드는 query를 사용하므로 그대로 유지
    def _fallback_text_search(self, query: str, top_k: int = 3) -> Dict:
        """텍스트 기반 폴백 검색 (유사도 기반 query 사용)"""
        # (이 메소드의 코드는 변경할 필요 없습니다)
        print(f"📝 텍스트 검색 폴백: {query}")
        
        results = {
            'vulnerability': None, 'unsafe_codes': [], 'safe_codes': [],
            'recommendations': None, 'metadata': {'fallback': True}
        }
        
        # 텍스트 유사도로 검색
        vuln_results = self.collections['vulnerabilities'].query(
            query_texts=[query],
            n_results=top_k
        )
        
        if vuln_results['documents'] and vuln_results['documents'][0]:
            results['vulnerability'] = {
                'content': vuln_results['documents'][0][0],
                'metadata': vuln_results['metadatas'][0][0] if vuln_results['metadatas'][0] else {}
            }
        
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