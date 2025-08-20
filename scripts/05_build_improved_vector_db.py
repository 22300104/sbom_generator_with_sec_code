# scripts/05_build_improved_vector_db.py
"""
개선된 벡터 데이터베이스 구축
KISIA 구조화 데이터 기반
"""
import chromadb
from chromadb.config import Settings
import json
from pathlib import Path
from typing import List, Dict
import hashlib
from datetime import datetime
import sys
sys.path.append('.')
from rag.kisia_vulnerability_mapping import KISIAVulnerabilityMapper

class ImprovedVectorDBBuilder:
    """개선된 벡터 DB 빌더"""
    
    def __init__(self, persist_directory: str = "data/vector_db_v2"):
        self.persist_dir = Path(persist_directory)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        
        # ChromaDB 클라이언트 초기화
        self.client = chromadb.PersistentClient(
            path=str(self.persist_dir),
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        
        self.mapper = KISIAVulnerabilityMapper()
        self.collections = {}
        self.stats = {
            "collections_created": [],
            "documents_added": {},
            "errors": []
        }
    
    def build(self):
        """벡터 DB 구축"""
        print("🚀 개선된 벡터 DB 구축 시작")
        
        # 1. 기존 컬렉션 정리
        self._cleanup_existing_collections()
        
        # 2. 구조화된 데이터 로드
        structured_data = self._load_structured_data()
        
        # 3. 컬렉션 생성
        self._create_collections()
        
        # 4. 데이터 임베딩
        self._embed_vulnerability_sections(structured_data['vulnerabilities'])
        self._embed_code_examples(structured_data['vulnerabilities'])
        self._embed_recommendations(structured_data['vulnerabilities'])
        
        print("✅ 벡터 DB 구축 완료")
        
        return self.stats
    
    def _cleanup_existing_collections(self):
        """기존 컬렉션 삭제"""
        print("🧹 기존 컬렉션 정리 중...")
        
        for collection in self.client.list_collections():
            try:
                self.client.delete_collection(collection.name)
                print(f"  ✓ 삭제: {collection.name}")
            except Exception as e:
                print(f"  ❌ 삭제 실패: {collection.name} - {e}")
    
    def _load_structured_data(self) -> Dict:
        """구조화된 데이터 로드"""
        path = Path("data/processed/kisia_structured.json")
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _create_collections(self):
        """컬렉션 생성"""
        print("📦 컬렉션 생성 중...")
        
        # 1. 취약점 섹션 컬렉션
        self.collections['vulnerabilities'] = self.client.create_collection(
            name="kisia_vulnerabilities",
            metadata={"description": "KISIA 취약점 섹션 (전체 내용)"}
        )
        
        # 2. 코드 예제 컬렉션
        self.collections['code_examples'] = self.client.create_collection(
            name="kisia_code_examples",
            metadata={"description": "안전/불안전 코드 예제"}
        )
        
        # 3. 권장사항 컬렉션
        self.collections['recommendations'] = self.client.create_collection(
            name="kisia_recommendations",
            metadata={"description": "보안 권장사항"}
        )
        
        print(f"  ✓ {len(self.collections)}개 컬렉션 생성 완료")
    
    def _embed_vulnerability_sections(self, vulnerabilities: List[Dict]):
        """취약점 섹션 임베딩"""
        print(f"🔍 취약점 섹션 임베딩 중... ({len(vulnerabilities)}개)")
        
        collection = self.collections['vulnerabilities']
        
        documents = []
        metadatas = []
        ids = []
        
        for vuln in vulnerabilities:
            # 문서 생성 (전체 내용)
            doc_text = f"""
[취약점: {vuln['korean_name']}]
섹션: {vuln['section']}

[설명]
{vuln['description']}

[안전하지 않은 코드 예시]
{self._format_code_examples(vuln['unsafe_codes'])}

[안전한 코드 예시]
{self._format_code_examples(vuln['safe_codes'])}

[권장사항]
{' '.join(vuln['recommendations'])}
"""
            
            documents.append(doc_text)
            
            # ChromaDB 호환 메타데이터
            metadatas.append({
                "section": vuln['section'],
                "section_number": str(vuln['number']),  # 문자열로 변환
                "korean_name": vuln['korean_name'],
                "english_type": vuln['english_type'],
                "start_page": vuln['start_page'],
                "end_page": vuln['end_page'],
                "has_unsafe_code": len(vuln['unsafe_codes']) > 0,
                "has_safe_code": len(vuln['safe_codes']) > 0,
                "unsafe_code_count": len(vuln['unsafe_codes']),
                "safe_code_count": len(vuln['safe_codes'])
            })
            
            # ID 생성
            ids.append(f"vuln_{vuln['english_type']}")
        
        # ChromaDB에 추가
        try:
            collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            print(f"  ✓ {len(documents)}개 취약점 섹션 임베딩 완료")
            self.stats["documents_added"]["vulnerabilities"] = len(documents)
        except Exception as e:
            print(f"  ❌ 취약점 섹션 임베딩 실패: {e}")
            self.stats["errors"].append(str(e))
    
    def _embed_code_examples(self, vulnerabilities: List[Dict]):
        """코드 예제 임베딩"""
        print(f"💻 코드 예제 임베딩 중...")
        
        collection = self.collections['code_examples']
        
        documents = []
        metadatas = []
        ids = []
        
        for vuln in vulnerabilities:
            # 안전하지 않은 코드
            for i, code_info in enumerate(vuln['unsafe_codes']):
                documents.append(code_info['code'])
                metadatas.append({
                    "code_type": "unsafe",
                    "vulnerability_type": vuln['english_type'],
                    "korean_name": vuln['korean_name'],
                    "page": code_info['page'],
                    "section": vuln['section'],
                    "label": code_info.get('label', '안전하지 않은 코드 예시')
                })
                ids.append(f"unsafe_{vuln['english_type']}_{i}")
            
            # 안전한 코드
            for i, code_info in enumerate(vuln['safe_codes']):
                documents.append(code_info['code'])
                metadatas.append({
                    "code_type": "safe",
                    "vulnerability_type": vuln['english_type'],
                    "korean_name": vuln['korean_name'],
                    "page": code_info['page'],
                    "section": vuln['section'],
                    "label": code_info.get('label', '안전한 코드 예시')
                })
                ids.append(f"safe_{vuln['english_type']}_{i}")
        
        if documents:
            try:
                collection.add(
                    documents=documents,
                    metadatas=metadatas,
                    ids=ids
                )
                print(f"  ✓ {len(documents)}개 코드 예제 임베딩 완료")
                self.stats["documents_added"]["code_examples"] = len(documents)
            except Exception as e:
                print(f"  ❌ 코드 예제 임베딩 실패: {e}")
                self.stats["errors"].append(str(e))
    
    def _embed_recommendations(self, vulnerabilities: List[Dict]):
        """권장사항 임베딩"""
        print(f"📝 권장사항 임베딩 중...")
        
        collection = self.collections['recommendations']
        
        documents = []
        metadatas = []
        ids = []
        
        for vuln in vulnerabilities:
            if vuln['recommendations']:
                # 모든 권장사항을 하나의 문서로
                doc_text = f"""
[{vuln['korean_name']} 권장사항]

{chr(10).join(f'• {rec}' for rec in vuln['recommendations'])}
"""
                
                documents.append(doc_text)
                metadatas.append({
                    "vulnerability_type": vuln['english_type'],
                    "korean_name": vuln['korean_name'],
                    "section": vuln['section'],
                    "recommendation_count": len(vuln['recommendations'])
                })
                ids.append(f"rec_{vuln['english_type']}")
        
        if documents:
            try:
                collection.add(
                    documents=documents,
                    metadatas=metadatas,
                    ids=ids
                )
                print(f"  ✓ {len(documents)}개 권장사항 임베딩 완료")
                self.stats["documents_added"]["recommendations"] = len(documents)
            except Exception as e:
                print(f"  ❌ 권장사항 임베딩 실패: {e}")
                self.stats["errors"].append(str(e))
    
    def _format_code_examples(self, code_list: List[Dict]) -> str:
        """코드 예제 포맷팅"""
        if not code_list:
            return "코드 예제 없음"
        
        formatted = []
        for code_info in code_list[:2]:  # 최대 2개만
            formatted.append(f"```python\n{code_info['code']}\n```")
        
        return '\n\n'.join(formatted)
    
    def verify_build(self):
        """빌드 검증"""
        print("\n🔍 벡터 DB 검증 중...")
        
        for name, collection in self.collections.items():
            count = collection.count()
            print(f"  • {name}: {count}개 문서")
        
        # 샘플 쿼리 테스트
        self._test_sample_queries()
    
    def _test_sample_queries(self):
        """샘플 쿼리 테스트"""
        print("\n🧪 샘플 쿼리 테스트...")
        
        test_cases = [
            ("SQL Injection", "SQL_Injection"),
            ("하드코딩된 패스워드", "Hardcoded_Secrets"),
            ("XSS 공격", "XSS"),
            ("역직렬화", "Unsafe_Deserialization")
        ]
        
        vuln_collection = self.collections['vulnerabilities']
        
        for query, expected_type in test_cases:
            # 메타데이터 필터링 테스트
            results = vuln_collection.query(
                query_texts=[query],
                where={"english_type": expected_type},
                n_results=1
            )
            
            if results and results['documents'][0]:
                print(f"  ✓ '{query}' → {expected_type}: 찾음")
            else:
                print(f"  ❌ '{query}' → {expected_type}: 못찾음")

if __name__ == "__main__":
    # 벡터 DB 빌더 생성
    builder = ImprovedVectorDBBuilder()
    
    # 빌드 실행
    stats = builder.build()
    
    # 검증
    builder.verify_build()
    
    print("\n✅ 개선된 벡터 DB 구축 완료!")