# scripts/03_build_vector_db.py
"""
추출된 데이터로 ChromaDB 벡터 데이터베이스 구축
다중 컬렉션 구조로 효율적인 검색 지원
"""
import chromadb
from chromadb.config import Settings
import json
from pathlib import Path
from typing import List, Dict
import hashlib
from datetime import datetime
import os

class VectorDBBuilder:
    def __init__(self, persist_directory: str = "data/vector_db"):
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
        
        # 컬렉션 정의
        self.collections = {}
        
        # 통계
        self.stats = {
            "collections_created": [],
            "documents_added": {},
            "errors": []
        }
    
    def build(self):
        """벡터 DB 구축 메인 함수"""
        print("🚀 벡터 DB 구축 시작")
        
        # 1. 기존 컬렉션 정리
        self._cleanup_existing_collections()
        
        # 2. 데이터 로드
        vuln_sections = self._load_vulnerability_sections()
        chunks = self._load_chunks()
        
        # 3. 컬렉션 생성
        self._create_collections()
        
        # 4. 데이터 임베딩 및 저장
        self._embed_vulnerability_sections(vuln_sections)
        self._embed_chunks(chunks)
        self._create_code_examples_collection(vuln_sections)
        
        # 5. 인덱스 생성
        self._create_indexes()
        
        print("✅ 벡터 DB 구축 완료")
        
        return self.stats
    
    def _cleanup_existing_collections(self):
        """기존 컬렉션 삭제"""
        print("🧹 기존 컬렉션 정리 중...")
        
        existing_collections = self.client.list_collections()
        for collection in existing_collections:
            try:
                self.client.delete_collection(collection.name)
                print(f"  ✓ 삭제: {collection.name}")
            except Exception as e:
                print(f"  ❌ 삭제 실패: {collection.name} - {e}")
    
    def _create_collections(self):
        """컬렉션 생성"""
        print("📦 컬렉션 생성 중...")
        
        # 1. 취약점 섹션 컬렉션 (메인)
        self.collections['vulnerabilities'] = self.client.create_collection(
            name="kisia_vulnerabilities",
            metadata={"description": "KISIA 취약점 섹션 (설명 + 코드 쌍)"}
        )
        print("  ✓ kisia_vulnerabilities 생성")
        
        # 2. 코드 예제 컬렉션
        self.collections['code_examples'] = self.client.create_collection(
            name="kisia_code_examples",
            metadata={"description": "안전/불안전 코드 예제"}
        )
        print("  ✓ kisia_code_examples 생성")
        
        # 3. 일반 청크 컬렉션
        self.collections['chunks'] = self.client.create_collection(
            name="kisia_chunks",
            metadata={"description": "의미 단위 텍스트 청크"}
        )
        print("  ✓ kisia_chunks 생성")
        
        # 4. 권장사항 컬렉션
        self.collections['recommendations'] = self.client.create_collection(
            name="kisia_recommendations",
            metadata={"description": "보안 권장사항 및 가이드라인"}
        )
        print("  ✓ kisia_recommendations 생성")
        
        self.stats["collections_created"] = list(self.collections.keys())
    
    def _load_vulnerability_sections(self) -> List[Dict]:
        """취약점 섹션 로드"""
        path = Path("data/processed/chunks/vulnerability_sections.json")
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _load_chunks(self) -> List[Dict]:
        """청크 로드"""
        path = Path("data/processed/chunks/semantic_chunks.json")
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _embed_vulnerability_sections(self, sections: List[Dict]):
        """취약점 섹션 임베딩"""
        print(f"🔍 취약점 섹션 임베딩 중... ({len(sections)}개)")
        
        collection = self.collections['vulnerabilities']
        
        documents = []
        metadatas = []
        ids = []
        
        for i, section in enumerate(sections):
            # 문서 생성 (설명 + 코드)
            doc_text = f"""
[취약점 섹션]
제목: {section.get('title', 'Unknown')}

[설명]
{section.get('description', '')}

[안전하지 않은 코드]
{section['unsafe_code'].get('code', '')[:500]}

[안전한 코드]
{section['safe_code'].get('code', '')[:500]}

[권장사항]
{section.get('recommendations', '')}
"""
            
            documents.append(doc_text)
            
            # 메타데이터
            metadatas.append({
                "title": section.get('title', ''),
                "vulnerability_types": ','.join(section.get('vulnerability_types', ['General'])),
                "page_start": section['page_range'][0],
                "page_end": section['page_range'][1],
                "has_unsafe_code": True,
                "has_safe_code": True,
                "section_index": i
            })
            
            # ID 생성
            ids.append(f"vuln_section_{i}")
        
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
    
    def _embed_chunks(self, chunks: List[Dict]):
        """청크 임베딩"""
        print(f"📝 청크 임베딩 중... ({len(chunks)}개)")
        
        # 타입별로 분류
        chunks_by_type = {
            'vulnerability': [],
            'recommendation': [],
            'code': [],
            'general': []
        }
        
        for chunk in chunks:
            chunk_type = chunk.get('type', 'general')
            if chunk_type in chunks_by_type:
                chunks_by_type[chunk_type].append(chunk)
        
        # vulnerability와 code는 chunks 컬렉션에
        chunks_collection = self.collections['chunks']
        all_chunks = chunks_by_type['vulnerability'] + chunks_by_type['code'] + chunks_by_type['general']
        
        if all_chunks:
            documents = []
            metadatas = []
            ids = []
            
            for i, chunk in enumerate(all_chunks):
                documents.append(chunk['text'])
                metadatas.append({
                    "page": chunk['page'],
                    "type": chunk['type'],
                    "has_code": chunk['metadata'].get('has_code', False),
                    "keywords": ','.join(chunk['metadata'].get('keywords', [])),
                    "char_count": chunk['metadata'].get('char_count', 0)
                })
                ids.append(f"chunk_{i}")
            
            try:
                chunks_collection.add(
                    documents=documents,
                    metadatas=metadatas,
                    ids=ids
                )
                print(f"  ✓ {len(documents)}개 일반 청크 임베딩 완료")
                self.stats["documents_added"]["chunks"] = len(documents)
            except Exception as e:
                print(f"  ❌ 청크 임베딩 실패: {e}")
                self.stats["errors"].append(str(e))
        
        # recommendations는 별도 컬렉션에
        reco_collection = self.collections['recommendations']
        recommendations = chunks_by_type['recommendation']
        
        if recommendations:
            documents = []
            metadatas = []
            ids = []
            
            for i, chunk in enumerate(recommendations):
                documents.append(chunk['text'])
                metadatas.append({
                    "page": chunk['page'],
                    "keywords": ','.join(chunk['metadata'].get('keywords', []))
                })
                ids.append(f"reco_{i}")
            
            try:
                reco_collection.add(
                    documents=documents,
                    metadatas=metadatas,
                    ids=ids
                )
                print(f"  ✓ {len(documents)}개 권장사항 임베딩 완료")
                self.stats["documents_added"]["recommendations"] = len(documents)
            except Exception as e:
                print(f"  ❌ 권장사항 임베딩 실패: {e}")
                self.stats["errors"].append(str(e))
    
    def _create_code_examples_collection(self, sections: List[Dict]):
        """코드 예제 전용 컬렉션 생성"""
        print(f"💻 코드 예제 임베딩 중...")
        
        collection = self.collections['code_examples']
        
        documents = []
        metadatas = []
        ids = []
        
        for i, section in enumerate(sections):
            # 안전하지 않은 코드
            unsafe_code = section['unsafe_code']
            if unsafe_code.get('code'):
                documents.append(unsafe_code['code'])
                metadatas.append({
                    "type": "unsafe",
                    "page": unsafe_code['page'],
                    "vulnerability_types": ','.join(section.get('vulnerability_types', ['General'])),
                    "pair_index": i
                })
                ids.append(f"unsafe_code_{i}")
            
            # 안전한 코드
            safe_code = section['safe_code']
            if safe_code.get('code'):
                documents.append(safe_code['code'])
                metadatas.append({
                    "type": "safe",
                    "page": safe_code['page'],
                    "vulnerability_types": ','.join(section.get('vulnerability_types', ['General'])),
                    "pair_index": i
                })
                ids.append(f"safe_code_{i}")
        
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
    
    def _create_indexes(self):
        """추가 인덱스 생성"""
        print("📑 인덱스 생성 중...")
        
        # 취약점 타입 인덱스
        vuln_type_index = {}
        
        # vulnerabilities 컬렉션에서 취약점 타입별 문서 ID 수집
        collection = self.collections['vulnerabilities']
        result = collection.get()
        
        if result and 'metadatas' in result:
            for i, metadata in enumerate(result['metadatas']):
                vuln_types = metadata.get('vulnerability_types', '').split(',')
                doc_id = result['ids'][i]
                
                for vtype in vuln_types:
                    if vtype not in vuln_type_index:
                        vuln_type_index[vtype] = []
                    vuln_type_index[vtype].append(doc_id)
        
        # 인덱스 저장
        index_path = Path("data/vector_db/indexes")
        index_path.mkdir(parents=True, exist_ok=True)
        
        with open(index_path / "vulnerability_type_index.json", 'w', encoding='utf-8') as f:
            json.dump(vuln_type_index, f, ensure_ascii=False, indent=2)
        
        print(f"  ✓ 취약점 타입 인덱스 생성 ({len(vuln_type_index)}개 타입)")
    
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
        
        test_queries = [
            "SQL 인젝션을 방지하는 방법",
            "안전한 패스워드 저장",
            "XSS 공격 방어",
            "파라미터 바인딩"
        ]
        
        vuln_collection = self.collections['vulnerabilities']
        
        for query in test_queries:
            results = vuln_collection.query(
                query_texts=[query],
                n_results=3
            )
            
            if results and results['documents'][0]:
                print(f"  ✓ '{query}': {len(results['documents'][0])}개 결과")
            else:
                print(f"  ❌ '{query}': 결과 없음")
    
    def save_stats(self):
        """통계 저장"""
        stats_path = Path("data/vector_db/build_stats.json")
        stats_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.stats["timestamp"] = datetime.now().isoformat()
        self.stats["collections"] = {
            name: collection.count() 
            for name, collection in self.collections.items()
        }
        
        with open(stats_path, 'w', encoding='utf-8') as f:
            json.dump(self.stats, f, ensure_ascii=False, indent=2)
        
        print(f"\n✅ 빌드 통계 저장: {stats_path}")
    
    def print_summary(self):
        """빌드 요약 출력"""
        print("\n" + "="*60)
        print("📊 벡터 DB 구축 결과")
        print("="*60)
        
        print(f"\n📦 생성된 컬렉션: {len(self.collections)}개")
        for name in self.collections:
            print(f"  • {name}")
        
        print(f"\n📄 임베딩된 문서:")
        total_docs = 0
        for name, count in self.stats["documents_added"].items():
            print(f"  • {name}: {count}개")
            total_docs += count
        print(f"  총합: {total_docs}개")
        
        if self.stats["errors"]:
            print(f"\n⚠️ 오류 발생: {len(self.stats['errors'])}건")
            for error in self.stats["errors"][:3]:
                print(f"  • {error[:100]}")

if __name__ == "__main__":
    # 벡터 DB 빌더 생성
    builder = VectorDBBuilder()
    
    # 빌드 실행
    stats = builder.build()
    
    # 검증
    builder.verify_build()
    
    # 통계 저장
    builder.save_stats()
    
    # 요약 출력
    builder.print_summary()