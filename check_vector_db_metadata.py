# check_vector_db_metadata.py
"""
벡터 DB의 메타데이터 구조 확인 스크립트
기존 vector_db_analyzer.py와 vector_db_data_type_detector.py 재활용
"""
import chromadb
from pathlib import Path

def analyze_metadata_fields():
    """각 컬렉션의 메타데이터 필드와 값 분석"""
    
    # 기존 설정 재활용
    vector_db_path = Path("data/vector_db")
    if not vector_db_path.exists():
        print(f"❌ 벡터 DB 경로가 없습니다: {vector_db_path}")
        return
    
    client = chromadb.PersistentClient(path=str(vector_db_path))
    
    # 분석할 컬렉션 목록 (기존 코드에서 확인된 것들)
    collection_names = [
        'kisia_vulnerabilities',
        'kisia_code_examples', 
        'kisia_chunks',
        'kisia_recommendations'
    ]
    
    analysis_results = {}
    
    for coll_name in collection_names:
        try:
            collection = client.get_collection(coll_name)
            
            # 샘플 데이터 가져오기 (최대 10개)
            sample = collection.get(limit=10)
            
            print(f"\n{'='*60}")
            print(f"📦 컬렉션: {coll_name}")
            print(f"📊 문서 수: {collection.count()}")
            print(f"{'='*60}")
            
            # 메타데이터 필드 분석
            if sample['metadatas']:
                all_fields = set()
                field_samples = {}
                
                for metadata in sample['metadatas']:
                    if metadata:
                        for key, value in metadata.items():
                            all_fields.add(key)
                            if key not in field_samples:
                                field_samples[key] = []
                            if len(field_samples[key]) < 3:  # 각 필드당 3개 샘플
                                field_samples[key].append(value)
                
                print("\n📋 메타데이터 필드:")
                for field in sorted(all_fields):
                    print(f"\n  • {field}:")
                    samples = field_samples[field]
                    for i, sample_val in enumerate(samples[:2], 1):
                        # 긴 값은 잘라서 표시
                        sample_str = str(sample_val)
                        if len(sample_str) > 100:
                            sample_str = sample_str[:100] + "..."
                        print(f"    샘플{i}: {sample_str}")
                
                # vulnerability_types 필드 특별 분석
                if 'vulnerability_types' in all_fields:
                    print("\n🎯 vulnerability_types 값 분석:")
                    vuln_types = set()
                    for metadata in sample['metadatas']:
                        if metadata and 'vulnerability_types' in metadata:
                            types = metadata['vulnerability_types'].split(',')
                            vuln_types.update(t.strip() for t in types if t.strip())
                    
                    print(f"  발견된 취약점 타입 ({len(vuln_types)}개):")
                    for vtype in sorted(vuln_types):
                        print(f"    - {vtype}")
                
                # 페이지 정보 필드 확인
                page_fields = [f for f in all_fields if 'page' in f.lower()]
                if page_fields:
                    print(f"\n📄 페이지 관련 필드: {page_fields}")
                
                analysis_results[coll_name] = {
                    'fields': list(all_fields),
                    'vuln_types': list(vuln_types) if 'vulnerability_types' in all_fields else [],
                    'page_fields': page_fields
                }
                
        except Exception as e:
            print(f"❌ {coll_name} 분석 실패: {e}")
    
    return analysis_results

def check_current_search_method():
    """현재 SimpleRAG의 검색 방식 확인"""
    
    print("\n\n" + "="*60)
    print("🔍 현재 SimpleRAG 검색 방식 분석")
    print("="*60)
    
    # simple_rag.py의 search_similar 메서드 분석
    print("\n현재 search_similar() 메서드:")
    print("1. collection.query() 사용")
    print("2. query_texts 파라미터만 사용 (텍스트 유사도)")
    print("3. where 절 미사용 (메타데이터 필터링 없음)")
    print("4. 단일 컬렉션만 검색 (kisia_vulnerabilities)")
    
    print("\n개선 필요 사항:")
    print("✅ where 절 추가로 메타데이터 필터링")
    print("✅ vulnerability_types 필드 활용")
    print("✅ 다중 컬렉션 검색")
    print("✅ 페이지 정보 정확한 추출")

if __name__ == "__main__":
    # 1. 벡터 DB 구조 분석
    results = analyze_metadata_fields()
    
    # 2. 현재 검색 방식 확인
    check_current_search_method()
    
    # 3. 요약
    print("\n\n" + "="*60)
    print("📊 분석 요약")
    print("="*60)
    
    if results:
        for coll_name, info in results.items():
            print(f"\n{coll_name}:")
            print(f"  - 메타데이터 필드 수: {len(info['fields'])}")
            print(f"  - 취약점 타입 수: {len(info['vuln_types'])}")
            print(f"  - 페이지 필드: {info['page_fields']}")