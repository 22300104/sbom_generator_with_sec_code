# vector_db_data_type_detector.py

import os
import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Set
import chromadb
from chromadb.config import Settings

def detect_data_types(value: Any) -> str:
    """
    값의 데이터 타입을 감지하는 함수
    """
    if value is None:
        return "null"
    elif isinstance(value, bool):
        return "boolean"
    elif isinstance(value, int):
        return "integer"
    elif isinstance(value, float):
        return "float"
    elif isinstance(value, str):
        return "string"
    elif isinstance(value, list):
        if len(value) > 0:
            # 리스트 내부 요소 타입도 확인
            inner_types = set(detect_data_types(item) for item in value[:5])  # 샘플로 처음 5개만
            if len(inner_types) == 1:
                return f"array[{inner_types.pop()}]"
            else:
                return f"array[mixed: {', '.join(inner_types)}]"
        return "array[empty]"
    elif isinstance(value, dict):
        return "object"
    else:
        return type(value).__name__

def analyze_metadata_structure(metadatas: List[Dict]) -> Dict:
    """
    메타데이터 구조를 분석하는 함수
    """
    field_info = defaultdict(lambda: {
        'types': set(),
        'count': 0,
        'null_count': 0,
        'samples': [],
        'unique_values': set(),
        'min_value': None,
        'max_value': None,
        'avg_length': []
    })
    
    for metadata in metadatas:
        if metadata:
            for key, value in metadata.items():
                info = field_info[key]
                info['count'] += 1
                
                # 데이터 타입 감지
                data_type = detect_data_types(value)
                info['types'].add(data_type)
                
                # NULL 값 체크
                if value is None:
                    info['null_count'] += 1
                    continue
                
                # 샘플 수집 (최대 3개)
                if len(info['samples']) < 3 and value not in info['samples']:
                    info['samples'].append(value)
                
                # 고유값 수집 (최대 10개)
                if len(info['unique_values']) < 10:
                    if isinstance(value, (str, int, float, bool)):
                        info['unique_values'].add(value)
                
                # 수치형 데이터 분석
                if isinstance(value, (int, float)):
                    if info['min_value'] is None or value < info['min_value']:
                        info['min_value'] = value
                    if info['max_value'] is None or value > info['max_value']:
                        info['max_value'] = value
                
                # 문자열 길이 분석
                if isinstance(value, str):
                    info['avg_length'].append(len(value))
    
    # 평균 길이 계산
    for field, info in field_info.items():
        if info['avg_length']:
            info['avg_length'] = sum(info['avg_length']) / len(info['avg_length'])
        else:
            info['avg_length'] = 0
    
    return dict(field_info)

def analyze_vector_dimensions(embeddings: List) -> Dict:
    """
    벡터 임베딩의 차원과 특성을 분석
    """
    if not embeddings:
        return {}
    
    analysis = {
        'count': len(embeddings),
        'dimensions': None,
        'min_values': [],
        'max_values': [],
        'avg_values': [],
        'data_type': None
    }
    
    if embeddings and embeddings[0]:
        first_embedding = embeddings[0]
        analysis['dimensions'] = len(first_embedding)
        analysis['data_type'] = detect_data_types(first_embedding[0]) if first_embedding else None
        
        # 각 차원별 통계 (처음 10개 차원만)
        for dim in range(min(10, len(first_embedding))):
            dim_values = [emb[dim] for emb in embeddings[:100] if len(emb) > dim]  # 샘플 100개
            if dim_values:
                analysis['min_values'].append(min(dim_values))
                analysis['max_values'].append(max(dim_values))
                analysis['avg_values'].append(sum(dim_values) / len(dim_values))
    
    return analysis

def print_collection_data_types(collection):
    """
    컬렉션의 데이터 타입 정보를 출력
    """
    print(f"\n{'='*80}")
    print(f"컬렉션: {collection.name}")
    print(f"총 문서 수: {collection.count()}")
    print(f"{'='*80}")
    
    if collection.count() == 0:
        print("  데이터가 없습니다.")
        return
    
    # 샘플 데이터 가져오기 (최대 100개)
    sample_size = min(100, collection.count())
    sample = collection.get(limit=sample_size)
    
    # 1. ID 타입 분석
    print("\n[ID 필드 분석]")
    if sample['ids']:
        id_types = set(detect_data_types(id) for id in sample['ids'][:10])
        print(f"  - 타입: {', '.join(id_types)}")
        print(f"  - 샘플: {sample['ids'][:3]}")
    
    # 2. 문서(documents) 타입 분석
    print("\n[Documents 필드 분석]")
    if sample['documents']:
        doc_types = set(detect_data_types(doc) for doc in sample['documents'] if doc)
        print(f"  - 타입: {', '.join(doc_types)}")
        non_null_docs = [doc for doc in sample['documents'] if doc]
        if non_null_docs:
            avg_length = sum(len(doc) for doc in non_null_docs) / len(non_null_docs)
            print(f"  - 평균 길이: {avg_length:.2f} 문자")
            print(f"  - NULL 비율: {sample['documents'].count(None)}/{len(sample['documents'])}")
    
    # 3. 임베딩 분석
    print("\n[Embeddings 분석]")
    if sample['embeddings']:
        emb_analysis = analyze_vector_dimensions(sample['embeddings'])
        if emb_analysis:
            print(f"  - 벡터 차원: {emb_analysis['dimensions']}")
            print(f"  - 데이터 타입: {emb_analysis['data_type']}")
            if emb_analysis['min_values']:
                print(f"  - 값 범위 (처음 10차원):")
                for i in range(min(5, len(emb_analysis['min_values']))):
                    print(f"    차원 {i}: [{emb_analysis['min_values'][i]:.4f}, {emb_analysis['max_values'][i]:.4f}] (평균: {emb_analysis['avg_values'][i]:.4f})")
    
    # 4. 메타데이터 필드 분석
    print("\n[Metadata 필드 분석]")
    if sample['metadatas']:
        metadata_analysis = analyze_metadata_structure(sample['metadatas'])
        
        for field, info in metadata_analysis.items():
            print(f"\n  필드: '{field}'")
            print(f"    - 데이터 타입: {', '.join(info['types'])}")
            print(f"    - 출현 빈도: {info['count']}/{sample_size}")
            print(f"    - NULL 개수: {info['null_count']}")
            
            # 타입별 추가 정보
            if 'string' in info['types'] and info['avg_length'] > 0:
                print(f"    - 평균 길이: {info['avg_length']:.2f} 문자")
            
            if any(t in ['integer', 'float'] for t in info['types']):
                if info['min_value'] is not None:
                    print(f"    - 값 범위: [{info['min_value']}, {info['max_value']}]")
            
            # 샘플 값 출력
            if info['samples']:
                sample_str = str(info['samples'][:2])
                if len(sample_str) > 100:
                    sample_str = sample_str[:100] + "..."
                print(f"    - 샘플 값: {sample_str}")
            
            # 고유값이 적으면 모두 출력
            if 0 < len(info['unique_values']) <= 5:
                print(f"    - 고유 값: {info['unique_values']}")

def main():
    # 벡터 DB 경로
    vector_db_path = Path(r"C:\sbom_generator_with_sec_code\data\vector_db")
    
    if not vector_db_path.exists():
        print(f"디렉토리가 존재하지 않습니다: {vector_db_path}")
        return
    
    try:
        # ChromaDB 클라이언트 생성
        client = chromadb.PersistentClient(path=str(vector_db_path))
        
        # 모든 컬렉션 가져오기
        collections = client.list_collections()
        
        if not collections:
            print("컬렉션이 없습니다.")
            return
        
        print(f"벡터 DB 경로: {vector_db_path}")
        print(f"발견된 컬렉션 수: {len(collections)}")
        print(f"컬렉션 목록: {[c.name for c in collections]}")
        
        # 각 컬렉션의 데이터 타입 분석
        for collection in collections:
            print_collection_data_types(collection)
            
    except Exception as e:
        print(f"오류 발생: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()