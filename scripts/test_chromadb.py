# scripts/test_chromadb.py
import chromadb

# 1. 메모리에서 테스트 (파일 저장 X)
client = chromadb.Client()

# 2. 컬렉션 생성
collection = client.create_collection(name="test")

# 3. 간단한 문서 추가
collection.add(
    documents=[
        "SBOM은 Software Bill of Materials의 약자입니다.",
        "SBOM은 소프트웨어 구성 요소 목록을 의미합니다.",
        "보안 취약점을 관리하기 위해 SBOM이 필요합니다."
    ],
    ids=["doc1", "doc2", "doc3"]
)

# 4. 검색 테스트
results = collection.query(
    query_texts=["SBOM이 뭐야?"],
    n_results=2
)

print("=== ChromaDB 테스트 ===")
print(f"검색 질문: SBOM이 뭐야?")
print(f"검색 결과 {len(results['documents'][0])}개:")
for doc in results['documents'][0]:
    print(f"  - {doc}")