# vector_db_analyzer.py
import chromadb

client = chromadb.PersistentClient(path="data/vector_db")

# 모든 취약점 타입 수집
vulnerability_types = set()

for collection_name in ['kisia_vulnerabilities', 'kisia_code_examples']:
    collection = client.get_collection(collection_name)
    result = collection.get()
    
    for metadata in result['metadatas']:
        if 'vulnerability_types' in metadata:
            types = metadata['vulnerability_types'].split(',')
            vulnerability_types.update(types)

print("발견된 모든 취약점 타입:")
for vtype in sorted(vulnerability_types):
    print(f"  - {vtype}")