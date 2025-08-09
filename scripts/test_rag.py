"""
RAG 테스트용 스크립트
"""
from rag.simple_rag import SimpleRAG

def test():
    rag = SimpleRAG()
    answer = rag.ask("SBOM이 뭐야?")
    print(answer)

if __name__ == "__main__":
    test()