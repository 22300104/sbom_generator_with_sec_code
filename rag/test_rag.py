# scripts/test_rag.py
import sys
sys.path.append('.')
from rag.simple_rag import SimpleRAG

def test_rag():
    print("🚀 RAG 시스템 테스트 시작\n")
    
    rag = SimpleRAG()
    
    test_questions = [
        "SQL 인젝션을 방어하는 방법은?",
        "Django에서 XSS 공격을 막으려면?",
        "안전한 패스워드는 어떻게 저장해야 하나요?",
        "CSRF 토큰은 왜 필요한가요?"
    ]
    
    for i, question in enumerate(test_questions, 1):
        print(f"질문 {i}: {question}")
        print("-" * 50)
        
        answer = rag.ask(question)
        print(f"답변: {answer}\n")
        print("=" * 70 + "\n")

if __name__ == "__main__":
    test_rag()