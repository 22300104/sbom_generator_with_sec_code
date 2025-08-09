# rag/simple_rag.py
import chromadb
import openai
import os
from typing import List, Dict

class SimpleRAG:
    def __init__(self):
        # ChromaDB 로드
        self.chroma_client = chromadb.PersistentClient(path="data/vector_db")
        self.collection = self.chroma_client.get_collection("secure_coding_guide")
        
        # OpenAI 설정
        openai.api_key = os.getenv("OPENAI_API_KEY")
        
    def search_similar(self, query: str, top_k: int = 3) -> Dict:
        """유사한 문서 검색"""
        results = self.collection.query(
            query_texts=[query],
            n_results=top_k
        )
        return results
    
    def ask(self, question: str) -> str:
        """질문에 대한 답변 생성"""
        # 1. 관련 문서 검색
        search_results = self.search_similar(question, top_k=3)
        
        if not search_results['documents'][0]:
            return "관련된 정보를 찾을 수 없습니다."
        
        # 2. 컨텍스트 생성
        context = "\n\n".join(search_results['documents'][0])
        
        # 3. 프롬프트 생성
        prompt = f"""
        당신은 Python 시큐어 코딩 전문가입니다.
        아래 가이드라인을 참고하여 질문에 답변해주세요.
        
        [가이드라인]
        {context}
        
        [질문]
        {question}
        
        [답변]
        """
        
        # 4. OpenAI API 호출
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Python 보안 코딩 가이드 전문가"},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=1000
        )
        
        return response.choices[0].message.content