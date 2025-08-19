# rag/simple_rag.py
import chromadb
from openai import OpenAI
import os
from typing import List, Dict

class SimpleRAG:
    def __init__(self):
        # ChromaDB 로드
        self.chroma_client = chromadb.PersistentClient(path="data/vector_db")
        
        # 컬렉션 로드 (이미 PDF 데이터가 있음)
        try:
            self.collection = self.chroma_client.get_collection("secure_coding_guide")
            print(f"✅ 벡터 DB 로드 완료 (문서 수: {self.collection.count()})")
        except Exception as e:
            print(f"❌ 벡터 DB 로드 실패: {e}")
            print("scripts/prepare_vectors.py를 먼저 실행해주세요.")
            raise
        
        # OpenAI 클라이언트 초기화
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY 환경 변수가 설정되지 않았습니다.")
        
        self.client = OpenAI(api_key=api_key)
        
    def search_similar(self, query: str, top_k: int = 5) -> Dict:
        """유사한 문서 검색 (top_k를 5로 증가)"""
        results = self.collection.query(
            query_texts=[query],
            n_results=top_k
        )
        return results
    
    def ask(self, question: str) -> str:
        """질문에 대한 답변 생성"""
        # 1. 관련 문서 검색 (더 많은 컨텍스트를 위해 5개 검색)
        search_results = self.search_similar(question, top_k=5)
        
        if not search_results['documents'][0]:
            return "관련된 정보를 찾을 수 없습니다."
        
        # 2. 컨텍스트 생성 (중복 제거)
        unique_docs = []
        seen = set()
        
        for doc in search_results['documents'][0]:
            # 문서의 처음 100자를 기준으로 중복 체크
            doc_key = doc[:100] if len(doc) > 100 else doc
            if doc_key not in seen:
                seen.add(doc_key)
                unique_docs.append(doc)
        
        context = "\n\n---\n\n".join(unique_docs)
        
        # 3. 더 상세한 프롬프트 생성
        prompt = f"""
        당신은 한국정보보호산업협회(KISIA)의 Python 시큐어 코딩 가이드 전문가입니다.
        아래 제공된 가이드라인을 참고하여 정확하고 실용적인 답변을 제공해주세요.
        
        [Python 시큐어코딩 가이드라인 내용]
        {context}
        
        [사용자 질문]
        {question}
        
        [답변 지침]
        1. 가이드라인에 있는 내용을 기반으로 답변하세요.
        2. 구체적인 코드 예시가 있다면 포함하세요.
        3. 보안 취약점과 해결 방법을 명확히 설명하세요.
        4. 한국어로 답변하세요.
        
        [답변]
        """
        
        # 4. OpenAI API 호출
        try:
            model = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
            response = self.client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "system", 
                        "content": "당신은 Python 보안 전문가입니다. KISIA Python 시큐어코딩 가이드를 기반으로 정확한 답변을 제공합니다."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1500  # 더 긴 답변을 위해 증가
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            return f"오류 발생: {str(e)}"
    
    def get_stats(self) -> Dict:
        """벡터 DB 통계 정보"""
        return {
            "total_documents": self.collection.count(),
            "collection_name": "secure_coding_guide",
            "metadata": self.collection.get()['metadatas'][:5] if self.collection.count() > 0 else []
        }