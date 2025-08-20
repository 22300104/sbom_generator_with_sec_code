# rag/simple_rag.py
# 전체 파일 교체

import os
from typing import List, Dict
from openai import OpenAI
from prompts.all_prompts import RAG_PROMPTS, SYSTEM_PROMPTS

class SimpleRAG:
    def __init__(self):
        self.collection = None
        self.chroma_available = False
        
        # ChromaDB 로드 시도 (실패해도 계속 진행)
        try:
            import chromadb
            self.chroma_client = chromadb.PersistentClient(path="data/vector_db")
            
            try:
                self.collection = self.chroma_client.get_collection("secure_coding_guide")
                self.chroma_available = True
                print(f"✅ 벡터 DB 로드 완료 (문서 수: {self.collection.count()})")
            except Exception as e:
                print(f"⚠️ ChromaDB Collection 없음: {e}")
                print("RAG 없이 일반 Q&A 모드로 작동합니다.")
        except ImportError:
            print("⚠️ ChromaDB가 설치되지 않았습니다. 일반 Q&A 모드로 작동합니다.")
        except Exception as e:
            print(f"⚠️ ChromaDB 초기화 실패: {e}")
        
        # OpenAI 클라이언트 초기화
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY 환경 변수가 설정되지 않았습니다.")
        
        self.client = OpenAI(api_key=api_key)
        
    def search_similar(self, query: str, top_k: int = 5) -> Dict:
        """유사한 문서 검색 (ChromaDB 있을 때만)"""
        if self.chroma_available and self.collection:
            try:
                results = self.collection.query(
                    query_texts=[query],
                    n_results=top_k
                )
                return results
            except Exception as e:
                print(f"검색 오류: {e}")
                return {'documents': [[]], 'metadatas': [[]]}
        else:
            # ChromaDB 없을 때 빈 결과 반환
            return {'documents': [[]], 'metadatas': [[]]}


    def ask(self, question: str) -> str:
        """질문에 대한 답변 생성 - Claude 우선"""
        
        from prompts.all_prompts import RAG_PROMPTS, SYSTEM_PROMPTS
        
        # RAG 모드 (ChromaDB 있을 때)
        if self.chroma_available:
            search_results = self.search_similar(question, top_k=5)
            
            if search_results['documents'][0]:
                # RAG 컨텍스트 있음
                documents = search_results['documents'][0]
                context = "\n\n---\n\n".join(documents[:3])
                
                # 중앙 관리 프롬프트 사용
                prompt = RAG_PROMPTS["qa_with_rag_context"].format(
                    context=context,
                    question=question
                )
            else:
                # RAG 컨텍스트 없음 - 일반 모드로 전환
                prompt = RAG_PROMPTS["qa_without_rag"].format(question=question)
        else:
            # 일반 Q&A 모드 (ChromaDB 없을 때)
            prompt = RAG_PROMPTS["qa_without_rag"].format(question=question)
        
        # 1. Claude 우선 시도 (메인 엔진)
        if os.getenv("ANTHROPIC_API_KEY"):
            try:
                from anthropic import Anthropic
                claude_client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
                model = os.getenv("ANTHROPIC_MODEL", "claude-3-opus-20240229")
                
                # Claude는 system 프롬프트를 user 메시지에 포함
                full_prompt = f"""{SYSTEM_PROMPTS.get('qa_expert', 'Python 보안 전문가입니다.')}

        {prompt}"""
                
                response = claude_client.messages.create(
                    model=model,
                    max_tokens=1500,
                    temperature=0.3,
                    messages=[
                        {
                            "role": "user",
                            "content": full_prompt
                        }
                    ]
                )
                
                # Claude 응답 형식에 맞게 추출
                if hasattr(response, 'content') and response.content:
                    return response.content[0].text
                else:
                    print(f"⚠️ Claude 응답 형식 오류: {response}")
                    raise ValueError("Claude 응답 형식 오류")
                    
            except Exception as e:
                print(f"⚠️ Claude 실패, GPT로 폴백: {e}")
        
        # 2. GPT 폴백 (Claude 실패 또는 미설정 시)
        if os.getenv("OPENAI_API_KEY"):
            try:
                model = os.getenv("OPENAI_MODEL")
                
                if not model:
                    model = "gpt-4-turbo-preview"
                    print(f"⚠️ OPENAI_MODEL 미설정, 기본값 사용: {model}")
                
                response = self.client.chat.completions.create(
                    model=model,
                    messages=[
                        {
                            "role": "system", 
                            "content": SYSTEM_PROMPTS.get("qa_expert", "Python 보안 전문가입니다.")
                        },
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                    max_tokens=1500
                )
                
                return response.choices[0].message.content
                
            except Exception as e:
                print(f"❌ GPT도 실패: {e}")
                return f"오류 발생: {str(e)}"
        
        # 3. 모든 API 실패 시
        return """죄송합니다. AI 서비스를 사용할 수 없습니다.

    다음을 확인해주세요:
    1. API 키가 올바르게 설정되었는지 (.env 파일)
    2. 인터넷 연결이 정상인지
    3. API 크레딧이 남아있는지

    문제가 지속되면 시스템 관리자에게 문의하세요."""
    
    def get_stats(self) -> Dict:
        """시스템 상태 정보"""
        if self.chroma_available and self.collection:
            return {
                "mode": "RAG 모드",
                "total_documents": self.collection.count(),
                "collection_name": "secure_coding_guide",
                "status": "정상"
            }
        else:
            return {
                "mode": "일반 Q&A 모드",
                "total_documents": 0,
                "collection_name": "없음",
                "status": "RAG 없이 작동 중"
            }