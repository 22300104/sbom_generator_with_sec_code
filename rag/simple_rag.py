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


# rag/simple_rag.py
# ask() 함수 전체 교체

    def ask(self, question: str) -> str:
        """질문에 대한 답변 생성 - AI 메인, RAG 보조"""
        
        from prompts.all_prompts import RAG_PROMPTS, SYSTEM_PROMPTS
        import time
        
        # 1. RAG 검색 시도 (빠르게, 실패해도 OK)
        rag_context = ""
        rag_section = ""
        source_note = ""
        
        if self.chroma_available:
            try:
                # 빠른 RAG 검색
                start_time = time.time()
                search_results = self.search_similar(question, top_k=3)
                
                if time.time() - start_time < 1.0 and search_results['documents'][0]:
                    # RAG 문서 발견
                    documents = search_results['documents'][0]
                    rag_context = "\n\n".join(documents[:2])  # 상위 2개만
                    
                    # RAG 섹션 구성
                    rag_section = f"\n[참고 자료]\n{rag_context}\n"
                    source_note = "- KISIA 가이드라인을 참고하여 답변"
                    print(f"✅ RAG 문서 {len(documents)}개 발견")
                else:
                    print("⚠️ RAG 문서 없음 또는 시간 초과")
                    source_note = "- 일반 보안 지식 기반 답변"
            except Exception as e:
                print(f"⚠️ RAG 검색 실패 (계속 진행): {e}")
                source_note = "- 일반 보안 지식 기반 답변"
        else:
            source_note = "- 일반 보안 지식 기반 답변"
        
        # 2. 통합 프롬프트 사용
        prompt = RAG_PROMPTS["qa_unified"].format(
            rag_section=rag_section,
            question=question,
            source_note=source_note
        )
        
        # 3. AI 답변 생성 (Claude 우선, GPT 폴백)
        answer = None
        
        # Claude 시도
        if os.getenv("ANTHROPIC_API_KEY"):
            try:
                from anthropic import Anthropic
                claude_client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
                model = os.getenv("ANTHROPIC_MODEL")
                if not model:
                    model = "claude-3-opus-20240229"
                    print(f"⚠️ ANTHROPIC_MODEL 미설정, 기본값: {model}")
                
                # Claude는 system을 user에 포함
                system_prompt = SYSTEM_PROMPTS.get("qa_expert", "")
                full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
                
                response = claude_client.messages.create(
                    model=model,
                    max_tokens=1500,
                    temperature=0.3,
                    messages=[{"role": "user", "content": full_prompt}]
                )
                
                answer = response.content[0].text
                print("✅ Claude 답변 생성 완료")
                
            except Exception as e:
                print(f"⚠️ Claude 실패, GPT로 폴백: {e}")
        
        # GPT 폴백
        if not answer and os.getenv("OPENAI_API_KEY"):
            try:
                model = os.getenv("OPENAI_MODEL")
                if not model:
                    model = "gpt-4-turbo-preview"
                    print(f"⚠️ OPENAI_MODEL 미설정, 기본값: {model}")
                
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
                
                answer = response.choices[0].message.content
                print("✅ GPT 답변 생성 완료")
                
            except Exception as e:
                print(f"❌ GPT도 실패: {e}")
                answer = f"오류 발생: {str(e)}"
        
        # 4. 최종 답변 구성
        if answer:
            # 출처 표시 추가
            if rag_context:
                footer = "\n\n---\n*📚 KISIA Python 시큐어코딩 가이드를 참고한 답변입니다.*"
            else:
                footer = "\n\n---\n*💡 일반 보안 지식을 기반으로 한 답변입니다.*"
            
            return answer + footer
        else:
            return "죄송합니다. AI 서비스를 사용할 수 없습니다.\n\nAPI 키 설정을 확인해주세요."
    
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