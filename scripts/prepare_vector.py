# scripts/prepare_vectors_v2.py
"""
PDF 전체를 벡터화하는 개선된 스크립트
ChromaDB 메타데이터 호환성 문제 해결
"""
import pdfplumber
import chromadb
from chromadb.config import Settings
import re
from pathlib import Path
from typing import List, Dict
import hashlib

class PDFProcessor:
    def __init__(self, pdf_path: str):
        self.pdf_path = pdf_path
        self.chroma_client = chromadb.PersistentClient(
            path="data/vector_db",
            settings=Settings(anonymized_telemetry=False)
        )
    
    def process(self):
        """메인 처리 함수"""
        print("📚 PDF 처리 시작")
        
        # PDF 정보
        with pdfplumber.open(self.pdf_path) as pdf:
            total_pages = len(pdf.pages)
            print(f"📖 전체: {total_pages} 페이지")
        
        # 범위 설정
        start = 8
        end = min(171, total_pages)  # 안전하게 처리
        print(f"📄 처리 범위: {start}-{end} 페이지")
        
        # 추출
        chunks = self.extract_chunks(start, end)
        
        # DB 생성
        self.create_db(chunks)
        
        print(f"\n✅ 완료! {len(chunks)}개 청크 생성")
    
    def extract_chunks(self, start: int, end: int) -> List[Dict]:
        """텍스트를 청크로 분할"""
        chunks = []
        
        with pdfplumber.open(self.pdf_path) as pdf:
            current_text = ""
            current_page = start
            
            for page_num in range(start-1, min(end, len(pdf.pages))):
                page = pdf.pages[page_num]
                text = page.extract_text()
                
                if not text:
                    continue
                
                current_text += text + "\n"
                
                # 2000자마다 청크 생성
                while len(current_text) > 2000:
                    chunk_text = current_text[:2000]
                    chunks.append({
                        'text': chunk_text,
                        'page': page_num + 1
                    })
                    current_text = current_text[1800:]  # 약간 겹치게
                
                if (page_num + 1) % 10 == 0:
                    print(f"  ✓ {page_num + 1}/{end} 페이지 처리")
            
            # 남은 텍스트
            if current_text.strip():
                chunks.append({
                    'text': current_text,
                    'page': end
                })
        
        print(f"✅ {len(chunks)}개 청크 생성")
        return chunks
    
    def create_db(self, chunks: List[Dict]):
        """벡터 DB 생성"""
        print("\n🗄️ 벡터 DB 생성 중...")
        
        # 기존 삭제
        try:
            self.chroma_client.delete_collection("secure_coding_guide")
            print("  ✓ 기존 컬렉션 삭제")
        except:
            pass
        
        # 새 컬렉션
        collection = self.chroma_client.create_collection(
            name="secure_coding_guide",
            metadata={"description": "Python 시큐어코딩 가이드"}
        )
        
        # 데이터 준비
        batch_size = 40
        
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i:i+batch_size]
            
            documents = []
            metadatas = []
            ids = []
            
            for j, chunk in enumerate(batch):
                # 텍스트
                text = chunk['text']
                documents.append(text)
                
                # 메타데이터 - 단순하게 유지
                metadata = {
                    'page': chunk['page'],
                    'chunk_index': i + j,
                    'length': len(text)
                }
                
                # 키워드 추출 (문자열로)
                keywords = self.extract_keywords(text)
                if keywords:
                    metadata['keywords'] = keywords  # 이미 문자열
                
                metadatas.append(metadata)
                
                # ID
                ids.append(f"chunk_{i+j:04d}")
            
            # 저장
            try:
                collection.add(
                    documents=documents,
                    metadatas=metadatas,
                    ids=ids
                )
                print(f"  ✓ {min(i+batch_size, len(chunks))}/{len(chunks)} 저장")
            except Exception as e:
                print(f"  ❌ 배치 {i//batch_size + 1} 실패: {e}")
                # 문제 있는 메타데이터 확인
                for m in metadatas:
                    for k, v in m.items():
                        if not isinstance(v, (str, int, float, bool, type(None))):
                            print(f"    문제: {k} = {v} (타입: {type(v)})")
        
        print("✅ 벡터 DB 생성 완료")
        
        # 테스트
        self.test_search(collection)
    
    def extract_keywords(self, text: str) -> str:
        """키워드 추출 - 문자열로 반환"""
        keywords = []
        
        # 보안 키워드
        patterns = [
            'SQL.?삽입', 'SQL.?인젝션', 'XSS', '크로스사이트',
            'CSRF', '인증', '인가', '암호화', '해시', '패스워드',
            '파일.?업로드', '경로.?조작', 'LDAP', '코드.?삽입'
        ]
        
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                keywords.append(pattern.replace('.?', ''))
        
        # 최대 5개, 쉼표로 구분된 문자열
        return ', '.join(keywords[:5])
    
    def test_search(self, collection):
        """테스트 검색"""
        print("\n🔍 테스트 검색:")
        
        queries = [
            "SQL 인젝션",
            "패스워드 저장",
            "XSS 방지",
            "파일 업로드"
        ]
        
        for query in queries:
            results = collection.query(
                query_texts=[query],
                n_results=1
            )
            
            if results['documents'][0]:
                doc = results['documents'][0][0][:100] + "..."
                meta = results['metadatas'][0][0]
                print(f"  ✓ '{query}' → 페이지 {meta.get('page', '?')}")

def main():
    pdf_path = "data/guidelines/Python_시큐어코딩_가이드(2023년_개정본).pdf"
    
    if not Path(pdf_path).exists():
        print(f"❌ PDF 없음: {pdf_path}")
        return
    
    processor = PDFProcessor(pdf_path)
    processor.process()

if __name__ == "__main__":
    main()