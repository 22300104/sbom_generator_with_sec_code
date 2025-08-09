# scripts/prepare_vectors.py
import pdfplumber
import chromadb
from chromadb.config import Settings
import json
import re
from pathlib import Path

class GuidelineProcessor:
    def __init__(self, pdf_path):
        self.pdf_path = pdf_path
        # ChromaDB 클라이언트 초기화 (로컬 저장)
        self.chroma_client = chromadb.PersistentClient(
            path="data/vector_db",
            settings=Settings(anonymized_telemetry=False)
        )
        
    def extract_pdf_content(self, start_page=8, end_page=50):
        """PDF에서 핵심 페이지만 추출 (MVP용)"""
        print(f"📖 PDF 추출 중... ({start_page}-{end_page} 페이지)")
        
        extracted_content = []
        
        with pdfplumber.open(self.pdf_path) as pdf:
            for page_num in range(start_page-1, min(end_page, len(pdf.pages))):
                page = pdf.pages[page_num]
                
                # 레이아웃 보존하면서 텍스트 추출
                text = page.extract_text()
                
                if text:
                    # 섹션별로 구분
                    sections = self._parse_sections(text, page_num + 1)
                    extracted_content.extend(sections)
                    
                print(f"  ✓ {page_num + 1} 페이지 처리 완료")
        
        return extracted_content
    
    def _parse_sections(self, text, page_num):
        """텍스트를 의미있는 섹션으로 분리"""
        sections = []
        
        # 주요 패턴들
        patterns = {
            'vulnerability': r'^\d+\.\s+(.+?)$',  # "1. SQL 삽입" 같은 패턴
            'safe_code': r'안전한 코드 예시',
            'unsafe_code': r'안전하지 않은 코드 예시',
            'description': r'가\.\s*개요',
            'solution': r'나\.\s*안전한 코딩기법'
        }
        
        lines = text.split('\n')
        current_section = {'type': 'general', 'content': [], 'page': page_num}
        
        for line in lines:
            # 섹션 타입 결정
            for section_type, pattern in patterns.items():
                if re.search(pattern, line):
                    # 이전 섹션 저장
                    if current_section['content']:
                        sections.append({
                            'type': current_section['type'],
                            'content': '\n'.join(current_section['content']),
                            'page': current_section['page']
                        })
                    # 새 섹션 시작
                    current_section = {
                        'type': section_type,
                        'content': [line],
                        'page': page_num
                    }
                    break
            else:
                # 현재 섹션에 추가
                current_section['content'].append(line)
        
        # 마지막 섹션 저장
        if current_section['content']:
            sections.append({
                'type': current_section['type'],
                'content': '\n'.join(current_section['content']),
                'page': current_section['page']
            })
        
        return sections
    
    def create_vector_db(self, content_sections):
        """ChromaDB에 벡터 저장"""
        print("\n🗄️ 벡터 DB 생성 중...")
        
        # 기존 컬렉션 삭제 (있다면)
        try:
            self.chroma_client.delete_collection("secure_coding_guide")
        except:
            pass
        
        # 새 컬렉션 생성
        collection = self.chroma_client.create_collection(
            name="secure_coding_guide",
            metadata={"description": "Python 시큐어코딩 가이드"}
        )
        
        # 문서와 메타데이터 준비
        documents = []
        metadatas = []
        ids = []
        
        for idx, section in enumerate(content_sections):
            documents.append(section['content'])
            metadatas.append({
                'type': section['type'],
                'page': section['page']
            })
            ids.append(f"doc_{idx}")
        
        # 벡터 DB에 추가 (청킹해서 추가)
        batch_size = 100
        for i in range(0, len(documents), batch_size):
            end_idx = min(i + batch_size, len(documents))
            collection.add(
                documents=documents[i:end_idx],
                metadatas=metadatas[i:end_idx],
                ids=ids[i:end_idx]
            )
            print(f"  ✓ {end_idx}/{len(documents)} 문서 저장")
        
        print(f"✅ 총 {len(documents)}개 섹션 벡터 DB 저장 완료!")
        return collection

def main():
    # PDF 경로 설정
    pdf_path = "data/guidelines/Python_시큐어코딩_가이드(2023년_개정본).pdf"
    
    if not Path(pdf_path).exists():
        print(f"❌ PDF 파일을 찾을 수 없습니다: {pdf_path}")
        print("파일을 data/guidelines/ 폴더에 넣어주세요.")
        return
    
    # 처리 시작
    processor = GuidelineProcessor(pdf_path)
    
    # 1. PDF 내용 추출 (8-50 페이지: 주요 보안 항목들)
    content_sections = processor.extract_pdf_content(start_page=8, end_page=50)
    
    # 2. 벡터 DB 생성
    collection = processor.create_vector_db(content_sections)
    
    # 3. 테스트 검색
    print("\n🔍 테스트 검색 수행...")
    test_queries = [
        "SQL 삽입 방어 방법",
        "안전한 패스워드 저장",
        "XSS 공격 방지"
    ]
    
    for query in test_queries:
        results = collection.query(
            query_texts=[query],
            n_results=2
        )
        print(f"\n질문: {query}")
        print(f"검색 결과: {len(results['documents'][0])}개 찾음")
        if results['documents'][0]:
            print(f"첫 번째 결과: {results['documents'][0][0][:100]}...")
    
    print("\n✅ MVP 벡터 DB 준비 완료!")

if __name__ == "__main__":
    main()