"""
Guideline processing for RAG
"""
import os
import glob
import PyPDF2
from typing import List, Dict
from config import rag_config
from core.models import ChunkInfo

class GuidelineProcessor:
    """가이드라인을 RAG용으로 처리"""
    
    def __init__(self):
        self.config = rag_config
        self.chunks = []
        self.documents = {}  # 이 부분이 중요!
        self.is_processed = False
        self.processing_log = []
    
    def process_all_pdfs(self) -> Dict:
        """모든 PDF를 읽고 청킹"""
        pdf_files = glob.glob(os.path.join(self.config.GUIDELINE_DIR, "*.pdf"))
        
        if not pdf_files:
            return {
                "success": False, 
                "error": f"PDF 파일이 없습니다: {self.config.GUIDELINE_DIR}"
            }
        
        all_text = ""
        file_count = 0
        
        for pdf_path in pdf_files:
            filename = os.path.basename(pdf_path)
            self.processing_log.append(f"📄 처리: {filename}")
            
            try:
                with open(pdf_path, 'rb') as file:
                    pdf_reader = PyPDF2.PdfReader(file)
                    
                    text_content = ""
                    for page in pdf_reader.pages:
                        page_text = page.extract_text()
                        text_content += page_text + "\n"
                    
                    # 문서 정보 저장
                    self.documents[filename] = {
                        "text": text_content,
                        "table_count": 0,  # 임시
                        "code_count": 0,   # 임시
                        "total_chars": len(text_content)
                    }
                    
                    all_text += f"\n[문서: {filename}]\n{text_content}\n"
                    file_count += 1
                    
            except Exception as e:
                self.processing_log.append(f"❌ 실패: {filename} - {str(e)}")
        
        self.chunks = self._create_chunks(all_text)
        self.is_processed = True
        
        return {
            "success": True,
            "files_processed": file_count,
            "total_chunks": len(self.chunks),
            "total_chars": len(all_text),
            "total_tables": 0,
            "total_code_blocks": 0,
            "documents": self.documents,
            "processing_log": self.processing_log
        }
    
    def _create_chunks(self, text: str) -> List[ChunkInfo]:
        """텍스트를 RAG용 청크로 분할"""
        chunks = []
        sentences = text.split('.')
        
        current_chunk = ""
        chunk_id = 0
        
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue
            
            if len(current_chunk) + len(sentence) > self.config.CHUNK_SIZE and current_chunk:
                chunks.append(ChunkInfo(
                    id=chunk_id,
                    text=current_chunk,
                    char_count=len(current_chunk),
                    metadata={"type": "text"}
                ))
                
                overlap_text = current_chunk[-self.config.OVERLAP:] if len(current_chunk) > self.config.OVERLAP else current_chunk
                current_chunk = overlap_text + " " + sentence
                chunk_id += 1
            else:
                current_chunk += " " + sentence
        
        if current_chunk:
            chunks.append(ChunkInfo(
                id=chunk_id,
                text=current_chunk,
                char_count=len(current_chunk),
                metadata={"type": "text"}
            ))
        
        return chunks
    
    def get_chunks_for_embedding(self) -> List[str]:
        """임베딩용 텍스트 청크 반환"""
        if not self.is_processed:
            self.process_all_pdfs()
        return [chunk.text for chunk in self.chunks]
    
    def search_similar_chunks(self, query: str, top_k: int = None) -> List[str]:
        """간단한 키워드 기반 검색"""
        if not self.is_processed:
            self.process_all_pdfs()
        
        if top_k is None:
            top_k = self.config.TOP_K
        
        query_lower = query.lower()
        scored_chunks = []
        
        for chunk in self.chunks:
            score = chunk.text.lower().count(query_lower)
            if score > 0:
                scored_chunks.append((score, chunk.text))
        
        scored_chunks.sort(key=lambda x: x[0], reverse=True)
        return [text for _, text in scored_chunks[:top_k]]
    
    def get_processing_summary(self) -> Dict:
        """처리 요약 정보 반환"""
        if not self.documents:
            return {"files": []}
        
        summary = {
            "total_files": len(self.documents),
            "total_tables": sum(doc.get("table_count", 0) for doc in self.documents.values()),
            "total_code_blocks": sum(doc.get("code_count", 0) for doc in self.documents.values()),
            "total_chars": sum(doc.get("total_chars", 0) for doc in self.documents.values()),
            "files": []
        }
        
        for filename, doc in self.documents.items():
            summary["files"].append({
                "name": filename,
                "tables": doc.get("table_count", 0),
                "code_blocks": doc.get("code_count", 0),
                "chars": doc.get("total_chars", 0)
            })
        
        return summary