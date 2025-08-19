# scripts/02_extract_pdf_content.py
"""
PDF에서 텍스트와 코드를 구조화하여 추출
분석 결과를 바탕으로 의미 단위로 추출
"""
import pdfplumber
import json
from pathlib import Path
from typing import List, Dict, Tuple
import re
from dataclasses import dataclass, asdict

@dataclass
class CodeExample:
    """코드 예제 구조체"""
    page: int
    type: str  # 'unsafe' or 'safe'
    code: str
    context: str  # 코드 앞뒤 설명
    vulnerability_type: List[str]
    label: str

@dataclass
class VulnerabilitySection:
    """취약점 섹션 구조체"""
    title: str
    description: str
    unsafe_code: CodeExample
    safe_code: CodeExample
    page_range: Tuple[int, int]
    recommendations: str

class PDFContentExtractor:
    def __init__(self, pdf_path: str, analysis_path: str = "data/processed/metadata/pdf_analysis_fixed.json"):
        self.pdf_path = Path(pdf_path)
        
        # 이전 분석 결과 로드
        with open(analysis_path, 'r', encoding='utf-8') as f:
            self.analysis = json.load(f)
        
        self.content = {
            "vulnerability_sections": [],
            "code_examples": [],
            "chunks": [],
            "metadata": {
                "total_pages": self.analysis['total_pages'],
                "total_sections": 0,
                "total_chunks": 0
            }
        }
        
    def extract(self):
        """PDF 내용 추출"""
        print(f"📄 PDF 내용 추출 시작: {self.pdf_path.name}")
        
        with pdfplumber.open(self.pdf_path) as pdf:
            # 1. 코드 쌍 기반으로 취약점 섹션 추출
            self._extract_vulnerability_sections(pdf)
            
            # 2. 전체 텍스트를 의미 단위로 청킹
            self._create_semantic_chunks(pdf)
            
            # 3. 메타데이터 업데이트
            self._update_metadata()
        
        print(f"✅ 추출 완료")
        return self.content
    
    def _extract_vulnerability_sections(self, pdf):
        """취약점 섹션 추출"""
        print(f"🔍 취약점 섹션 추출 중...")
        
        code_pairs = self.analysis.get('code_pairs', [])
        
        for pair in code_pairs:
            unsafe_code = pair['unsafe']
            safe_code = pair['safe']
            
            # 페이지 범위 결정
            start_page = min(unsafe_code['page'], safe_code['page'])
            end_page = max(unsafe_code['page'], safe_code['page'])
            
            # 해당 페이지들의 텍스트 추출
            section_text = ""
            for page_num in range(start_page - 1, min(end_page + 1, len(pdf.pages))):
                page = pdf.pages[page_num]
                section_text += page.extract_text() + "\n"
            
            # 섹션 제목 찾기
            title = self._find_section_title(section_text, start_page)
            
            # 설명 텍스트 추출
            description = self._extract_description(section_text, unsafe_code, safe_code)
            
            # 권장사항 추출
            recommendations = self._extract_recommendations(section_text)
            
            # VulnerabilitySection 생성
            vuln_section = {
                "title": title,
                "description": description,
                "unsafe_code": {
                    "page": unsafe_code['page'],
                    "code": unsafe_code.get('code', ''),
                    "label": unsafe_code.get('label', '안전하지 않은 코드 예시')
                },
                "safe_code": {
                    "page": safe_code['page'],
                    "code": safe_code.get('code', ''),
                    "label": safe_code.get('label', '안전한 코드 예시')
                },
                "page_range": [start_page, end_page],
                "recommendations": recommendations,
                "vulnerability_types": pair.get('vulnerability_type', ['General'])
            }
            
            self.content["vulnerability_sections"].append(vuln_section)
        
        print(f"  ✓ {len(self.content['vulnerability_sections'])}개 취약점 섹션 추출")
    
    def _create_semantic_chunks(self, pdf):
        """의미 단위로 텍스트 청킹"""
        print(f"📝 의미 단위 청킹 중...")
        
        for page_num, page in enumerate(pdf.pages, 1):
            if page_num % 30 == 0:
                print(f"  처리 중... {page_num}/{len(pdf.pages)} 페이지")
            
            text = page.extract_text()
            if not text:
                continue
            
            # 페이지를 의미 단위로 분할
            chunks = self._split_into_chunks(text, page_num)
            
            for chunk in chunks:
                # 청크 분류
                chunk_type = self._classify_chunk(chunk['text'])
                
                self.content["chunks"].append({
                    "page": page_num,
                    "text": chunk['text'],
                    "type": chunk_type,
                    "metadata": {
                        "char_count": len(chunk['text']),
                        "has_code": self._has_code(chunk['text']),
                        "keywords": self._extract_keywords(chunk['text'])
                    }
                })
        
        print(f"  ✓ {len(self.content['chunks'])}개 청크 생성")
    
    def _split_into_chunks(self, text: str, page_num: int, 
                          chunk_size: int = 800, 
                          overlap: int = 200) -> List[Dict]:
        """텍스트를 청크로 분할"""
        chunks = []
        
        # 단락 단위로 먼저 분할
        paragraphs = text.split('\n\n')
        
        current_chunk = ""
        for para in paragraphs:
            # 청크 크기 확인
            if len(current_chunk) + len(para) < chunk_size:
                current_chunk += para + "\n\n"
            else:
                if current_chunk:
                    chunks.append({
                        'text': current_chunk.strip(),
                        'page': page_num
                    })
                
                # 오버랩 처리
                if len(current_chunk) > overlap:
                    overlap_text = current_chunk[-overlap:]
                    current_chunk = overlap_text + para + "\n\n"
                else:
                    current_chunk = para + "\n\n"
        
        # 마지막 청크
        if current_chunk.strip():
            chunks.append({
                'text': current_chunk.strip(),
                'page': page_num
            })
        
        return chunks
    
    def _classify_chunk(self, text: str) -> str:
        """청크 분류"""
        text_lower = text.lower()
        
        # 코드 청크
        if any(pattern in text for pattern in ['def ', 'class ', 'import ', 'if __name__']):
            return 'code'
        
        # 취약점 설명
        if any(word in text_lower for word in ['취약점', '공격', 'injection', 'xss', 'csrf']):
            return 'vulnerability'
        
        # 권장사항
        if any(word in text_lower for word in ['권장', '해야', '주의', '방지', '보안']):
            return 'recommendation'
        
        # 일반 설명
        return 'general'
    
    def _has_code(self, text: str) -> bool:
        """코드 포함 여부 확인"""
        code_patterns = [
            r'def \w+\(',
            r'class \w+',
            r'import \w+',
            r'\w+\.\w+\(',
            r'if .+:',
            r'for .+ in .+:',
        ]
        
        for pattern in code_patterns:
            if re.search(pattern, text):
                return True
        return False
    
    def _extract_keywords(self, text: str) -> List[str]:
        """키워드 추출"""
        keywords = []
        
        # 보안 관련 키워드
        security_keywords = [
            'SQL', 'XSS', 'CSRF', 'injection', '취약점', '보안',
            '암호화', '인증', '인가', '세션', '쿠키', 'token',
            'escape', 'sanitize', 'validate', 'filter'
        ]
        
        for keyword in security_keywords:
            if keyword.lower() in text.lower():
                keywords.append(keyword)
        
        return keywords[:5]  # 최대 5개
    
    def _find_section_title(self, text: str, page_num: int) -> str:
        """섹션 제목 찾기"""
        lines = text.split('\n')
        
        # 제목 패턴
        title_patterns = [
            r'^(\d+\.[\d\.]*)\s+(.+)$',  # 1.2.3 제목
            r'^(제\d+[장절])\s+(.+)$',    # 제1장 제목
            r'^\[(.+)\]$',                # [제목]
        ]
        
        for line in lines[:20]:  # 처음 20줄만 확인
            for pattern in title_patterns:
                match = re.match(pattern, line.strip())
                if match:
                    return line.strip()
        
        return f"Section (Page {page_num})"
    
    def _extract_description(self, text: str, unsafe_code: Dict, safe_code: Dict) -> str:
        """설명 추출"""
        # 코드 전후의 텍스트를 설명으로 추출
        lines = text.split('\n')
        
        # "안전하지 않은 코드 예시" 이전 텍스트 찾기
        description_lines = []
        for i, line in enumerate(lines):
            if '안전하지 않은 코드' in line:
                # 이전 10줄 정도를 설명으로
                start = max(0, i - 10)
                description_lines = lines[start:i]
                break
        
        description = '\n'.join(description_lines)
        
        # 너무 길면 요약
        if len(description) > 1000:
            description = description[:1000] + "..."
        
        return description.strip()
    
    def _extract_recommendations(self, text: str) -> str:
        """권장사항 추출"""
        recommendations = []
        
        # 권장사항 키워드
        rec_keywords = ['권장', '해야', '사용하세요', '주의', '방지', '확인']
        
        lines = text.split('\n')
        for line in lines:
            if any(keyword in line for keyword in rec_keywords):
                recommendations.append(line.strip())
        
        # 최대 5개 권장사항
        return '\n'.join(recommendations[:5])
    
    def _update_metadata(self):
        """메타데이터 업데이트"""
        self.content["metadata"]["total_sections"] = len(self.content["vulnerability_sections"])
        self.content["metadata"]["total_chunks"] = len(self.content["chunks"])
        
        # 청크 타입별 통계
        chunk_types = {}
        for chunk in self.content["chunks"]:
            chunk_type = chunk['type']
            chunk_types[chunk_type] = chunk_types.get(chunk_type, 0) + 1
        
        self.content["metadata"]["chunk_types"] = chunk_types
    
    def save_results(self, output_dir: str = "data/processed"):
        """추출 결과 저장"""
        output_dir = Path(output_dir)
        
        # 취약점 섹션 저장
        vuln_path = output_dir / "chunks" / "vulnerability_sections.json"
        vuln_path.parent.mkdir(parents=True, exist_ok=True)
        with open(vuln_path, 'w', encoding='utf-8') as f:
            json.dump(self.content["vulnerability_sections"], f, 
                     ensure_ascii=False, indent=2)
        print(f"✅ 취약점 섹션 저장: {vuln_path}")
        
        # 청크 저장
        chunks_path = output_dir / "chunks" / "semantic_chunks.json"
        with open(chunks_path, 'w', encoding='utf-8') as f:
            json.dump(self.content["chunks"], f, 
                     ensure_ascii=False, indent=2)
        print(f"✅ 청크 저장: {chunks_path}")
        
        # 메타데이터 저장
        meta_path = output_dir / "metadata" / "extraction_metadata.json"
        with open(meta_path, 'w', encoding='utf-8') as f:
            json.dump(self.content["metadata"], f, 
                     ensure_ascii=False, indent=2)
        print(f"✅ 메타데이터 저장: {meta_path}")
    
    def print_summary(self):
        """추출 요약 출력"""
        print("\n" + "="*60)
        print("📊 PDF 내용 추출 결과")
        print("="*60)
        
        print(f"\n📄 파일: {self.pdf_path.name}")
        print(f"📑 총 페이지: {self.content['metadata']['total_pages']}")
        
        print(f"\n🎯 취약점 섹션:")
        print(f"  • 총 섹션: {self.content['metadata']['total_sections']}개")
        
        # 취약점 타입별 통계
        vuln_types = {}
        for section in self.content["vulnerability_sections"]:
            for vtype in section.get('vulnerability_types', ['General']):
                vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
        
        print(f"\n  취약점 타입별:")
        for vtype, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
            print(f"    • {vtype}: {count}개")
        
        print(f"\n📝 청크 분석:")
        print(f"  • 총 청크: {self.content['metadata']['total_chunks']}개")
        
        if 'chunk_types' in self.content['metadata']:
            print(f"\n  청크 타입별:")
            for ctype, count in self.content['metadata']['chunk_types'].items():
                print(f"    • {ctype}: {count}개")

if __name__ == "__main__":
    # PDF 경로
    pdf_path = "data/guidelines/Python_시큐어코딩_가이드(2023년_개정본).pdf"
    
    # 추출기 생성 및 실행
    extractor = PDFContentExtractor(pdf_path)
    content = extractor.extract()
    
    # 결과 저장
    extractor.save_results()
    
    # 요약 출력
    extractor.print_summary()