# scripts/04_parse_kisia_structured.py
"""
KISIA 가이드라인 구조화된 파싱
목차 기반으로 정확한 취약점 섹션 추출
"""
import pdfplumber
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import sys
sys.path.append('.')
from rag.kisia_vulnerability_mapping import KISIAVulnerabilityMapper

class KISIAStructuredParser:
    """KISIA 가이드라인 구조화 파서"""
    
    def __init__(self, pdf_path: str):
        self.pdf_path = Path(pdf_path)
        self.mapper = KISIAVulnerabilityMapper()
        
        # 코드 블록 레이블 패턴
        self.UNSAFE_CODE_PATTERNS = [
            r'안전하지\s*않은\s*코드\s*예시',
            r'안전하지\s*않은\s*코드',
            r'취약한\s*코드\s*예시',
            r'취약한\s*코드',
            r'잘못된\s*코드\s*예시',
            r'문제가\s*있는\s*코드'
        ]
        
        self.SAFE_CODE_PATTERNS = [
            r'안전한\s*코드\s*예시',
            r'안전한\s*코드',
            r'개선된\s*코드\s*예시',
            r'수정된\s*코드',
            r'올바른\s*코드\s*예시',
            r'권장\s*코드'
        ]
        
        self.parsed_data = {
            'vulnerabilities': [],
            'metadata': {
                'total_sections': 0,
                'total_vulnerabilities': 0
            }
        }
    
    def parse(self):
        """메인 파싱 함수"""
        print(f"📄 KISIA 가이드라인 구조화 파싱 시작: {self.pdf_path.name}")
        
        with pdfplumber.open(self.pdf_path) as pdf:
            # 각 섹션별로 파싱
            for section_name, section_items in self.mapper.GUIDELINE_STRUCTURE.items():
                print(f"\n📂 {section_name} 파싱 중...")
                
                for num, (korean_name, english_type, start_page) in section_items.items():
                    print(f"  {num}. {korean_name} (p.{start_page})")
                    
                    # 다음 항목의 시작 페이지 찾기 (섹션 끝 결정)
                    end_page = self._find_end_page(section_name, num, start_page)
                    
                    # 취약점 섹션 추출
                    vuln_data = self._extract_vulnerability_section(
                        pdf, 
                        section_name,
                        num,
                        korean_name,
                        english_type,
                        start_page,
                        end_page
                    )
                    
                    if vuln_data:
                        self.parsed_data['vulnerabilities'].append(vuln_data)
        
        # 메타데이터 업데이트
        self.parsed_data['metadata']['total_vulnerabilities'] = len(self.parsed_data['vulnerabilities'])
        
        print(f"\n✅ 파싱 완료: {len(self.parsed_data['vulnerabilities'])}개 취약점")
        
        return self.parsed_data
    
    def _find_end_page(self, section_name: str, current_num: int, start_page: int) -> int:
        """현재 취약점 섹션의 끝 페이지 찾기"""
        # 같은 섹션의 다음 항목 찾기
        section_items = self.mapper.GUIDELINE_STRUCTURE[section_name]
        next_num = current_num + 1
        
        if next_num in section_items:
            _, _, next_page = section_items[next_num]
            return next_page - 1
        
        # 다음 섹션의 첫 항목 찾기
        sections = list(self.mapper.GUIDELINE_STRUCTURE.keys())
        current_section_idx = sections.index(section_name)
        
        if current_section_idx < len(sections) - 1:
            next_section = sections[current_section_idx + 1]
            if self.mapper.GUIDELINE_STRUCTURE[next_section]:
                first_item = min(self.mapper.GUIDELINE_STRUCTURE[next_section].keys())
                _, _, next_page = self.mapper.GUIDELINE_STRUCTURE[next_section][first_item]
                return next_page - 1
        
        # 기본값: 현재 페이지 + 5
        return start_page + 5
    
    def _extract_vulnerability_section(self, pdf, section_name: str, num: int, 
                                      korean_name: str, english_type: str,
                                      start_page: int, end_page: int) -> Dict:
        """취약점 섹션 추출"""
        
        vuln_data = {
            'section': section_name,
            'number': num,
            'korean_name': korean_name,
            'english_type': english_type,
            'start_page': start_page,
            'end_page': end_page,
            'description': '',
            'unsafe_codes': [],
            'safe_codes': [],
            'recommendations': []
        }
        
        # 페이지 범위 내에서 텍스트 추출
        full_text = ""
        for page_num in range(start_page - 1, min(end_page, len(pdf.pages))):
            page = pdf.pages[page_num]
            text = page.extract_text()
            if text:
                full_text += f"\n[PAGE {page_num + 1}]\n{text}\n"
        
        # 설명 추출
        vuln_data['description'] = self._extract_description(full_text, korean_name)
        
        # 안전하지 않은 코드 추출
        unsafe_codes = self._extract_code_blocks(full_text, 'unsafe', start_page)
        vuln_data['unsafe_codes'] = unsafe_codes
        
        # 안전한 코드 추출
        safe_codes = self._extract_code_blocks(full_text, 'safe', start_page)
        vuln_data['safe_codes'] = safe_codes
        
        # 권장사항 추출
        recommendations = self._extract_recommendations(full_text)
        vuln_data['recommendations'] = recommendations
        
        return vuln_data
    
    def _extract_description(self, text: str, vuln_name: str) -> str:
        """취약점 설명 추출"""
        lines = text.split('\n')
        description_lines = []
        in_description = False
        
        for i, line in enumerate(lines):
            # 취약점 이름이 나오면 설명 시작
            if vuln_name in line and not in_description:
                in_description = True
                continue
            
            # 코드 블록이 시작되면 설명 끝
            if in_description:
                if any(re.search(pattern, line) for pattern in 
                      self.UNSAFE_CODE_PATTERNS + self.SAFE_CODE_PATTERNS):
                    break
                
                # 설명 수집
                if line.strip() and not line.startswith('[PAGE'):
                    description_lines.append(line.strip())
                
                # 최대 10줄까지만
                if len(description_lines) > 10:
                    break
        
        return ' '.join(description_lines)
    
    def _extract_code_blocks(self, text: str, code_type: str, base_page: int) -> List[Dict]:
        """코드 블록 추출"""
        if code_type == 'unsafe':
            patterns = self.UNSAFE_CODE_PATTERNS
        else:
            patterns = self.SAFE_CODE_PATTERNS
        
        code_blocks = []
        lines = text.split('\n')
        
        for i, line in enumerate(lines):
            # 코드 레이블 찾기
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # 다음 줄부터 코드 수집
                    code_lines = []
                    page_num = base_page
                    
                    # 현재 페이지 번호 추출
                    for j in range(i-1, max(0, i-10), -1):
                        if '[PAGE' in lines[j]:
                            match = re.search(r'\[PAGE (\d+)\]', lines[j])
                            if match:
                                page_num = int(match.group(1))
                                break
                    
                    # 코드 수집
                    for j in range(i+1, min(i+50, len(lines))):
                        next_line = lines[j]
                        
                        # 다음 섹션이나 레이블이 나오면 중단
                        if any(re.search(p, next_line, re.IGNORECASE) 
                              for p in self.UNSAFE_CODE_PATTERNS + self.SAFE_CODE_PATTERNS):
                            break
                        
                        # 페이지 마커는 제외
                        if '[PAGE' in next_line:
                            continue
                        
                        # 빈 줄이 3개 이상 연속되면 중단
                        if not next_line.strip():
                            if len(code_lines) > 0 and not code_lines[-1].strip():
                                break
                        
                        code_lines.append(next_line)
                    
                    # 코드가 있으면 저장
                    code_text = '\n'.join(code_lines).strip()
                    if code_text and len(code_text) > 20:
                        code_blocks.append({
                            'code': code_text[:2000],  # 최대 2000자
                            'page': page_num,
                            'type': code_type,
                            'label': line.strip()
                        })
                    
                    break
        
        return code_blocks
    
    def _extract_recommendations(self, text: str) -> List[str]:
        """권장사항 추출"""
        recommendations = []
        keywords = ['권장', '해야', '사용하세요', '주의', '방지', '확인', '검증']
        
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if any(keyword in line for keyword in keywords):
                if len(line) > 10 and not line.startswith('[PAGE'):
                    recommendations.append(line)
                    if len(recommendations) >= 5:  # 최대 5개
                        break
        
        return recommendations
    
    def save_results(self, output_path: str = "data/processed/kisia_structured.json"):
        """파싱 결과 저장"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.parsed_data, f, ensure_ascii=False, indent=2)
        
        print(f"✅ 구조화된 데이터 저장: {output_path}")
    
    def print_summary(self):
        """파싱 요약 출력"""
        print("\n" + "="*60)
        print("📊 KISIA 가이드라인 구조화 파싱 결과")
        print("="*60)
        
        # 섹션별 통계
        section_stats = {}
        for vuln in self.parsed_data['vulnerabilities']:
            section = vuln['section']
            if section not in section_stats:
                section_stats[section] = {
                    'count': 0,
                    'unsafe_codes': 0,
                    'safe_codes': 0
                }
            
            section_stats[section]['count'] += 1
            section_stats[section]['unsafe_codes'] += len(vuln['unsafe_codes'])
            section_stats[section]['safe_codes'] += len(vuln['safe_codes'])
        
        print(f"\n총 {len(self.parsed_data['vulnerabilities'])}개 취약점 파싱")
        
        for section, stats in section_stats.items():
            print(f"\n{section}:")
            print(f"  - 취약점: {stats['count']}개")
            print(f"  - 안전하지 않은 코드: {stats['unsafe_codes']}개")
            print(f"  - 안전한 코드: {stats['safe_codes']}개")

if __name__ == "__main__":
    # PDF 경로
    pdf_path = "data/guidelines/Python_시큐어코딩_가이드(2023년_개정본).pdf"
    
    # 파서 생성 및 실행
    parser = KISIAStructuredParser(pdf_path)
    parsed_data = parser.parse()
    
    # 결과 저장
    parser.save_results()
    
    # 요약 출력
    parser.print_summary()