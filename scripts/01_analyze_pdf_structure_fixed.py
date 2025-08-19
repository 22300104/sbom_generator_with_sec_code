# scripts/01_analyze_pdf_structure_fixed.py
"""
KISIA PDF 정밀 분석 - 정확한 레이블 패턴 사용
'안전하지 않은 코드 예시' / '안전한 코드 예시' 패턴 매칭
"""
import pdfplumber
import json
import re
from pathlib import Path
from collections import Counter, defaultdict
import time

class PDFAnalyzerFixed:
    def __init__(self, pdf_path):
        self.pdf_path = Path(pdf_path)
        
        # 정확한 레이블 패턴 정의
        self.UNSAFE_CODE_LABELS = [
            '안전하지 않은 코드 예시',
            '안전하지 않은 코드',
            '취약한 코드 예시',
            '잘못된 코드 예시',
            '문제가 있는 코드',
            '나쁜 예',
            'Bad Example',
            '취약점이 있는 코드'
        ]
        
        self.SAFE_CODE_LABELS = [
            '안전한 코드 예시',
            '안전한 코드',
            '개선된 코드 예시',
            '올바른 코드 예시',
            '권장 코드',
            '좋은 예',
            'Good Example',
            '수정된 코드'
        ]
        
        self.analysis = {
            "file_name": self.pdf_path.name,
            "total_pages": 0,
            "code_blocks": {
                "unsafe": [],
                "safe": [],
                "unknown": []
            },
            "code_pairs": [],  # 안전/불안전 코드 쌍
            "sections": [],
            "vulnerability_sections": defaultdict(list),
            "statistics": {},
            "debug_info": []  # 디버깅용
        }
        
    def analyze(self):
        """전체 PDF 분석"""
        if not self.pdf_path.exists():
            print(f"❌ PDF 파일을 찾을 수 없습니다: {self.pdf_path}")
            return None
            
        print(f"📄 PDF 정밀 분석 시작 (수정된 패턴): {self.pdf_path.name}")
        start_time = time.time()
        
        with pdfplumber.open(self.pdf_path) as pdf:
            self.analysis["total_pages"] = len(pdf.pages)
            print(f"📊 총 페이지: {self.analysis['total_pages']}")
            
            # 전체 페이지 분석
            for page_num, page in enumerate(pdf.pages, 1):
                if page_num % 20 == 0:
                    print(f"  분석 중... {page_num}/{self.analysis['total_pages']} 페이지")
                
                try:
                    self._analyze_page(page, page_num)
                except Exception as e:
                    self.analysis["debug_info"].append({
                        "page": page_num,
                        "error": str(e)
                    })
        
        # 코드 쌍 매칭
        self._match_code_pairs()
        
        # 통계 생성
        self._generate_statistics()
        
        elapsed = time.time() - start_time
        print(f"✅ 분석 완료 ({elapsed:.1f}초)")
        
        return self.analysis
    
    def _analyze_page(self, page, page_num):
        """페이지별 분석"""
        text = page.extract_text()
        if not text:
            return
        
        lines = text.split('\n')
        
        # 코드 블록 추출 (레이블 기반)
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # 안전하지 않은 코드 레이블 확인
            unsafe_found = False
            for label in self.UNSAFE_CODE_LABELS:
                if label in line:
                    unsafe_found = True
                    code_block = self._extract_code_after_label(lines, i+1, page_num)
                    if code_block:
                        code_block['label'] = label
                        code_block['type'] = 'unsafe'
                        self.analysis["code_blocks"]["unsafe"].append(code_block)
                        
                        # 디버깅 정보
                        self.analysis["debug_info"].append({
                            "page": page_num,
                            "line": i,
                            "found": f"UNSAFE: {label}"
                        })
                    break
            
            # 안전한 코드 레이블 확인
            if not unsafe_found:
                for label in self.SAFE_CODE_LABELS:
                    if label in line:
                        code_block = self._extract_code_after_label(lines, i+1, page_num)
                        if code_block:
                            code_block['label'] = label
                            code_block['type'] = 'safe'
                            self.analysis["code_blocks"]["safe"].append(code_block)
                            
                            # 디버깅 정보
                            self.analysis["debug_info"].append({
                                "page": page_num,
                                "line": i,
                                "found": f"SAFE: {label}"
                            })
                        break
            
            i += 1
        
        # 레이블 없는 코드 블록도 찾기 (Python 패턴 기반)
        self._extract_unlabeled_code(text, page_num)
        
        # 섹션 추출
        sections = self._extract_sections(text, page_num)
        self.analysis["sections"].extend(sections)
        
        # 취약점 분류
        self._classify_vulnerability_content(text, page_num)
    
    def _extract_code_after_label(self, lines, start_idx, page_num):
        """레이블 다음에 오는 코드 블록 추출"""
        if start_idx >= len(lines):
            return None
        
        code_lines = []
        blank_line_count = 0
        max_blank_lines = 2  # 빈 줄 2개까지 허용
        
        for i in range(start_idx, min(start_idx + 50, len(lines))):  # 최대 50줄까지
            line = lines[i]
            
            # 다음 레이블이 나오면 중단
            if any(label in line for label in self.UNSAFE_CODE_LABELS + self.SAFE_CODE_LABELS):
                break
            
            # 섹션 헤더가 나오면 중단
            if re.match(r'^(\d+\.|\[|제\d+[장절])', line.strip()):
                break
            
            # 빈 줄 처리
            if not line.strip():
                blank_line_count += 1
                if blank_line_count > max_blank_lines:
                    break
                code_lines.append(line)
            else:
                blank_line_count = 0
                code_lines.append(line)
        
        # 코드가 있는지 확인
        code_text = '\n'.join(code_lines).strip()
        if len(code_text) < 10:  # 너무 짧으면 무시
            return None
        
        # Python 코드 특징이 있는지 확인
        has_code_features = any([
            'def ' in code_text,
            'class ' in code_text,
            'import ' in code_text,
            '=' in code_text,
            '(' in code_text and ')' in code_text,
            'if ' in code_text,
            'for ' in code_text,
            'while ' in code_text,
            'return ' in code_text,
            'print(' in code_text,
        ])
        
        if not has_code_features and len(code_lines) < 3:
            return None
        
        return {
            'page': page_num,
            'start_line': start_idx,
            'code': code_text[:1000],  # 처음 1000자만
            'lines': len(code_lines),
            'vulnerability_type': self._detect_vulnerability_type(code_text)
        }
    
    def _extract_unlabeled_code(self, text, page_num):
        """레이블이 없는 코드 블록 찾기"""
        # Python 코드 패턴
        code_patterns = [
            r'^\s*(def |class )\w+',
            r'^\s*import ',
            r'^\s*from .+ import ',
            r'^\s*if __name__',
            r'^\s*@\w+',  # 데코레이터
        ]
        
        lines = text.split('\n')
        i = 0
        
        while i < len(lines):
            for pattern in code_patterns:
                if re.match(pattern, lines[i]):
                    # 코드 블록 시작
                    code_lines = []
                    j = i
                    
                    # 들여쓰기나 연속된 코드 라인 찾기
                    while j < len(lines) and j < i + 30:  # 최대 30줄
                        line = lines[j]
                        
                        # 코드 블록 종료 조건
                        if j > i and not line.strip() and j + 1 < len(lines) and not lines[j+1].startswith((' ', '\t')):
                            break
                        
                        code_lines.append(line)
                        j += 1
                    
                    if len(code_lines) > 2:  # 최소 3줄
                        code_text = '\n'.join(code_lines)
                        
                        # 이미 찾은 레이블된 코드와 중복 체크
                        is_duplicate = False
                        for existing in self.analysis["code_blocks"]["safe"] + self.analysis["code_blocks"]["unsafe"]:
                            if existing['page'] == page_num and abs(existing['start_line'] - i) < 5:
                                is_duplicate = True
                                break
                        
                        if not is_duplicate:
                            self.analysis["code_blocks"]["unknown"].append({
                                'page': page_num,
                                'start_line': i,
                                'code': code_text[:500],
                                'lines': len(code_lines),
                                'type': 'unknown',
                                'vulnerability_type': self._detect_vulnerability_type(code_text)
                            })
                    
                    i = j
                    break
            else:
                i += 1
    
    def _detect_vulnerability_type(self, code):
        """코드에서 취약점 타입 감지"""
        patterns = {
            'SQL_Injection': ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'execute(', 'cursor.'],
            'Command_Injection': ['os.system', 'subprocess', 'shell=True', 'os.popen'],
            'Path_Traversal': ['../', '..\\', 'os.path.join', 'open('],
            'XSS': ['innerHTML', '<script>', 'document.write', 'eval('],
            'Deserialization': ['pickle.loads', 'yaml.load', 'eval(', 'exec('],
            'Weak_Crypto': ['md5', 'sha1', 'DES', 'ECB'],
            'Hardcoded_Secret': ['password =', 'api_key =', 'secret =', 'token ='],
        }
        
        detected = []
        for vuln_type, keywords in patterns.items():
            for keyword in keywords:
                if keyword.lower() in code.lower():
                    detected.append(vuln_type)
                    break
        
        return detected if detected else ['General']
    
    def _match_code_pairs(self):
        """안전/불안전 코드 쌍 매칭"""
        unsafe_codes = self.analysis["code_blocks"]["unsafe"]
        safe_codes = self.analysis["code_blocks"]["safe"]
        
        # 같은 페이지 또는 인접 페이지의 코드들을 쌍으로 매칭
        for unsafe in unsafe_codes:
            best_match = None
            min_distance = float('inf')
            
            for safe in safe_codes:
                # 페이지 거리 계산
                page_distance = abs(safe['page'] - unsafe['page'])
                
                # 3페이지 이내의 코드만 쌍으로 고려
                if page_distance <= 3:
                    # 취약점 타입이 같은지 확인
                    if set(unsafe.get('vulnerability_type', [])) & set(safe.get('vulnerability_type', [])):
                        if page_distance < min_distance:
                            min_distance = page_distance
                            best_match = safe
            
            if best_match:
                self.analysis["code_pairs"].append({
                    'unsafe': unsafe,
                    'safe': best_match,
                    'page_distance': min_distance,
                    'vulnerability_type': list(set(unsafe.get('vulnerability_type', [])) & 
                                              set(best_match.get('vulnerability_type', [])))
                })
    
    def _extract_sections(self, text, page_num):
        """섹션 추출"""
        sections = []
        
        section_patterns = [
            (r'^(\d+\.[\d\.]*)\s+(.+)$', 'numbered'),
            (r'^(제\d+[장절])\s+(.+)$', 'korean'),
            (r'^([가-하]\.)\s+(.+)$', 'korean_sub'),
            (r'^\[(.+)\]$', 'bracket'),  # [제목] 형식
        ]
        
        for line in text.split('\n'):
            for pattern, stype in section_patterns:
                match = re.match(pattern, line.strip())
                if match:
                    sections.append({
                        'page': page_num,
                        'type': stype,
                        'title': line.strip()
                    })
                    break
        
        return sections
    
    def _classify_vulnerability_content(self, text, page_num):
        """취약점 관련 내용 분류"""
        vuln_keywords = {
            'SQL_Injection': ['SQL 인젝션', 'SQL Injection', 'SQL주입'],
            'XSS': ['XSS', '크로스 사이트 스크립팅', 'Cross-Site Scripting'],
            'CSRF': ['CSRF', '크로스 사이트 요청 위조'],
            'Command_Injection': ['명령 삽입', '명령어 삽입', 'Command Injection'],
            'Path_Traversal': ['경로 조작', 'Path Traversal', '디렉토리 탐색'],
            'Authentication': ['인증', 'Authentication', '로그인'],
            'Encryption': ['암호화', 'Encryption', '해시', 'Hash'],
            'Deserialization': ['역직렬화', 'Deserialization', 'pickle', 'yaml'],
            'File_Upload': ['파일 업로드', 'File Upload'],
            'Session': ['세션', 'Session', '쿠키', 'Cookie'],
        }
        
        for vuln_type, keywords in vuln_keywords.items():
            for keyword in keywords:
                if keyword.lower() in text.lower():
                    self.analysis["vulnerability_sections"][vuln_type].append({
                        'page': page_num,
                        'keyword': keyword
                    })
    
    def _generate_statistics(self):
        """통계 생성"""
        unsafe_count = len(self.analysis["code_blocks"]["unsafe"])
        safe_count = len(self.analysis["code_blocks"]["safe"])
        unknown_count = len(self.analysis["code_blocks"]["unknown"])
        
        self.analysis['statistics'] = {
            'code': {
                'total_code_blocks': unsafe_count + safe_count + unknown_count,
                'unsafe_code_blocks': unsafe_count,
                'safe_code_blocks': safe_count,
                'unknown_code_blocks': unknown_count,
                'code_pairs': len(self.analysis["code_pairs"]),
                'pages_with_unsafe': len(set(b['page'] for b in self.analysis["code_blocks"]["unsafe"])),
                'pages_with_safe': len(set(b['page'] for b in self.analysis["code_blocks"]["safe"])),
            },
            'vulnerabilities': {
                'coverage': {
                    vuln: len(pages) 
                    for vuln, pages in self.analysis['vulnerability_sections'].items()
                }
            },
            'sections': {
                'total': len(self.analysis['sections'])
            }
        }
    
    def save_results(self, output_path="data/processed/metadata/pdf_analysis_fixed.json"):
        """분석 결과 저장"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # defaultdict를 dict로 변환
        save_data = self.analysis.copy()
        save_data['vulnerability_sections'] = dict(save_data['vulnerability_sections'])
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(save_data, f, ensure_ascii=False, indent=2)
        
        print(f"✅ 수정된 분석 결과 저장: {output_path}")
    
    def print_summary(self):
        """분석 요약 출력"""
        print("\n" + "="*60)
        print("📊 PDF 정밀 분석 결과 (수정된 패턴)")
        print("="*60)
        
        stats = self.analysis['statistics']['code']
        
        print(f"\n📄 파일: {self.analysis['file_name']}")
        print(f"📑 총 페이지: {self.analysis['total_pages']}")
        
        print(f"\n💻 코드 블록 분석:")
        print(f"  • 총 코드 블록: {stats['total_code_blocks']}개")
        print(f"  • 안전하지 않은 코드: {stats['unsafe_code_blocks']}개")
        print(f"  • 안전한 코드: {stats['safe_code_blocks']}개")
        print(f"  • 레이블 없는 코드: {stats['unknown_code_blocks']}개")
        print(f"  • 매칭된 코드 쌍: {stats['code_pairs']}개")
        
        print(f"\n📍 코드 분포:")
        print(f"  • 안전하지 않은 코드가 있는 페이지: {stats['pages_with_unsafe']}페이지")
        print(f"  • 안전한 코드가 있는 페이지: {stats['pages_with_safe']}페이지")
        
        # 레이블 통계
        unsafe_labels = Counter(b['label'] for b in self.analysis["code_blocks"]["unsafe"] if 'label' in b)
        safe_labels = Counter(b['label'] for b in self.analysis["code_blocks"]["safe"] if 'label' in b)
        
        if unsafe_labels:
            print(f"\n🏷️ 발견된 안전하지 않은 코드 레이블:")
            for label, count in unsafe_labels.most_common():
                print(f"  • '{label}': {count}회")
        
        if safe_labels:
            print(f"\n🏷️ 발견된 안전한 코드 레이블:")
            for label, count in safe_labels.most_common():
                print(f"  • '{label}': {count}회")
        
        print(f"\n🎯 취약점 타입별 언급:")
        vuln_coverage = self.analysis['statistics']['vulnerabilities']['coverage']
        for vuln_type, count in sorted(vuln_coverage.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  • {vuln_type}: {count}회")
        
        # 디버그 정보 일부 출력
        if self.analysis["debug_info"][:5]:
            print(f"\n🔍 디버그 정보 (처음 5개):")
            for info in self.analysis["debug_info"][:5]:
                if 'found' in info:
                    print(f"  • 페이지 {info['page']}: {info['found']}")

if __name__ == "__main__":
    # PDF 경로
    pdf_path = "data/guidelines/Python_시큐어코딩_가이드(2023년_개정본).pdf"
    
    # 분석기 생성 및 실행
    analyzer = PDFAnalyzerFixed(pdf_path)
    analysis = analyzer.analyze()
    
    if analysis:
        # 결과 저장
        analyzer.save_results()
        
        # 요약 출력
        analyzer.print_summary()
    else:
        print("❌ PDF 분석 실패")