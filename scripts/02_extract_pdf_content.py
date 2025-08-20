import pdfplumber
import json
import re
from pathlib import Path
from typing import List, Dict, Tuple

class PDFStructureExtractor:
    def __init__(self, pdf_path: str):
        self.pdf_path = Path(pdf_path)
        # 사용자께서 확인해주신 정확한 페이지 오프셋 '6'을 적용합니다.
        self.PAGE_OFFSET = 6
        self.TOC = self._get_table_of_contents()
        self.vulnerability_map = self._create_vulnerability_map()

    def extract_all_vulnerabilities(self) -> Dict:
        print(f"📄 PDF 구조 기반 추출을 시작합니다 (페이지 오프셋: {self.PAGE_OFFSET})")
        structured_data = {"vulnerabilities": []}

        with pdfplumber.open(self.pdf_path) as pdf:
            for i, current_section in enumerate(self.TOC):
                start_page = current_section['page']
                next_page_in_toc = self.TOC[i + 1]['page'] if i + 1 < len(self.TOC) else (len(pdf.pages) - self.PAGE_OFFSET + 1)
                end_page = next_page_in_toc - 1

                print(f"  -> '{current_section['title']}' 추출 중 (목차 페이지: {start_page}-{end_page})")
                
                section_text = self._get_text_in_range(pdf, start_page, end_page)
                parsed_content = self._parse_section_content(section_text)

                structured_data["vulnerabilities"].append({
                    "section": current_section['section'],
                    "number": int(re.match(r'^\d+', current_section['title']).group(0)),
                    "korean_name": re.sub(r'^\d+\.\s*', '', current_section['title']),
                    "english_type": self.vulnerability_map.get(current_section['title'], "Unknown"),
                    "start_page": start_page,
                    "end_page": end_page,
                    "description": parsed_content['description'],
                    "unsafe_codes": parsed_content['unsafe_codes'],
                    "safe_codes": parsed_content['safe_codes'],
                    "recommendations": parsed_content['recommendations']
                })

        print(f"✅ 총 {len(structured_data['vulnerabilities'])}개 취약점 추출 완료.")
        return structured_data

    def _get_text_in_range(self, pdf, start_toc_page: int, end_toc_page: int) -> str:
        text = ""
        start_index = start_toc_page + self.PAGE_OFFSET - 1
        end_index = end_toc_page + self.PAGE_OFFSET - 1

        for i in range(start_index, end_index + 1):
            if i < len(pdf.pages):
                page = pdf.pages[i]
                page_text = page.extract_text(x_tolerance=2, layout=False)
                if page_text:
                    cleaned_text = re.sub(r'^\s*\d+\s*$', '', page_text, flags=re.MULTILINE)
                    cleaned_text = re.sub(r'\n(Python\s)?시큐어코딩\s가이드\s*.*', '', cleaned_text)
                    cleaned_text = re.sub(r'PART\s+제\d장[\s\S]+?$', '', cleaned_text)
                    text += cleaned_text + "\n"
        return text.strip()

    def _parse_section_content(self, text: str) -> Dict:
        content = {}
        landmarks = ["가. 개요", "나. 안전한 코딩기법", "다. 코드예제", "라. 참고자료"]
        
        content['description'] = self._extract_text_between(text, landmarks[0], landmarks[1])
        recommendations_text = self._extract_text_between(text, landmarks[1], landmarks[2])
        content['recommendations'] = [line.strip() for line in recommendations_text.split('\n') if line.strip()]
        
        code_section_text = self._extract_text_between(text, landmarks[2], landmarks[3])
        unsafe_codes, safe_codes = self._split_code_examples_robust(code_section_text)
        content['unsafe_codes'] = unsafe_codes
        content['safe_codes'] = safe_codes
        
        return content

    def _extract_text_between(self, full_text: str, start_keyword: str, end_keyword: str) -> str:
        start_pattern = re.escape(start_keyword)
        end_pattern = re.escape(end_keyword)
        match = re.search(f'{start_pattern}([\\s\\S]*?)(?={end_pattern}|$)', full_text, re.DOTALL)
        return match.group(1).strip() if match else ""

    def _split_code_examples_robust(self, code_section_text: str) -> Tuple[List[Dict], List[Dict]]:
        """
        '안전/불안전 코드 예시' 키워드로 텍스트를 분할하여 모든 개별 예제를 추출하는 최종 로직
        """
        unsafe_codes, safe_codes = [], []
        
        # '안전한 코드 예시' 키워드를 기준으로 텍스트를 크게 나눔
        # parts[0]는 안전하지 않은 코드 영역, parts[1:]는 안전한 코드 영역들
        safe_keyword = '안전한 코드 예시'
        parts = code_section_text.split(safe_keyword)
        
        # 1. 안전하지 않은 코드 영역 처리
        unsafe_area = parts[0]
        # '안전하지 않은 코드 예시' 키워드로 다시 분할하여 개별 예제를 모두 찾음
        unsafe_examples = unsafe_area.split('안전하지 않은 코드 예시')
        for example in unsafe_examples:
            content = example.strip()
            if content:
                unsafe_codes.append({'code': content, 'page': 0, 'label': '안전하지 않은 코드 예시'})

        # 2. 안전한 코드 영역 처리
        # '안전한 코드 예시' 뒤에 따라오는 모든 텍스트 블록을 개별 예제로 처리
        for area in parts[1:]:
            content = area.strip()
            if content:
                safe_codes.append({'code': content, 'page': 0, 'label': safe_keyword})
                
        return unsafe_codes, safe_codes
    
    # _create_vulnerability_map과 _get_table_of_contents는 변경하지 않습니다.
    def _create_vulnerability_map(self) -> Dict:
        return {
            "1. SQL 삽입": "SQL_Injection", "2. 코드 삽입": "Code_Injection",
            "3. 경로 조작 및 자원 삽입": "Path_Traversal", "4. 크로스사이트 스크립트(XSS)": "XSS",
            "5. 운영체제 명령어 삽입": "Command_Injection", "6. 위험한 형식 파일 업로드": "File_Upload",
            "7. 신뢰되지 않은 URL주소로 자동접속 연결": "Open_Redirect", "8. 부적절한 XML 외부 개체 참조": "XXE",
            "9. XML 삽입": "XML_Injection", "10. LDAP 삽입": "LDAP_Injection",
            "11. 크로스사이트 요청 위조(CSRF)": "CSRF", "12. 서버사이드 요청 위조": "SSRF",
            "13. HTTP 응답분할": "HTTP_Response_Splitting", "14. 정수형 오버플로우": "Integer_Overflow",
            "15. 보안기능 결정에 사용되는 부적절한 입력값": "Input_Validation", "16. 포맷 스트링 삽입": "Format_String",
            "1. 적절한 인증 없는 중요 기능 허용": "Missing_Authentication", "2. 부적절한 인가": "Improper_Authorization",
            "3. 중요한 자원에 대한 잘못된 권한 설정": "Incorrect_Permission", "4. 취약한 암호화 알고리즘 사용": "Weak_Cryptography",
            "5. 암호화되지 않은 중요정보": "Unencrypted_Data", "6. 하드코드된 중요정보": "Hardcoded_Secrets",
            "7. 충분하지 않은 키 길이 사용": "Insufficient_Key_Length", "8. 적절하지 않은 난수 값 사용": "Weak_Random",
            "9. 취약한 패스워드 허용": "Weak_Password", "10. 부적절한 전자서명 확인": "Improper_Signature_Verification",
            "11. 부적절한 인증서 유효성 검증": "Improper_Certificate_Validation", "12. 사용자 하드디스크에 저장되는 쿠키를 통한 정보 노출": "Cookie_Exposure",
            "13. 주석문 안에 포함된 시스템 주요정보": "Information_in_Comments", "14. 솔트 없이 일방향 해시 함수 사용": "Missing_Salt",
            "15. 무결성 검사없는 코드 다운로드": "Unverified_Download", "16. 반복된 인증시도 제한 기능 부재": "Missing_Brute_Force_Protection",
            "1. 경쟁조건: 검사시점과 사용시점(TOCTOU)": "TOCTOU", "2. 종료되지 않는 반복문 또는 재귀 함수": "Infinite_Loop",
            "1. 오류 메시지 정보노출": "Error_Message_Exposure", "2. 오류상황 대응 부재": "Missing_Error_Handling",
            "3. 부적절한 예외 처리": "Improper_Exception_Handling", "1. Null Pointer 역참조": "Null_Pointer_Dereference",
            "2. 부적절한 자원 해제": "Improper_Resource_Release", "3. 신뢰할 수 없는 데이터의 역직렬화": "Unsafe_Deserialization",
            "1. 잘못된 세션에 의한 데이터 정보 노출": "Session_Data_Exposure", "2. 제거되지 않고 남은 디버그 코드": "Debug_Code",
            "3. Public 메소드로부터 반환된 Private 배열": "Private_Array_Return", "4. Private 배열에 Public 데이터 할당": "Public_Data_Assignment",
            "1. DNS lookup에 의존한 보안결정": "DNS_Based_Security", "2. 취약한 API 사용": "Vulnerable_API"
        }

    def _get_table_of_contents(self) -> List[Dict]:
        return [
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '1. SQL 삽입', 'page': 8},
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '2. 코드 삽입', 'page': 14},
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '3. 경로 조작 및 자원 삽입', 'page': 18},
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '4. 크로스사이트 스크립트(XSS)', 'page': 22},
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '5. 운영체제 명령어 삽입', 'page': 29},
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '6. 위험한 형식 파일 업로드', 'page': 33},
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '7. 신뢰되지 않은 URL주소로 자동접속 연결', 'page': 36},
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '8. 부적절한 XML 외부 개체 참조', 'page': 39},
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '9. XML 삽입', 'page': 42},
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '10. LDAP 삽입', 'page': 44},
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '11. 크로스사이트 요청 위조(CSRF)', 'page': 48},
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '12. 서버사이드 요청 위조', 'page': 55},
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '13. HTTP 응답분할', 'page': 58},
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '14. 정수형 오버플로우', 'page': 61},
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '15. 보안기능 결정에 사용되는 부적절한 입력값', 'page': 64},
            {'section': '제1절 입력데이터 검증 및 표현', 'title': '16. 포맷 스트링 삽입', 'page': 67},
            {'section': '제2절 보안기능', 'title': '1. 적절한 인증 없는 중요 기능 허용', 'page': 69},
            {'section': '제2절 보안기능', 'title': '2. 부적절한 인가', 'page': 72},
            {'section': '제2절 보안기능', 'title': '3. 중요한 자원에 대한 잘못된 권한 설정', 'page': 75},
            {'section': '제2절 보안기능', 'title': '4. 취약한 암호화 알고리즘 사용', 'page': 77},
            {'section': '제2절 보안기능', 'title': '5. 암호화되지 않은 중요정보', 'page': 81},
            {'section': '제2절 보안기능', 'title': '6. 하드코드된 중요정보', 'page': 85},
            {'section': '제2절 보안기능', 'title': '7. 충분하지 않은 키 길이 사용', 'page': 88},
            {'section': '제2절 보안기능', 'title': '8. 적절하지 않은 난수 값 사용', 'page': 91},
            {'section': '제2절 보안기능', 'title': '9. 취약한 패스워드 허용', 'page': 94},
            {'section': '제2절 보안기능', 'title': '10. 부적절한 전자서명 확인', 'page': 98},
            {'section': '제2절 보안기능', 'title': '11. 부적절한 인증서 유효성 검증', 'page': 102},
            {'section': '제2절 보안기능', 'title': '12. 사용자 하드디스크에 저장되는 쿠키를 통한 정보 노출', 'page': 106},
            {'section': '제2절 보안기능', 'title': '13. 주석문 안에 포함된 시스템 주요정보', 'page': 109},
            {'section': '제2절 보안기능', 'title': '14. 솔트 없이 일방향 해시 함수 사용', 'page': 111},
            {'section': '제2절 보안기능', 'title': '15. 무결성 검사없는 코드 다운로드', 'page': 113},
            {'section': '제2절 보안기능', 'title': '16. 반복된 인증시도 제한 기능 부재', 'page': 116},
            {'section': '제3절 시간 및 상태', 'title': '1. 경쟁조건: 검사시점과 사용시점(TOCTOU)', 'page': 119},
            {'section': '제3절 시간 및 상태', 'title': '2. 종료되지 않는 반복문 또는 재귀 함수', 'page': 122},
            {'section': '제4절 에러처리', 'title': '1. 오류 메시지 정보노출', 'page': 125},
            {'section': '제4절 에러처리', 'title': '2. 오류상황 대응 부재', 'page': 129},
            {'section': '제4절 에러처리', 'title': '3. 부적절한 예외 처리', 'page': 132},
            {'section': '제5절 코드오류', 'title': '1. Null Pointer 역참조', 'page': 134},
            {'section': '제5절 코드오류', 'title': '2. 부적절한 자원 해제', 'page': 137},
            {'section': '제5절 코드오류', 'title': '3. 신뢰할 수 없는 데이터의 역직렬화', 'page': 140},
            {'section': '제6절 캡슐화', 'title': '1. 잘못된 세션에 의한 데이터 정보 노출', 'page': 143},
            {'section': '제6절 캡슐화', 'title': '2. 제거되지 않고 남은 디버그 코드', 'page': 146},
            {'section': '제6절 캡슐화', 'title': '3. Public 메소드로부터 반환된 Private 배열', 'page': 150},
            {'section': '제6절 캡슐화', 'title': '4. Private 배열에 Public 데이터 할당', 'page': 152},
            {'section': '제7절 API 오용', 'title': '1. DNS lookup에 의존한 보안결정', 'page': 154},
            {'section': '제7절 API 오용', 'title': '2. 취약한 API 사용', 'page': 156}
        ]

def save_json(data: Dict, path: str):
    """데이터를 JSON 파일로 저장합니다."""
    output_file = Path(path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"✅ 추출 결과 저장 완료: {output_file}")

if __name__ == "__main__":
    pdf_file_path = "data/guidelines/Python_시큐어코딩_가이드(2023년_개정본).pdf"
    
    extractor = PDFStructureExtractor(pdf_file_path)
    final_data = extractor.extract_all_vulnerabilities()
    
    # 올바른 파일명으로 저장
    save_json(final_data, "data/processed/kisia_structured.json")