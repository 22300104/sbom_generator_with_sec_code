import json
from core.improved_llm_analyzer import ImprovedSecurityAnalyzer

# 테스트 코드
test_code = """
import os
def unsafe_function(user_input):
    os.system(f"echo {user_input}")
"""

# 분석 실행
analyzer = ImprovedSecurityAnalyzer(use_claude=False)  # GPT 사용
result = analyzer.analyze_security(test_code)

# 결과 출력
print(json.dumps(result, indent=2, ensure_ascii=False))