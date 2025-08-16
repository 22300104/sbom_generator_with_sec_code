# 새 파일: ui/github_examples.py
"""
GitHub 보안 테스트용 예제 프로젝트 모음
"""

GITHUB_VULNERABLE_PROJECTS = {
    "education": [
        {
            "name": "DVWA-Flask",
            "url": "https://github.com/anxolerd/dvwa-flask",
            "description": "Damn Vulnerable Web Application - Flask 버전",
            "language": "Python",
            "framework": "Flask",
            "vulnerabilities": [
                "SQL Injection",
                "XSS (Reflected/Stored)",
                "CSRF",
                "Command Injection",
                "File Upload",
                "Session Management"
            ],
            "difficulty": "초급-중급",
            "sbom_available": True
        },
        {
            "name": "PyGoat",
            "url": "https://github.com/adeyosemanputra/pygoat",
            "description": "OWASP PyGoat - 의도적으로 취약한 Django 애플리케이션",
            "language": "Python",
            "framework": "Django",
            "vulnerabilities": [
                "A1:2021 – Broken Access Control",
                "A2:2021 – Cryptographic Failures",
                "A3:2021 – Injection",
                "A4:2021 – Insecure Design",
                "A5:2021 – Security Misconfiguration"
            ],
            "difficulty": "중급",
            "sbom_available": True
        },
        {
            "name": "django.nV",
            "url": "https://github.com/nVisium/django.nV",
            "description": "의도적으로 취약한 Django 애플리케이션",
            "language": "Python",
            "framework": "Django",
            "vulnerabilities": [
                "Authentication Bypass",
                "SQL Injection",
                "XSS",
                "Insecure Direct Object Reference",
                "Missing Function Level Access Control"
            ],
            "difficulty": "중급-고급",
            "sbom_available": True
        }
    ],
    "demos": [
        {
            "name": "Vulnerable-Flask-App",
            "url": "https://github.com/we45/Vulnerable-Flask-App",
            "description": "보안 교육용 취약한 Flask 애플리케이션",
            "language": "Python",
            "framework": "Flask",
            "vulnerabilities": [
                "SQL Injection",
                "NoSQL Injection",
                "Server Side Template Injection",
                "Insecure Deserialization",
                "XXE"
            ],
            "difficulty": "중급",
            "sbom_available": True
        }
    ]
}