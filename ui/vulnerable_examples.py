# ui/vulnerable_examples.py
"""
보안 취약점이 있는 예제 프로젝트들
테스트 및 데모용
"""

def get_vulnerable_web_app():
    """취약한 웹 애플리케이션 예제"""
    return {
        'name': 'Vulnerable Web App',
        'files': [
            {
                'path': 'app.py',
                'content': """from flask import Flask, request, render_template_string, session, redirect, url_for
import sqlite3
import hashlib
import os
import pickle

app = Flask(__name__)
app.secret_key = "hardcoded-secret-key-123"  # 하드코딩된 시크릿

# 데이터베이스 설정
DB_PATH = "users.db"
ADMIN_PASSWORD = "admin123"  # 하드코딩된 관리자 비밀번호

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # SQL 인젝션 취약점
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cursor.execute(query)  # 위험: 직접 문자열 삽입
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
    
    return '<form method="post">Username: <input name="username"><br>Password: <input type="password" name="password"><br><input type="submit"></form>'

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    
    # XSS 취약점 - 사용자 입력을 직접 렌더링
    template = f'''
    <h1>검색 결과</h1>
    <p>검색어: {keyword}</p>
    <div id="results"></div>
    <script>
        document.getElementById('results').innerHTML = '{keyword}';
    </script>
    '''
    return render_template_string(template)  # 위험: XSS 가능

@app.route('/user/<user_id>')
def get_user(user_id):
    # SQL 인젝션 취약점 (또 다른 형태)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id  # 위험: 문자열 연결
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    return str(user) if user else "User not found"

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    
    # 경로 조작 취약점
    filename = file.filename
    filepath = f"uploads/{filename}"  # 위험: 경로 검증 없음
    
    # 파일 타입 검증 없음
    file.save(filepath)  # 위험: 악성 파일 업로드 가능
    
    return f"File uploaded to {filepath}"

@app.route('/admin')
def admin():
    # 인증 확인 없음 - 접근 제어 취약점
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    all_users = cursor.fetchall()
    conn.close()
    
    return str(all_users)  # 위험: 모든 사용자 정보 노출

@app.route('/execute')
def execute():
    # 명령어 삽입 취약점
    cmd = request.args.get('cmd', 'ls')
    result = os.system(cmd)  # 위험: OS 명령어 직접 실행
    return f"Command executed: {cmd}, Result: {result}"

@app.route('/deserialize', methods=['POST'])
def deserialize():
    # 안전하지 않은 역직렬화
    data = request.get_data()
    obj = pickle.loads(data)  # 위험: 신뢰할 수 없는 데이터 역직렬화
    return str(obj)

def hash_password(password):
    # 약한 해시 알고리즘
    return hashlib.md5(password.encode()).hexdigest()  # 위험: MD5는 안전하지 않음

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # 약한 패스워드 해싱
    password_hash = hash_password(password)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SQL 인젝션 취약점
    query = f"INSERT INTO users (username, password, role) VALUES ('{username}', '{password_hash}', 'user')"
    cursor.execute(query)
    conn.commit()
    conn.close()
    
    return "User registered"

if __name__ == '__main__':
    init_db()
    # 디버그 모드로 프로덕션 실행 - 보안 취약점
    app.run(debug=True, host='0.0.0.0')  # 위험: 디버그 모드 + 모든 인터페이스 노출
""",
                'size': 4500,
                'lines': 140
            },
            {
                'path': 'config.py',
                'content': """# 설정 파일 - 여러 보안 문제 포함

# 하드코딩된 민감한 정보
DATABASE_URL = "postgresql://admin:password123@localhost/mydb"
SECRET_KEY = "my-super-secret-key-123"
API_KEY = "sk-1234567890abcdef"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# 약한 설정
SESSION_COOKIE_HTTPONLY = False  # XSS에 취약
SESSION_COOKIE_SECURE = False    # HTTPS 미사용
PASSWORD_MIN_LENGTH = 4          # 너무 짧은 패스워드
LOGIN_ATTEMPTS_LIMIT = 999999    # 브루트포스 공격 가능

# 디버그 설정
DEBUG = True
TESTING = True
PROPAGATE_EXCEPTIONS = True

# CORS 설정 - 너무 관대함
CORS_ORIGINS = "*"
CORS_ALLOW_HEADERS = "*"
CORS_ALLOW_METHODS = "*"
""",
                'size': 800,
                'lines': 25
            },
            {
                'path': 'models.py',
                'content': """import sqlite3
import hashlib

class User:
    def __init__(self, username, password):
        self.username = username
        # 평문 패스워드 저장 - 보안 취약점
        self.password = password  # 위험: 평문 저장
    
    def authenticate(self, username, password):
        # SQL 인젝션 취약점
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE username='%s' AND password='%s'" % (username, password)
        cursor.execute(query)  # 위험: % formatting으로 SQL 구성
        return cursor.fetchone()
    
    def get_user_by_id(self, user_id):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        # SQL 인젝션 취약점
        cursor.execute(f"SELECT * FROM users WHERE id={user_id}")  # 위험: f-string 사용
        return cursor.fetchone()
    
    def update_password(self, new_password):
        # 약한 해시 사용
        hashed = hashlib.sha1(new_password.encode()).hexdigest()  # 위험: SHA1은 안전하지 않음
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        # SQL 인젝션 취약점
        query = f"UPDATE users SET password='{hashed}' WHERE username='{self.username}'"
        cursor.execute(query)
        conn.commit()

class Session:
    sessions = {}  # 메모리에 세션 저장 - 취약점
    
    @staticmethod
    def create_session(user_id):
        # 예측 가능한 세션 ID - 보안 취약점
        import time
        session_id = hashlib.md5(f"{user_id}{time.time()}".encode()).hexdigest()  # 위험: 예측 가능
        Session.sessions[session_id] = user_id
        return session_id
    
    @staticmethod
    def validate_session(session_id):
        # 세션 만료 없음 - 보안 취약점
        return Session.sessions.get(session_id)
""",
                'size': 1800,
                'lines': 50
            },
            {
                'path': 'utils.py',
                'content': """import os
import subprocess
import yaml
import pickle
import random

def execute_command(cmd):
    # 명령어 실행 - 명령어 삽입 취약점
    # 위험: shell=True로 사용자 입력 실행
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout.decode()

def process_yaml(yaml_string):
    # YAML 처리 - 안전하지 않은 로드
    # 위험: yaml.load()는 임의 Python 객체 실행 가능
    data = yaml.load(yaml_string)  # Loader 미지정
    return data

def save_object(obj, filename):
    # 객체 저장 - 안전하지 않은 직렬화
    with open(filename, 'wb') as f:
        pickle.dump(obj, f)  # pickle은 신뢰할 수 없는 데이터에 위험

def load_object(filename):
    # 객체 로드 - 안전하지 않은 역직렬화
    with open(filename, 'rb') as f:
        return pickle.load(f)  # 위험: 악성 객체 실행 가능

def generate_token():
    # 토큰 생성 - 약한 랜덤
    # 위험: random은 암호학적으로 안전하지 않음
    token = random.randint(100000, 999999)
    return str(token)

def read_file(filepath):
    # 파일 읽기 - 경로 조작 취약점
    # 위험: 경로 검증 없음
    with open(f"data/{filepath}", 'r') as f:
        return f.read()

def write_log(message):
    # 로그 작성 - 로그 인젝션 취약점
    # 위험: 사용자 입력을 직접 로그에 기록
    with open('app.log', 'a') as f:
        f.write(f"{message}\\n")  # 로그 인젝션 가능

def check_admin(user_role):
    # 관리자 확인 - 취약한 권한 확인
    # 위험: 대소문자 구분 없이 비교
    return user_role.lower() == "admin"  # 'Admin', 'ADMIN' 등도 통과

def encrypt_data(data):
    # 데이터 암호화 - 취약한 암호화
    # 위험: XOR은 암호화가 아님
    key = 42
    encrypted = ""
    for char in data:
        encrypted += chr(ord(char) ^ key)
    return encrypted

def validate_email(email):
    # 이메일 검증 - 불충분한 검증
    # 위험: 너무 단순한 검증
    return "@" in email  # 불충분한 검증

class TempFile:
    # 임시 파일 처리 - 보안 취약점
    def __init__(self, content):
        # 위험: 예측 가능한 파일명
        self.filename = f"/tmp/temp_{random.randint(1, 100)}.txt"
        with open(self.filename, 'w') as f:
            f.write(content)
    
    def __del__(self):
        # 위험: 파일 삭제 실패 가능
        try:
            os.remove(self.filename)
        except:
            pass  # 에러 무시
""",
                'size': 2500,
                'lines': 85
            },
            {
                'path': 'requirements.txt',
                'content': """Flask==2.0.1
pyyaml==5.3.1
requests==2.25.1
jwt==1.2.0
""",
                'size': 100,
                'lines': 4
            }
        ]
    }


def get_vulnerable_django_app():
    """취약한 Django 애플리케이션 예제"""
    return {
        'name': 'Vulnerable Django App',
        'files': [
            {
                'path': 'settings.py',
                'content': """# Django 설정 - 여러 보안 문제

# 하드코딩된 시크릿 키
SECRET_KEY = 'django-insecure-very-secret-key-12345'

# 디버그 모드 활성화
DEBUG = True
ALLOWED_HOSTS = ['*']  # 모든 호스트 허용

# 데이터베이스 설정 - 패스워드 노출
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'mydb',
        'USER': 'admin',
        'PASSWORD': 'admin123',  # 하드코딩된 패스워드
        'HOST': 'localhost',
    }
}

# 보안 설정 비활성화
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_BROWSER_XSS_FILTER = False
SECURE_CONTENT_TYPE_NOSNIFF = False
X_FRAME_OPTIONS = 'ALLOWALL'  # Clickjacking 취약

# 약한 패스워드 검증
AUTH_PASSWORD_VALIDATORS = []  # 패스워드 검증 없음

# CORS 설정 - 너무 관대함
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

# 미들웨어 - 보안 미들웨어 제외
MIDDLEWARE = [
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware',  # CSRF 보호 비활성화
    'django.contrib.sessions.middleware.SessionMiddleware',
]
""",
                'size': 1200,
                'lines': 40
            },
            {
                'path': 'views.py',
                'content': """from django.shortcuts import render
from django.http import HttpResponse
from django.db import connection
from django.contrib.auth import authenticate
import os
import pickle

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # SQL 인젝션 취약점
        with connection.cursor() as cursor:
            query = f"SELECT * FROM auth_user WHERE username='{username}' AND password='{password}'"
            cursor.execute(query)  # 위험: Raw SQL with string formatting
            user = cursor.fetchone()
        
        if user:
            request.session['user_id'] = user[0]
            return HttpResponse("Logged in")
    
    return render(request, 'login.html')

def search_view(request):
    search_term = request.GET.get('q', '')
    
    # XSS 취약점 - 템플릿에서 |safe 필터 사용
    context = {
        'search_term': search_term,
        'results': f"<script>alert('{search_term}')</script>"  # 위험: XSS
    }
    return render(request, 'search.html', context)

def user_profile(request, user_id):
    # SQL 인젝션 취약점
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM auth_user WHERE id = {user_id}")  # 위험
        user = cursor.fetchone()
    
    return HttpResponse(str(user))

def upload_file(request):
    if request.method == 'POST':
        uploaded_file = request.FILES['file']
        
        # 경로 조작 취약점
        filename = uploaded_file.name
        filepath = os.path.join('/uploads/', filename)  # 위험: 경로 검증 없음
        
        with open(filepath, 'wb') as f:
            for chunk in uploaded_file.chunks():
                f.write(chunk)
        
        # 안전하지 않은 역직렬화
        if filename.endswith('.pkl'):
            with open(filepath, 'rb') as f:
                data = pickle.load(f)  # 위험: 신뢰할 수 없는 데이터
        
        return HttpResponse(f"File uploaded: {filename}")

def admin_panel(request):
    # 권한 확인 없음 - 접근 제어 취약점
    users = []
    with connection.cursor() as cursor:
        cursor.execute("SELECT username, password FROM auth_user")  # 패스워드 노출
        users = cursor.fetchall()
    
    return HttpResponse(str(users))

def execute_command(request):
    cmd = request.GET.get('cmd', 'ls')
    
    # 명령어 삽입 취약점
    result = os.popen(cmd).read()  # 위험: OS 명령어 실행
    
    return HttpResponse(f"Result: {result}")

def set_cookie(request):
    response = HttpResponse("Cookie set")
    
    # 안전하지 않은 쿠키 설정
    response.set_cookie('session_id', 'secret_value', 
                       secure=False,  # HTTPS 미사용
                       httponly=False,  # JavaScript 접근 가능
                       samesite=None)  # CSRF 취약
    
    return response
""",
                'size': 2800,
                'lines': 85
            },
            {
                'path': 'models.py',
                'content': """from django.db import models
from django.contrib.auth.models import User
import hashlib

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    # 민감한 정보 평문 저장
    ssn = models.CharField(max_length=20)  # 주민번호 평문
    credit_card = models.CharField(max_length=20)  # 카드번호 평문
    password_hint = models.CharField(max_length=100)  # 패스워드 힌트
    
    def save_password(self, password):
        # 약한 해시 사용
        self.password_hash = hashlib.md5(password.encode()).hexdigest()  # MD5
        self.save()

class SecretData(models.Model):
    # 암호화 없이 민감한 데이터 저장
    api_key = models.CharField(max_length=100)
    private_key = models.TextField()
    password = models.CharField(max_length=100)
    
    class Meta:
        # 잘못된 권한 설정
        permissions = [
            ("view_secretdata", "Can view secret data"),
        ]
        default_permissions = ('add', 'change', 'delete', 'view')  # 너무 관대

class AuditLog(models.Model):
    # 로그에 민감한 정보 포함
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=100)
    data = models.TextField()  # 민감한 데이터 포함 가능
    password_used = models.CharField(max_length=100)  # 패스워드 로깅
    
    def __str__(self):
        # 민감한 정보 노출
        return f"{self.user.username} - {self.password_used}"
""",
                'size': 1400,
                'lines': 40
            }
        ]
    }


def get_vulnerable_fastapi_app():
    """취약한 FastAPI 애플리케이션 예제"""
    return {
        'name': 'Vulnerable FastAPI App',
        'files': [
            {
                'path': 'main.py',
                'content': """from fastapi import FastAPI, Request, File, UploadFile
from fastapi.responses import HTMLResponse
import sqlite3
import os
import pickle
import subprocess

app = FastAPI()

# 하드코딩된 API 키
API_KEY = "super-secret-api-key-123"
DB_PASSWORD = "admin123"

@app.get("/")
async def root():
    return {"message": "Vulnerable FastAPI App"}

@app.get("/users/{user_id}")
async def get_user(user_id: str):
    # SQL 인젝션 취약점
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # 위험: 직접 삽입
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    return {"user": user}

@app.post("/login")
async def login(request: Request):
    data = await request.json()
    username = data.get("username")
    password = data.get("password")
    
    # SQL 인젝션 취약점
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)  # 위험
    user = cursor.fetchone()
    conn.close()
    
    if user:
        # 예측 가능한 토큰
        import time
        token = str(hash(f"{username}{time.time()}"))  # 위험: 예측 가능
        return {"token": token}
    
    return {"error": "Invalid credentials"}

@app.get("/search")
async def search(q: str):
    # XSS 취약점
    html = f'''
    <html>
        <body>
            <h1>Search Results</h1>
            <p>You searched for: {q}</p>
            <script>
                var searchTerm = '{q}';
                document.write(searchTerm);
            </script>
        </body>
    </html>
    '''
    return HTMLResponse(content=html)  # 위험: XSS

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    # 경로 조작 취약점
    filename = file.filename
    filepath = f"uploads/{filename}"  # 위험: 경로 검증 없음
    
    # 파일 타입 검증 없음
    contents = await file.read()
    with open(filepath, "wb") as f:
        f.write(contents)
    
    # 안전하지 않은 역직렬화
    if filename.endswith(".pkl"):
        data = pickle.loads(contents)  # 위험
    
    return {"filename": filename}

@app.get("/exec")
async def execute(cmd: str):
    # 명령어 삽입 취약점
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)  # 위험
    return {"output": result.stdout}

@app.get("/admin")
async def admin():
    # 인증 없음 - 접근 제어 취약점
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    all_users = cursor.fetchall()
    conn.close()
    
    # 민감한 정보 노출
    return {
        "users": all_users,
        "api_key": API_KEY,
        "db_password": DB_PASSWORD
    }

@app.post("/eval")
async def evaluate(request: Request):
    data = await request.json()
    code = data.get("code")
    
    # 코드 실행 취약점
    result = eval(code)  # 위험: 임의 코드 실행
    
    return {"result": str(result)}

@app.get("/redirect")
async def redirect(url: str):
    # 오픈 리다이렉트 취약점
    return {"redirect_to": url}  # 위험: 검증 없는 리다이렉트
""",
                'size': 3500,
                'lines': 115
            },
            {
                'path': 'database.py',
                'content': """import sqlite3
import hashlib

class Database:
    def __init__(self):
        # 하드코딩된 데이터베이스 경로
        self.db_path = "users.db"
        self.admin_password = "admin123"  # 하드코딩된 패스워드
    
    def create_user(self, username, password):
        # 약한 해시 사용
        password_hash = hashlib.sha1(password.encode()).hexdigest()  # SHA1
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # SQL 인젝션 취약점
        query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password_hash}')"
        cursor.execute(query)  # 위험
        conn.commit()
        conn.close()
    
    def authenticate(self, username, password):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # SQL 인젝션 취약점
        query = "SELECT * FROM users WHERE username='%s' AND password='%s'" % (username, password)
        cursor.execute(query)  # 위험: % formatting
        user = cursor.fetchone()
        conn.close()
        
        return user
    
    def get_all_users(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 민감한 정보 포함
        cursor.execute("SELECT id, username, password, email, ssn FROM users")
        users = cursor.fetchall()
        conn.close()
        
        return users  # 위험: 패스워드와 주민번호 노출
""",
                'size': 1400,
                'lines': 45
            },
            {
                'path': 'requirements.txt',
                'content': """fastapi==0.68.0
uvicorn==0.15.0
python-multipart==0.0.5
pyyaml==5.3.1
""",
                'size': 100,
                'lines': 4
            }
        ]
    }


# 예제 프로젝트 목록
VULNERABLE_EXAMPLES = {
    'flask_vulnerable': get_vulnerable_web_app(),
    'django_vulnerable': get_vulnerable_django_app(),
    'fastapi_vulnerable': get_vulnerable_fastapi_app()
}