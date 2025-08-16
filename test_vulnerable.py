# test_vulnerable.py
import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/user')
def get_user():
    # SQL Injection 취약점
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

@app.route('/ping')
def ping():
    # Command Injection 취약점
    host = request.args.get('host')
    result = os.system(f"ping -c 1 {host}")
    return str(result)