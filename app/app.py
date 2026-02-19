from flask import Flask, request
import sqlite3
import subprocess
import os
# demo: trigger pipeline

app = Flask(__name__)

# ❌ VULNERABILIDADE 1: SQL Injection
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    # INSECURE: concatenação direta de input do usuário
    query = "SELECT * FROM users WHERE id = " + user_id
    result = conn.execute(query).fetchall()
    return str(result)

# ❌ VULNERABILIDADE 2: Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host')
    # INSECURE: execução direta de comando com input do usuário
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output

# ❌ VULNERABILIDADE 3: Hardcoded Secret
SECRET_KEY = "minha-senha-super-secreta-123"
DB_PASSWORD = "admin123"

# ✅ CORRETO: SQL com parâmetros
@app.route('/user/safe')
def get_user_safe():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    result = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
    return str(result)

if __name__ == '__main__':
    app.run(debug=True)
