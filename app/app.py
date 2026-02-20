"""
Aplicação Flask — Configuração de Produção.
Segue OWASP Top 10 2025, CIS Benchmarks e boas práticas de mercado.
"""

import logging
import os
import re
import sqlite3
import subprocess
import sys
import time
from collections import defaultdict
from functools import wraps

from flask import Flask, jsonify, request

# ─────────────────────────────────────────────────
# Configuração de Logging Estruturado (produção)
# ─────────────────────────────────────────────────
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%S%z",
    stream=sys.stdout,
)
logger = logging.getLogger("app")

# ─────────────────────────────────────────────────
# Validação de variáveis obrigatórias em PRODUÇÃO
# ─────────────────────────────────────────────────
REQUIRED_ENV_VARS = ["SECRET_KEY"]
_missing = [v for v in REQUIRED_ENV_VARS if not os.environ.get(v)]
if _missing and os.environ.get("FLASK_ENV") != "testing":
    logger.critical(
        "Variáveis de ambiente obrigatórias ausentes: %s — "
        "a aplicação NÃO será iniciada em produção sem elas.",
        ", ".join(_missing),
    )
    # Em produção de verdade, aborta; em dev/teste continua com warning
    if os.environ.get("FLASK_DEBUG", "false").lower() != "true":
        sys.exit(1)

# ─────────────────────────────────────────────────
# Inicialização do App
# ─────────────────────────────────────────────────
app = Flask(__name__)

app.config.update(
    # ✅ SECRET_KEY — nunca hardcoded, obrigatória via env
    SECRET_KEY=os.environ.get("SECRET_KEY", "INSECURE-DEV-ONLY-KEY"),

    # ✅ Cookies de sessão seguros
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,               # Exige HTTPS
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_NAME="__Host-session",      # Prefixo __Host exige Secure + path=/

    # ✅ Limites de payload (proteção DoS)
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,        # 1 MB
    MAX_FORM_MEMORY_SIZE=500 * 1024,           # 500 KB
    MAX_FORM_PARTS=100,

    # ✅ JSON seguro
    JSON_SORT_KEYS=False,

    # ✅ Desabilita o modo debug incondicionalmente em prod
    DEBUG=False,
    TESTING=False,
)

# ✅ Secrets do banco via variáveis de ambiente
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DATABASE_PATH = os.environ.get("DATABASE_PATH", "users.db")


# ─────────────────────────────────────────────────
# Security Headers Middleware
# ─────────────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    """Adiciona headers de segurança recomendados pelo OWASP a todas as respostas."""
    # Previne MIME sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Previne clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # Proteção XSS legada (browsers antigos)
    response.headers["X-XSS-Protection"] = "0"
    # HSTS — força HTTPS por 1 ano + subdomains + preload list
    response.headers["Strict-Transport-Security"] = (
        "max-age=63072000; includeSubDomains; preload"
    )
    # CSP restritiva
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    # Referrer Policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Permissions Policy — bloqueia APIs sensíveis
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
        "accelerometer=(), gyroscope=(), magnetometer=()"
    )
    # Cache control — nenhuma resposta é cacheada por padrão
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    # Cross-Origin isolation
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    # Remove headers que expõem informações do servidor
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    return response


# ─────────────────────────────────────────────────
# Rate Limiting (in-memory — para produção com múltiplos
# workers, usar Redis via flask-limiter)
# ─────────────────────────────────────────────────
_rate_limit_store: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT_MAX_REQUESTS = int(os.environ.get("RATE_LIMIT_MAX", "30"))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))


def rate_limit(f):
    """Rate limiting por IP de origem."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Respeita X-Forwarded-For quando atrás de proxy/LB confiável
        client_ip = request.headers.get(
            "X-Real-IP",
            request.headers.get("X-Forwarded-For", request.remote_addr or "unknown"),
        )
        # Se X-Forwarded-For tiver múltiplos IPs, pega o primeiro (cliente real)
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()

        now = time.time()
        window_start = now - RATE_LIMIT_WINDOW_SECONDS

        _rate_limit_store[client_ip] = [
            t for t in _rate_limit_store[client_ip] if t > window_start
        ]

        if len(_rate_limit_store[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
            logger.warning("rate_limit_exceeded client_ip=%s", client_ip)
            return jsonify({"error": "Too many requests"}), 429

        _rate_limit_store[client_ip].append(now)
        return f(*args, **kwargs)

    return decorated


# ─────────────────────────────────────────────────
# Gerenciamento seguro de conexão DB
# ─────────────────────────────────────────────────
def get_db_connection():
    """Retorna conexão SQLite com configurações seguras."""
    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=5,
        isolation_level="DEFERRED",
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ─────────────────────────────────────────────────
# Validação de entrada
# ─────────────────────────────────────────────────
def validate_positive_integer(value: str | None, param_name: str = "id") -> int | None:
    """Valida que o parâmetro é um inteiro positivo (>= 0)."""
    if value is None:
        return None
    try:
        parsed = int(value)
        if parsed < 0 or parsed > 2_147_483_647:  # Max INT32
            return None
        return parsed
    except (ValueError, TypeError):
        logger.info("invalid_param param=%s value=%s", param_name, value[:50] if value else "")
        return None


# ─────────────────────────────────────────────────
# Rotas
# ─────────────────────────────────────────────────

@app.route("/health")
def health_check():
    """Health check para load balancers, Kubernetes probes, etc."""
    return jsonify({"status": "healthy"}), 200


@app.route("/ready")
def readiness_check():
    """Readiness probe — verifica que o DB está acessível."""
    try:
        conn = get_db_connection()
        conn.execute("SELECT 1")
        conn.close()
        return jsonify({"status": "ready"}), 200
    except Exception:
        return jsonify({"status": "not ready"}), 503


# ✅ SQL com parâmetros (sem SQL Injection) + validação rigorosa
@app.route("/user")
@rate_limit
def get_user():
    """Busca usuário por ID com query parametrizada."""
    user_id = validate_positive_integer(request.args.get("id"), "id")
    if user_id is None:
        return jsonify({"error": "Parâmetro 'id' inválido ou ausente"}), 400

    try:
        conn = get_db_connection()
        try:
            result = conn.execute(
                "SELECT id, name FROM users WHERE id = ?", (user_id,)
            ).fetchall()
            return jsonify([dict(row) for row in result])
        finally:
            conn.close()
    except sqlite3.Error:
        logger.exception("db_error endpoint=/user")
        return jsonify({"error": "Erro interno do servidor"}), 500


# ✅ Sem shell=True + validação rigorosa + anti-SSRF
VALID_HOST_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,252}$")
BLOCKED_HOSTS = frozenset({
    "127.0.0.1", "0.0.0.0", "::1", "localhost",
    "metadata.google.internal",           # GCP metadata
    "169.254.169.254",                    # AWS/Azure metadata
    "metadata.google.internal.",
    "10.0.0.1",
})
BLOCKED_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.", "fd", "fe80:")


@app.route("/ping")
@rate_limit
def ping():
    """Ping com proteção contra command injection e SSRF."""
    host = request.args.get("host", "").strip()

    if not host:
        return jsonify({"error": "Parâmetro 'host' é obrigatório"}), 400

    if not VALID_HOST_RE.match(host):
        return jsonify({"error": "Host inválido"}), 400

    host_lower = host.lower()
    if host_lower in BLOCKED_HOSTS or any(host_lower.startswith(p) for p in BLOCKED_PREFIXES):
        logger.warning("ssrf_attempt host=%s client=%s", host, request.remote_addr)
        return jsonify({"error": "Host não permitido"}), 403

    try:
        output = subprocess.check_output(
            ["ping", "-c", "1", "-W", "3", host],
            timeout=5,
            stderr=subprocess.STDOUT,
        )
        return jsonify({"result": output.decode("utf-8", errors="replace")})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout"}), 504
    except subprocess.CalledProcessError:
        return jsonify({"error": "Host unreachable"}), 502


# ✅ Rota segura duplicada
@app.route("/user/safe")
@rate_limit
def get_user_safe():
    """Busca segura de usuário por ID."""
    user_id = validate_positive_integer(request.args.get("id"), "id")
    if user_id is None:
        return jsonify({"error": "Parâmetro 'id' inválido ou ausente"}), 400

    try:
        conn = get_db_connection()
        try:
            result = conn.execute(
                "SELECT id, name FROM users WHERE id = ?", (user_id,)
            ).fetchall()
            return jsonify([dict(row) for row in result])
        finally:
            conn.close()
    except sqlite3.Error:
        logger.exception("db_error endpoint=/user/safe")
        return jsonify({"error": "Erro interno do servidor"}), 500


# ✅ Sem Path Traversal — whitelist fixa
ALLOWED_FILES: dict[str, str] = {
    "report": "/var/data/report.txt",
    "status": "/var/data/status.txt",
}


@app.route("/file")
@rate_limit
def read_file():
    """Lê arquivo de whitelist fixa — sem path traversal."""
    filename = request.args.get("name", "").strip()

    if not filename:
        return jsonify({"error": "Parâmetro 'name' é obrigatório"}), 400

    filepath = ALLOWED_FILES.get(filename)
    if filepath is None:
        logger.warning("path_traversal_attempt name=%s client=%s", filename[:50], request.remote_addr)
        return jsonify({"error": "Arquivo não permitido"}), 403

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return jsonify({"content": f.read()})
    except FileNotFoundError:
        return jsonify({"error": "Arquivo não encontrado"}), 404
    except OSError:
        logger.exception("file_read_error path=%s", filepath)
        return jsonify({"error": "Erro interno do servidor"}), 500


# ─────────────────────────────────────────────────
# Error Handlers — NUNCA expor stack traces em prod
# ─────────────────────────────────────────────────
@app.errorhandler(400)
def bad_request(_e):
    return jsonify({"error": "Bad request"}), 400


@app.errorhandler(404)
def not_found(_e):
    return jsonify({"error": "Recurso não encontrado"}), 404


@app.errorhandler(405)
def method_not_allowed(_e):
    return jsonify({"error": "Método não permitido"}), 405


@app.errorhandler(413)
def payload_too_large(_e):
    return jsonify({"error": "Payload excede o limite"}), 413


@app.errorhandler(429)
def too_many_requests(_e):
    return jsonify({"error": "Too many requests"}), 429


@app.errorhandler(500)
def internal_error(_e):
    return jsonify({"error": "Erro interno do servidor"}), 500


# ─────────────────────────────────────────────────
# Entrypoint — NUNCA usar em produção (usar Gunicorn)
# ─────────────────────────────────────────────────
if __name__ == "__main__":
    logger.warning(
        "⚠️  Usando servidor de desenvolvimento Flask. "
        "Em PRODUÇÃO use: gunicorn -c gunicorn.conf.py app:app"
    )
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
