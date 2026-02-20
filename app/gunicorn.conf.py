"""
Gunicorn — Configuração de Produção.

Uso: gunicorn -c gunicorn.conf.py app:app

Referência: https://docs.gunicorn.org/en/stable/settings.html
"""

import multiprocessing
import os

# ─────────────────────────────────────────────────
# Servidor
# ─────────────────────────────────────────────────
bind = "0.0.0.0:" + os.environ.get("PORT", "5000")
backlog = 2048

# ─────────────────────────────────────────────────
# Workers — Fórmula: (2 × CPU) + 1
# Para containers com CPU limitada, definir via env
# ─────────────────────────────────────────────────
workers = int(os.environ.get("GUNICORN_WORKERS", multiprocessing.cpu_count() * 2 + 1))
worker_class = "gthread"
threads = int(os.environ.get("GUNICORN_THREADS", "4"))

# ─────────────────────────────────────────────────
# Timeouts
# ─────────────────────────────────────────────────
timeout = 30                   # Mata worker que não responde em 30s
graceful_timeout = 30          # Tempo para graceful shutdown
keepalive = 5                  # Keep-alive de conexão (atrás de proxy)

# ─────────────────────────────────────────────────
# Reciclagem de Workers (proteção contra memory leaks)
# ─────────────────────────────────────────────────
max_requests = 1000            # Recicla worker após N requests
max_requests_jitter = 100      # Jitter para evitar restart simultâneo

# ─────────────────────────────────────────────────
# Segurança
# ─────────────────────────────────────────────────
limit_request_line = 4094      # Tamanho máximo da request line
limit_request_fields = 50      # Número máximo de headers
limit_request_field_size = 8190  # Tamanho máximo de cada header

# ─────────────────────────────────────────────────
# Headers (quando atrás de Nginx/ALB)
# ─────────────────────────────────────────────────
forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1")
proxy_protocol = False
secure_scheme_headers = {
    "X-FORWARDED-PROTOCOL": "ssl",
    "X-FORWARDED-PROTO": "https",
    "X-FORWARDED-SSL": "on",
}

# ─────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────
accesslog = "-"                # stdout
errorlog = "-"                 # stdout
loglevel = os.environ.get("LOG_LEVEL", "info").lower()
access_log_format = (
    '{"remote_addr":"%(h)s","request":"%(r)s","status":"%(s)s",'
    '"response_length":"%(b)s","response_time":"%(D)s","referer":"%(f)s",'
    '"user_agent":"%(a)s"}'
)

# ─────────────────────────────────────────────────
# Process Naming
# ─────────────────────────────────────────────────
proc_name = "demo-app"

# ─────────────────────────────────────────────────
# Server Mechanics
# ─────────────────────────────────────────────────
preload_app = True             # Carrega app antes de fork (economiza memória)
daemon = False                 # Container — não daemonizar
tmp_upload_dir = None

# ─────────────────────────────────────────────────
# Hooks
# ─────────────────────────────────────────────────
def on_starting(server):
    """Executado quando Gunicorn inicia."""
    server.log.info("Gunicorn starting — workers=%s threads=%s", workers, threads)


def worker_exit(server, worker):
    """Log quando um worker morre (útil para diagnóstico)."""
    server.log.info("Worker exited: pid=%s", worker.pid)
