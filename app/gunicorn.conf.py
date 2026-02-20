"""
Gunicorn — Configuração de Produção.

Uso: gunicorn -c gunicorn.conf.py app:app

Referência: https://docs.gunicorn.org/en/stable/settings.html
"""

import multiprocessing
import os

bind = "0.0.0.0:" + os.environ.get("PORT", "5000")
backlog = 2048

workers = int(os.environ.get("GUNICORN_WORKERS", multiprocessing.cpu_count() * 2 + 1))
worker_class = "gthread"
threads = int(os.environ.get("GUNICORN_THREADS", "4"))

timeout = 30
graceful_timeout = 30
keepalive = 5

max_requests = 1000
max_requests_jitter = 100

limit_request_line = 4094
limit_request_fields = 50
limit_request_field_size = 8190

forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1")
proxy_protocol = False
secure_scheme_headers = {
    "X-FORWARDED-PROTOCOL": "ssl",
    "X-FORWARDED-PROTO": "https",
    "X-FORWARDED-SSL": "on",
}

accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info").lower()
access_log_format = (
    '{"remote_addr":"%(h)s","request":"%(r)s","status":"%(s)s",'
    '"response_length":"%(b)s","response_time":"%(D)s","referer":"%(f)s",'
    '"user_agent":"%(a)s"}'
)

proc_name = "demo-app"

preload_app = True
daemon = False
tmp_upload_dir = None


def on_starting(server):
    """Executado quando Gunicorn inicia."""
    server.log.info("Gunicorn starting — workers=%s threads=%s", workers, threads)


def worker_exit(server, worker):
    """Log quando um worker morre (útil para diagnóstico)."""
    server.log.info("Worker exited: pid=%s", worker.pid)
