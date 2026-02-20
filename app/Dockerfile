# ═══════════════════════════════════════════════════
# Stage 1: Builder — instala dependências isoladamente
# ═══════════════════════════════════════════════════
FROM python:3.13-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt


# ═══════════════════════════════════════════════════
# Stage 2: Runtime — imagem final mínima e segura
# ═══════════════════════════════════════════════════
FROM python:3.13-slim

# ── Labels OCI ─────────────────────────────────────
LABEL org.opencontainers.image.title="demo-app" \
      org.opencontainers.image.description="FIAP Demo CICD SAST — Production" \
      org.opencontainers.image.vendor="FIAP" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.source="https://github.com/brianmonteiro54/fiap-demo-cicd-sast"

# ── Variáveis de ambiente (seguras, sem valores sensíveis) ──
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    FLASK_DEBUG=false \
    PORT=5000 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

WORKDIR /app

# ── Copia dependências do builder ──────────────────
COPY --from=builder /install /usr/local

# ── Cria usuário não-root (princípio do menor privilégio) ──
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /usr/sbin/nologin --no-create-home appuser && \
    mkdir -p /var/data && \
    chown appuser:appgroup /var/data && \
    # Remove pacotes desnecessários
    apt-get purge -y --auto-remove && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.cache && \
    # Remove pip e setuptools do runtime (não são necessários)
    pip uninstall -y pip setuptools 2>/dev/null || true

# ── Copia código com ownership correto ─────────────
COPY --chown=appuser:appgroup . .

# ── Permissões restritivas ────────────────────────
RUN chmod -R 550 /app && \
    chmod 440 /app/gunicorn.conf.py && \
    # Remove __pycache__ e .pyc se existirem
    find /app -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true && \
    find /app -name "*.pyc" -delete 2>/dev/null || true

# ── Executa como não-root ─────────────────────────
USER 1001:1001

# ── Expõe porta ───────────────────────────────────
EXPOSE 5000

# ── Health check ──────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')"]

# ── Entrypoint: Gunicorn (produção) ──────────────
ENTRYPOINT ["gunicorn"]
CMD ["-c", "gunicorn.conf.py", "app:app"]