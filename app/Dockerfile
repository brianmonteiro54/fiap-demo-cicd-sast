FROM python:3.13-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.13-slim

LABEL org.opencontainers.image.title="demo-app" \
      org.opencontainers.image.description="FIAP Demo CICD SAST — Production" \
      org.opencontainers.image.vendor="FIAP" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.source="https://github.com/brianmonteiro54/fiap-demo-cicd-sast"

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

COPY --from=builder /install /usr/local

RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /usr/sbin/nologin --no-create-home appuser && \
    mkdir -p /var/data && \
    chown appuser:appgroup /var/data && \
    apt-get purge -y --auto-remove && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.cache && \
    pip uninstall -y pip setuptools 2>/dev/null || true

COPY app.py gunicorn.conf.py requirements.txt ./

RUN chown root:appgroup /app/app.py /app/gunicorn.conf.py /app/requirements.txt && \
    chmod 440 /app/app.py /app/gunicorn.conf.py /app/requirements.txt

USER 1001:1001

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')"]

ENTRYPOINT ["gunicorn"]
CMD ["-c", "gunicorn.conf.py", "app:app"]
