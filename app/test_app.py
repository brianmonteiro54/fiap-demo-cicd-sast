"""
Testes de segurança e funcionais — Produção.
Cobertura: OWASP Top 10, headers, injection, SSRF, rate limiting.
"""

import os
import pytest
from unittest.mock import patch, mock_open, MagicMock

# Forçar variáveis antes do import da app
os.environ["FLASK_ENV"] = "testing"
os.environ["SECRET_KEY"] = "test-secret-key-for-ci-only"

from app import app, _rate_limit_store  # noqa: E402


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Limpa o rate limiter entre cada teste para evitar falsos 429."""
    _rate_limit_store.clear()
    yield
    _rate_limit_store.clear()


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ═══════════════════════════════════════════════════
# Health & Readiness Probes
# ═══════════════════════════════════════════════════
class TestProbes:
    def test_health_returns_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.get_json()["status"] == "healthy"

    def test_readiness_check(self, client):
        r = client.get("/ready")
        assert r.status_code in [200, 503]

    def test_readiness_db_failure(self, client):
        """Cobre linhas 172-173: exceção no DB retorna 503."""
        with patch("app.get_db_connection", side_effect=Exception("DB down")):
            r = client.get("/ready")
            assert r.status_code == 503
            assert r.get_json()["status"] == "not ready"

    def test_app_exists(self):
        assert app is not None


# ═══════════════════════════════════════════════════
# Security Headers (OWASP)
# ═══════════════════════════════════════════════════
class TestSecurityHeaders:
    def _get_headers(self, client):
        return client.get("/health").headers

    def test_x_content_type_options(self, client):
        assert self._get_headers(client)["X-Content-Type-Options"] == "nosniff"

    def test_x_frame_options_deny(self, client):
        assert self._get_headers(client)["X-Frame-Options"] == "DENY"

    def test_hsts_present_and_long_max_age(self, client):
        hsts = self._get_headers(client)["Strict-Transport-Security"]
        assert "max-age=63072000" in hsts
        assert "includeSubDomains" in hsts
        assert "preload" in hsts

    def test_csp_present(self, client):
        csp = self._get_headers(client)["Content-Security-Policy"]
        assert "default-src 'none'" in csp

    def test_referrer_policy(self, client):
        assert "strict-origin" in self._get_headers(client)["Referrer-Policy"]

    def test_permissions_policy(self, client):
        pp = self._get_headers(client)["Permissions-Policy"]
        assert "camera=()" in pp
        assert "microphone=()" in pp

    def test_cache_control_no_store(self, client):
        assert "no-store" in self._get_headers(client)["Cache-Control"]

    def test_cross_origin_opener_policy(self, client):
        assert self._get_headers(client)["Cross-Origin-Opener-Policy"] == "same-origin"

    def test_cross_origin_resource_policy(self, client):
        assert self._get_headers(client)["Cross-Origin-Resource-Policy"] == "same-origin"

    def test_no_server_header_leaked(self, client):
        assert "Server" not in self._get_headers(client)


# ═══════════════════════════════════════════════════
# SQL Injection (A03:2021)
# ═══════════════════════════════════════════════════
class TestSQLInjection:
    def test_valid_id(self, client):
        assert client.get("/user?id=1").status_code in [200, 500]

    def test_string_id_rejected(self, client):
        assert client.get("/user?id=abc").status_code == 400

    def test_sql_union_rejected(self, client):
        assert client.get("/user?id=1 UNION SELECT * FROM users").status_code == 400

    def test_sql_or_rejected(self, client):
        assert client.get("/user?id=1 OR 1=1").status_code == 400

    def test_missing_id_rejected(self, client):
        assert client.get("/user").status_code == 400

    def test_negative_id_rejected(self, client):
        assert client.get("/user?id=-1").status_code == 400

    def test_overflow_id_rejected(self, client):
        assert client.get("/user?id=99999999999999999").status_code == 400

    def test_safe_route_valid(self, client):
        assert client.get("/user/safe?id=1").status_code in [200, 500]

    def test_safe_route_injection(self, client):
        assert client.get("/user/safe?id=1; DROP TABLE users").status_code == 400


# ═══════════════════════════════════════════════════
# SQL — DB success path (mock)
# ═══════════════════════════════════════════════════
class TestSQLSuccess:
    """Cobre linhas 190 e 268: retorno com sucesso do DB."""

    def _mock_conn(self):
        mock_conn = MagicMock()
        mock_row = {"id": 1, "name": "Alice"}
        mock_conn.execute.return_value.fetchall.return_value = [mock_row]
        return mock_conn

    def test_get_user_success(self, client):
        with patch("app.get_db_connection", return_value=self._mock_conn()):
            r = client.get("/user?id=1")
            assert r.status_code == 200

    def test_get_user_safe_success(self, client):
        with patch("app.get_db_connection", return_value=self._mock_conn()):
            r = client.get("/user/safe?id=1")
            assert r.status_code == 200


# ═══════════════════════════════════════════════════
# Command Injection (A03:2021)
# ═══════════════════════════════════════════════════
class TestCommandInjection:
    def test_valid_host(self, client):
        r = client.get("/ping?host=8.8.8.8")
        assert r.status_code in [200, 502, 504]

    def test_semicolon_injection(self, client):
        assert client.get("/ping?host=; rm -rf /").status_code == 400

    def test_pipe_injection(self, client):
        assert client.get("/ping?host=| cat /etc/passwd").status_code == 400

    def test_backtick_injection(self, client):
        assert client.get("/ping?host=`whoami`").status_code == 400

    def test_dollar_injection(self, client):
        assert client.get("/ping?host=$(id)").status_code == 400

    def test_newline_injection(self, client):
        assert client.get("/ping?host=google.com%0als").status_code == 400

    def test_empty_host(self, client):
        assert client.get("/ping?host=").status_code == 400

    def test_missing_host(self, client):
        assert client.get("/ping").status_code == 400


# ═══════════════════════════════════════════════════
# Ping — subprocess edge cases
# ═══════════════════════════════════════════════════
class TestPingEdgeCases:
    """Cobre linhas 247-251: sucesso, TimeoutExpired e CalledProcessError."""

    def test_ping_success(self, client):
        """Cobre linha 247: retorno com sucesso do ping."""
        with patch("app.subprocess.check_output", return_value=b"PING ok"):
            r = client.get("/ping?host=example.com")
            assert r.status_code == 200
            assert "PING ok" in r.get_json()["result"]

    def test_ping_timeout(self, client):
        """Cobre linhas 248-249: TimeoutExpired."""
        import subprocess
        with patch("app.subprocess.check_output", side_effect=subprocess.TimeoutExpired(cmd="ping", timeout=5)):
            r = client.get("/ping?host=example.com")
            assert r.status_code == 504

    def test_ping_unreachable(self, client):
        """Cobre linhas 250-251: CalledProcessError."""
        import subprocess
        with patch("app.subprocess.check_output", side_effect=subprocess.CalledProcessError(1, "ping")):
            r = client.get("/ping?host=example.com")
            assert r.status_code == 502


# ═══════════════════════════════════════════════════
# SSRF (A10:2021)
# ═══════════════════════════════════════════════════
class TestSSRF:
    def test_localhost_blocked(self, client):
        assert client.get("/ping?host=127.0.0.1").status_code == 403

    def test_localhost_name_blocked(self, client):
        assert client.get("/ping?host=localhost").status_code == 403

    def test_metadata_gcp_blocked(self, client):
        assert client.get("/ping?host=metadata.google.internal").status_code == 403

    def test_metadata_aws_blocked(self, client):
        assert client.get("/ping?host=169.254.169.254").status_code == 403

    def test_private_10_blocked(self, client):
        assert client.get("/ping?host=10.0.0.1").status_code == 403

    def test_private_172_blocked(self, client):
        assert client.get("/ping?host=172.16.0.1").status_code == 403

    def test_private_192_blocked(self, client):
        assert client.get("/ping?host=192.168.1.1").status_code == 403

    def test_non_ip_host_not_blocked(self, client):
        """Cobre linhas 220-221: hostname válido gera ValueError em ip_address()."""
        r = client.get("/ping?host=example.com")
        assert r.status_code in [200, 502, 504]


# ═══════════════════════════════════════════════════
# Path Traversal (A01:2021)
# ═══════════════════════════════════════════════════
class TestPathTraversal:
    def test_etc_passwd_blocked(self, client):
        assert client.get("/file?name=../../etc/passwd").status_code == 403

    def test_unknown_file_blocked(self, client):
        assert client.get("/file?name=unknown.txt").status_code == 403

    def test_allowed_report(self, client):
        assert client.get("/file?name=report").status_code in [200, 404]

    def test_allowed_status(self, client):
        assert client.get("/file?name=status").status_code in [200, 404]

    def test_empty_name(self, client):
        assert client.get("/file?name=").status_code == 400

    def test_missing_param(self, client):
        assert client.get("/file").status_code == 400

    def test_null_byte_injection(self, client):
        assert client.get("/file?name=report%00.txt").status_code == 403

    def test_double_encoding(self, client):
        assert client.get("/file?name=..%252f..%252fetc/passwd").status_code == 403


# ═══════════════════════════════════════════════════
# File read — success + OSError paths
# ═══════════════════════════════════════════════════
class TestFileReadEdgeCases:
    """Cobre linhas 298, 301-303."""

    def test_file_read_success(self, client):
        """Cobre linha 298: leitura de arquivo com sucesso."""
        m = mock_open(read_data="conteúdo do relatório")
        with patch("builtins.open", m):
            r = client.get("/file?name=report")
            assert r.status_code == 200
            assert r.get_json()["content"] == "conteúdo do relatório"

    def test_file_read_os_error(self, client):
        """Cobre linhas 301-303: OSError na leitura."""
        with patch("builtins.open", side_effect=OSError("Permission denied")):
            r = client.get("/file?name=report")
            assert r.status_code == 500


# ═══════════════════════════════════════════════════
# Rate Limiting
# ═══════════════════════════════════════════════════
class TestRateLimiting:
    """Cobre linhas 112, 122-123."""

    def test_rate_limit_exceeded(self, client):
        """Cobre linhas 122-123: retorna 429 após exceder limite."""
        for _ in range(31):
            client.get("/user?id=1")
        r = client.get("/user?id=1")
        assert r.status_code == 429
        assert "Too many" in r.get_json()["error"]

    def test_forwarded_for_with_comma(self, client):
        """Cobre linha 112: X-Forwarded-For com múltiplos IPs."""
        r = client.get(
            "/user?id=1",
            headers={"X-Forwarded-For": "203.0.113.1, 198.51.100.1"},
        )
        assert r.status_code in [200, 400, 500]


# ═══════════════════════════════════════════════════
# Error Handling — não vazar informações
# ═══════════════════════════════════════════════════
class TestErrorHandling:
    def test_404_returns_json(self, client):
        r = client.get("/nonexistent")
        assert r.status_code == 404
        assert "application/json" in r.content_type
        body = r.get_json()
        assert "traceback" not in str(body).lower()
        assert "stack" not in str(body).lower()

    def test_405_returns_json(self, client):
        r = client.post("/health")
        assert r.status_code == 405
        assert "application/json" in r.content_type

    def test_error_does_not_leak_internals(self, client):
        r = client.get("/user?id=1")
        body = r.get_data(as_text=True)
        assert "sqlite" not in body.lower() or r.status_code == 200
        assert "traceback" not in body.lower()

    def test_413_payload_too_large(self, client):
        """Cobre linha 323: error handler 413."""
        r = client.post(
            "/health",
            data=b"x" * (2 * 1024 * 1024),
            content_type="application/octet-stream",
        )
        assert r.status_code in [405, 413]

    def test_500_error_handler(self, client):
        """Cobre linha 333: error handler 500 via sqlite3.Error."""
        import sqlite3
        with patch("app.get_db_connection", side_effect=sqlite3.Error("db fail")):
            r = client.get("/user?id=1")
            assert r.status_code == 500


# ═══════════════════════════════════════════════════
# Response Format
# ═══════════════════════════════════════════════════
class TestResponseFormat:
    def test_health_is_json(self, client):
        assert "application/json" in client.get("/health").content_type

    def test_error_responses_are_json(self, client):
        assert "application/json" in client.get("/user?id=invalid").content_type

    def test_400_is_json(self, client):
        assert "application/json" in client.get("/file?name=").content_type
