import os
import pytest

# Forçar variáveis antes do import da app
os.environ["FLASK_ENV"] = "testing"
os.environ["SECRET_KEY"] = "test-secret-key-for-ci-only"

from app import app  # noqa: E402


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
