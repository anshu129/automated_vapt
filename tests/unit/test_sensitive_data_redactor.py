"""Unit tests for SensitiveDataRedactor."""

from vapt_platform.security.sensitive_data_redactor import SensitiveDataRedactor


def test_authorization_header_redacted() -> None:
    text = "Authorization: Bearer secret-token-123"
    assert "[REDACTED]" in SensitiveDataRedactor().redact_text(text)
    assert "secret-token" not in SensitiveDataRedactor().redact_text(text)


def test_cookie_redacted() -> None:
    text = "Cookie: sessionid=abc123; path=/"
    redacted = SensitiveDataRedactor().redact_text(text)
    assert "abc123" not in redacted


def test_set_cookie_redacted() -> None:
    text = "Set-Cookie: id=xyz; HttpOnly"
    assert "xyz" not in SensitiveDataRedactor().redact_text(text)


def test_bearer_token_redacted() -> None:
    assert "[REDACTED]" in SensitiveDataRedactor().redact_text("token Bearer abc.def.ghi")


def test_basic_auth_redacted() -> None:
    assert "[REDACTED]" in SensitiveDataRedactor().redact_text("Authorization: Basic dXNlcjpwYXNz")


def test_credential_field_redacted_in_dict() -> None:
    payload = {"username": "user", "password": "secret123"}
    redacted = SensitiveDataRedactor().redact_dict(payload)
    assert redacted["password"] == "[REDACTED]"
    assert redacted["username"] == "user"
