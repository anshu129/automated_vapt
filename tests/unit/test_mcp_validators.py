"""Unit tests for MCP validation connectors."""

from vapt_platform.config.settings import Settings
from vapt_platform.validators.base import with_auth_url
from vapt_platform.validators.burp import BurpMcpValidator
from vapt_platform.validators.registry import build_validation_connectors
from vapt_platform.validators.sqlmap_mcp import SqlmapMcpValidator


def test_burp_parses_scanner_issue_json() -> None:
    raw = '{"name":"SQL injection","severity":"high","host":"app.example.com","path":"/login"}'
    findings = BurpMcpValidator._parse_scanner_issues(raw, "app.example.com", "https://app.example.com")
    assert len(findings) == 1
    assert findings[0].name == "SQL injection"
    assert findings[0].severity == "high"


def test_sqlmap_positive_detection() -> None:
    positive = "Parameter 'id' is vulnerable. Type: boolean-based blind"
    negative = "all tested parameters appear to be not injectable"
    assert SqlmapMcpValidator._looks_positive(positive)
    assert not SqlmapMcpValidator._looks_positive(negative)


def test_registry_includes_burp_when_enabled() -> None:
    settings = Settings(
        BURP_MCP_ENABLED=True,
        BURP_MCP_SSE_URL="http://127.0.0.1:9876/sse",
    )
    names = [c.name for c in build_validation_connectors(settings)]
    assert "nuclei" in names
    assert "burp" in names


def test_sqlmap_skips_non_injection_classes() -> None:
    validator = SqlmapMcpValidator(server_path="/nonexistent/server.py")
    assert not validator._targets_sqli(["XSS_REFLECTED"])
    assert validator._targets_sqli(["SQL_INJECTION"])


def test_with_auth_url_embeds_credentials() -> None:
    url = with_auth_url("http://example.com/path", "user", "pass")
    assert url.startswith("http://user:pass@example.com")
    assert with_auth_url("http://already:here@example.com", "user", "pass") == "http://already:here@example.com"
