"""Auth challenge status filtering for discovery tools and parsers."""

from vapt_platform.parameters.context import OperationalContext
from vapt_platform.parameters.engine import ParameterSelectionEngine
from vapt_platform.parsers.registry import parse_tool_output


def test_ffuf_match_codes_exclude_auth_challenges() -> None:
    engine = ParameterSelectionEngine()
    decision = engine.derive(
        "ffuf",
        ["-u", "{url}/FUZZ", "-w", "{wordlist}", "-json"],
        {"url": "http://example.com"},
        OperationalContext(),
    )
    mc = decision.final_args[decision.final_args.index("-mc") + 1]
    assert "401" not in mc
    assert "403" not in mc
    assert "200" in mc


def test_feroxbuster_filters_auth_status_codes() -> None:
    engine = ParameterSelectionEngine()
    decision = engine.derive(
        "feroxbuster",
        ["-u", "{url}", "-w", "{wordlist}", "--json"],
        {"url": "http://example.com"},
        OperationalContext(),
    )
    assert "--filter-status" in decision.final_args
    idx = decision.final_args.index("--filter-status")
    filtered = decision.final_args[idx + 1 : idx + 3]
    assert "401" in filtered
    assert "403" in filtered


def test_gobuster_status_codes_exclude_auth() -> None:
    engine = ParameterSelectionEngine()
    decision = engine.derive(
        "gobuster",
        ["dir", "-u", "{url}", "-w", "{wordlist}", "-q"],
        {"url": "http://example.com"},
        OperationalContext(),
    )
    codes = decision.final_args[decision.final_args.index("-s") + 1]
    assert "401" not in codes
    assert "403" not in codes


def test_content_discovery_parser_skips_auth_responses() -> None:
    stdout = "\n".join(
        [
            '{"url":"http://example.com/admin","status":401}',
            '{"url":"http://example.com/index","status":200}',
        ]
    )
    parsed = parse_tool_output("ffuf", stdout, {"url": "http://example.com"})
    urls = [event["url"] for event in parsed["events"]]
    assert urls == ["http://example.com/index"]


def test_httpx_skips_web_app_confirmation_on_auth_challenge() -> None:
    stdout = '{"url":"http://example.com/","status_code":401,"title":"Unauthorized"}'
    parsed = parse_tool_output("httpx", stdout, {"url": "http://example.com"})
    types = [event["type"] for event in parsed["events"]]
    assert "HTTP_SERVICE_CONFIRMED" in types
    assert "WEB_APPLICATION_CONFIRMED" not in types
