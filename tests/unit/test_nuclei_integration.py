"""Safe Nuclei manifest and normalized output parsing."""

import json

from vapt_platform.parsers.registry import parse_tool_output
from vapt_platform.tools.manifest import load_tool_manifests


def test_nuclei_manifest_is_bounded_and_low_impact() -> None:
    manifest = load_tool_manifests()["nuclei"]

    assert manifest.safety_class == "LOW_IMPACT"
    assert "TEMPLATE_BASED_ASSESSMENT" in manifest.capabilities
    assert "-omit-raw" in manifest.base_args
    assert "-no-interactsh" in manifest.base_args
    assert "-exclude-tags" in manifest.base_args
    assert "-rate-limit" in manifest.base_args


def test_nuclei_parser_keeps_only_normalized_candidate_metadata() -> None:
    stdout = json.dumps(
        {
            "template-id": "missing-hsts",
            "info": {"name": "Missing HSTS", "severity": "low"},
            "matched-at": "https://example.com",
            "request": "sensitive request body",
            "response": "sensitive response body",
        }
    )

    parsed = parse_tool_output("nuclei", stdout, {"url": "https://example.com"})

    assert parsed["events"] == []
    assert parsed["observations"] == [
        {
            "type": "SCANNER_OBSERVATION",
            "template_id": "missing-hsts",
            "name": "Missing HSTS",
            "severity": "low",
            "matched_at": "https://example.com",
            "target": "https://example.com",
        }
    ]
