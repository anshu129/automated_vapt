"""Applicability rule evaluator unit tests."""

from vapt_platform.domain.enums import ApplicabilityState
from vapt_platform.vuln.applicability_rules import (
    ApplicabilityContext,
    ApplicabilityRuleSpec,
    RuleOutput,
    evaluate_condition,
    evaluate_rules,
)


def test_web_app_baseline_rule_matches() -> None:
    ctx = ApplicabilityContext(
        asset_type="WEB_APPLICATION",
        metadata={"http_confirmed": True},
        uses_https=True,
    )
    rule = ApplicabilityRuleSpec(
        rule_id="web-app-baseline",
        version="1.0",
        description="baseline",
        condition={
            "all": [
                {"field": "asset_type", "eq": "WEB_APPLICATION"},
                {"field": "metadata.http_confirmed", "eq": True},
            ]
        },
        outputs=[
            RuleOutput("AUTHENTICATION", ApplicabilityState.APPLICABLE.value, 0.85),
            RuleOutput("AUTHORIZATION", ApplicabilityState.APPLICABLE.value, 0.85),
        ],
    )
    results = evaluate_rules([rule], ctx)
    codes = {r.class_code: r.state for r in results}
    assert codes["AUTHENTICATION"] == ApplicabilityState.APPLICABLE.value
    assert codes["AUTHORIZATION"] == ApplicabilityState.APPLICABLE.value
    assert "web-app-baseline" in results[0].rule_ids


def test_known_component_only_possibly_applicable() -> None:
    ctx = ApplicabilityContext(
        asset_type="WEB_APPLICATION",
        metadata={"technology_versions_confident": False},
        technologies=["nginx"],
    )
    rule = ApplicabilityRuleSpec(
        rule_id="known-component-technology-only",
        version="1.0",
        description="tech only",
        condition={
            "all": [
                {"field": "technologies", "exists": True},
                {"field": "metadata.technology_versions_confident", "eq": False},
            ]
        },
        outputs=[
            RuleOutput(
                "KNOWN_COMPONENT_VULNERABILITY",
                ApplicabilityState.POSSIBLY_APPLICABLE.value,
                0.5,
            )
        ],
    )
    results = evaluate_rules([rule], ctx)
    assert len(results) == 1
    assert results[0].state == ApplicabilityState.POSSIBLY_APPLICABLE.value


def test_endpoint_any_match_condition() -> None:
    ctx = ApplicabilityContext(
        asset_type="WEB_APPLICATION",
        endpoints=["https://app.example.com/api/users", "https://app.example.com/login"],
    )
    assert evaluate_condition({"field": "endpoints", "any_match": "login"}, ctx)
    assert evaluate_condition({"field": "endpoints", "any_match": "/api/users"}, ctx)
    assert not evaluate_condition({"field": "endpoints", "any_match": "graphql"}, ctx)


def test_state_priority_keeps_applicable_over_possible() -> None:
    ctx = ApplicabilityContext(
        asset_type="WEB_APPLICATION",
        metadata={"http_confirmed": True},
    )
    rules = [
        ApplicabilityRuleSpec(
            rule_id="possible",
            version="1.0",
            description="",
            condition={"field": "asset_type", "eq": "WEB_APPLICATION"},
            outputs=[RuleOutput("AUTHORIZATION", ApplicabilityState.POSSIBLY_APPLICABLE.value, 0.5)],
        ),
        ApplicabilityRuleSpec(
            rule_id="applicable",
            version="1.0",
            description="",
            condition={"field": "metadata.http_confirmed", "eq": True},
            outputs=[RuleOutput("AUTHORIZATION", ApplicabilityState.APPLICABLE.value, 0.9)],
        ),
    ]
    results = evaluate_rules(rules, ctx)
    assert results[0].state == ApplicabilityState.APPLICABLE.value
    assert set(results[0].rule_ids) == {"possible", "applicable"}
