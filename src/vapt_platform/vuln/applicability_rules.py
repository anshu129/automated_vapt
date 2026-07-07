"""Applicability rule loading and deterministic condition evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from vapt_platform.domain.enums import ApplicabilityState

RULES_PATH = Path(__file__).resolve().parents[3] / "config" / "applicability" / "rules.yaml"

STATE_PRIORITY: dict[str, int] = {
    ApplicabilityState.CONFIRMED.value: 6,
    ApplicabilityState.PARTIALLY_TESTED.value: 5,
    ApplicabilityState.TESTED_NO_EVIDENCE.value: 4,
    ApplicabilityState.APPLICABLE.value: 3,
    ApplicabilityState.POSSIBLY_APPLICABLE.value: 2,
    ApplicabilityState.INCONCLUSIVE.value: 1,
    ApplicabilityState.NOT_APPLICABLE.value: 0,
}


@dataclass
class ApplicabilityContext:
    asset_type: str
    metadata: dict[str, Any] = field(default_factory=dict)
    surface_dimensions: dict[str, str] = field(default_factory=dict)
    endpoints: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    uses_https: bool = False
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class RuleOutput:
    class_code: str
    state: str
    confidence: float


@dataclass
class ApplicabilityRuleSpec:
    rule_id: str
    version: str
    description: str
    condition: dict[str, Any]
    outputs: list[RuleOutput]
    active: bool = True


@dataclass
class ClassApplicabilityResult:
    class_code: str
    state: str
    confidence: float
    rule_ids: list[str]
    explanation: str


def load_rules_from_yaml(path: Path | None = None) -> tuple[str, list[ApplicabilityRuleSpec]]:
    rules_file = path or RULES_PATH
    with rules_file.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    version = str(data.get("version", "1.0"))
    specs: list[ApplicabilityRuleSpec] = []
    for raw in data.get("rules", []):
        outputs = [
            RuleOutput(
                class_code=o["class_code"],
                state=o["state"],
                confidence=float(o.get("confidence", 0.5)),
            )
            for o in raw.get("outputs", [])
        ]
        specs.append(
            ApplicabilityRuleSpec(
                rule_id=raw["rule_id"],
                version=version,
                description=raw.get("description", ""),
                condition=raw.get("condition", {}),
                outputs=outputs,
                active=raw.get("active", True),
            )
        )
    return version, specs


def evaluate_condition(condition: dict[str, Any], ctx: ApplicabilityContext) -> bool:
    if "all" in condition:
        return all(evaluate_condition(c, ctx) for c in condition["all"])
    if "any" in condition:
        return any(evaluate_condition(c, ctx) for c in condition["any"])
    if "not" in condition:
        return not evaluate_condition(condition["not"], ctx)

    field_path = condition.get("field", "")
    value = resolve_field(ctx, field_path)

    if "exists" in condition:
        want = condition["exists"]
        present = value is not None and value != "" and value != [] and value != {}
        return present if want else not present
    if "eq" in condition:
        return value == condition["eq"]
    if "neq" in condition:
        return value != condition["neq"]
    if "in" in condition:
        return value in condition["in"]
    if "contains" in condition:
        if isinstance(value, list):
            return condition["contains"] in value
        if isinstance(value, str):
            return condition["contains"] in value
        return False
    if "any_match" in condition:
        needle = condition["any_match"].lower()
        items = value if isinstance(value, list) else [value]
        return any(needle in str(item).lower() for item in items if item is not None)

    return False


def resolve_field(ctx: ApplicabilityContext, path: str) -> Any:
    if not path:
        return None
    if path == "asset_type":
        return ctx.asset_type
    if path == "uses_https":
        return ctx.uses_https
    if path == "endpoints":
        return ctx.endpoints
    if path == "technologies":
        return ctx.technologies

    if path.startswith("surface."):
        return ctx.surface_dimensions.get(path.split(".", 1)[1])

    if path.startswith("metadata."):
        cur: Any = ctx.metadata
        for part in path.split(".")[1:]:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur

    return None


def evaluate_rules(
    rules: list[ApplicabilityRuleSpec],
    ctx: ApplicabilityContext,
) -> list[ClassApplicabilityResult]:
    merged: dict[str, ClassApplicabilityResult] = {}

    for rule in rules:
        if not rule.active:
            continue
        if not evaluate_condition(rule.condition, ctx):
            continue
        for output in rule.outputs:
            existing = merged.get(output.class_code)
            if existing is None or STATE_PRIORITY[output.state] > STATE_PRIORITY[existing.state]:
                rule_ids = list(existing.rule_ids) if existing else []
                if rule.rule_id not in rule_ids:
                    rule_ids.append(rule.rule_id)
                merged[output.class_code] = ClassApplicabilityResult(
                    class_code=output.class_code,
                    state=output.state,
                    confidence=output.confidence,
                    rule_ids=rule_ids,
                    explanation=rule.description or f"Matched rule {rule.rule_id}",
                )
            elif (
                existing is not None
                and STATE_PRIORITY[output.state] == STATE_PRIORITY[existing.state]
            ):
                if rule.rule_id not in existing.rule_ids:
                    existing.rule_ids.append(rule.rule_id)
            elif existing is not None and rule.rule_id not in existing.rule_ids:
                existing.rule_ids.append(rule.rule_id)

    return list(merged.values())
