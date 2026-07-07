"""Deterministic confirmation policy (Phase 3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from vapt_platform.domain.enums import VerdictStatus

_POLICY_PATH = Path(__file__).resolve().parents[3] / "config" / "confirmation_policies.yaml"


@dataclass
class ConfirmationDecision:
    recommended_verdict: str
    requirements_satisfied: bool
    missing_evidence_types: list[str] = field(default_factory=list)
    supporting_evidence_ids: list[str] = field(default_factory=list)
    contradicting_evidence_ids: list[str] = field(default_factory=list)
    policy_id: str = "default"
    policy_version: str = "1.0"
    reason_codes: list[str] = field(default_factory=list)


class ConfirmationPolicy:
    def __init__(self, policy_path: Path | None = None) -> None:
        path = policy_path or _POLICY_PATH
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
        self._version = str(raw.get("version", "1.0"))
        self._policies: dict[str, dict[str, Any]] = raw.get("policies", {})

    def evaluate(
        self,
        *,
        vulnerability_class: str,
        supporting_evidence: list[dict[str, Any]],
        contradicting_evidence: list[dict[str, Any]],
        coverage_evidence: list[dict[str, Any]],
        has_validation_evidence: bool,
        has_scanner_finding: bool,
        has_negative_evidence: bool,
        has_authenticated_context: bool = False,
    ) -> ConfirmationDecision:
        policy = self._policies.get(vulnerability_class) or self._policies.get("DEFAULT", {})
        policy_id = vulnerability_class if vulnerability_class in self._policies else "DEFAULT"
        required_types = list(policy.get("required_evidence_types") or [])
        missing: list[str] = []

        present: set[str] = set()
        if has_validation_evidence or has_scanner_finding:
            present.add("validation_evidence")
            present.add("positive_validation_or_scanner_evidence")
        if has_scanner_finding:
            present.add("positive_validation_or_scanner_evidence")
        if coverage_evidence:
            present.add("input_surface_evidence")
        if has_authenticated_context:
            present.add("authenticated_context")
        if supporting_evidence:
            present.add("analyst_or_structured_validation_evidence")

        for req in required_types:
            if req not in present:
                missing.append(req)

        supporting_ids = [str(e.get("id")) for e in supporting_evidence if e.get("id")]
        contradicting_ids = [str(e.get("id")) for e in contradicting_evidence if e.get("id")]

        contradiction_rules = policy.get("contradiction_rules") or {}
        if has_negative_evidence and contradiction_rules.get("decisive_negative_validation") == "REJECTED":
            if not has_validation_evidence and not has_scanner_finding:
                return ConfirmationDecision(
                    recommended_verdict=VerdictStatus.REJECTED.value,
                    requirements_satisfied=True,
                    supporting_evidence_ids=supporting_ids,
                    contradicting_evidence_ids=contradicting_ids,
                    policy_id=policy_id,
                    policy_version=self._version,
                    reason_codes=["DECISIVE_NEGATIVE_VALIDATION"],
                )

        if supporting_evidence and contradicting_evidence and not has_validation_evidence:
            return ConfirmationDecision(
                recommended_verdict=VerdictStatus.INCONCLUSIVE.value,
                requirements_satisfied=False,
                missing_evidence_types=missing,
                supporting_evidence_ids=supporting_ids,
                contradicting_evidence_ids=contradicting_ids,
                policy_id=policy_id,
                policy_version=self._version,
                reason_codes=["CONFLICTING_EVIDENCE"],
            )

        if not missing and has_validation_evidence:
            return ConfirmationDecision(
                recommended_verdict=VerdictStatus.CONFIRMED.value,
                requirements_satisfied=True,
                supporting_evidence_ids=supporting_ids,
                contradicting_evidence_ids=contradicting_ids,
                policy_id=policy_id,
                policy_version=self._version,
                reason_codes=["REQUIREMENTS_SATISFIED"],
            )

        if has_scanner_finding and missing:
            default = policy.get("default_insufficient", VerdictStatus.PARTIALLY_VALIDATED.value)
            return ConfirmationDecision(
                recommended_verdict=default,
                requirements_satisfied=False,
                missing_evidence_types=missing,
                supporting_evidence_ids=supporting_ids,
                contradicting_evidence_ids=contradicting_ids,
                policy_id=policy_id,
                policy_version=self._version,
                reason_codes=["INSUFFICIENT_CONFIRMATION_EVIDENCE"],
            )

        default = policy.get("default_insufficient", VerdictStatus.PARTIALLY_VALIDATED.value)
        return ConfirmationDecision(
            recommended_verdict=default,
            requirements_satisfied=False,
            missing_evidence_types=missing,
            supporting_evidence_ids=supporting_ids,
            contradicting_evidence_ids=contradicting_ids,
            policy_id=policy_id,
            policy_version=self._version,
            reason_codes=["INSUFFICIENT_EVIDENCE"],
        )
