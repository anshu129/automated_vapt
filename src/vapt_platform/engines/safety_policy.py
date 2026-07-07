"""Safety policy for capability provider execution (Phase 2)."""

from __future__ import annotations

from dataclasses import dataclass, field

from vapt_platform.config.settings import Settings, get_settings
from vapt_platform.domain.enums import SafetyClass


@dataclass
class SafetyDecision:
    allowed: bool
    reason_codes: list[str] = field(default_factory=list)
    requires_manual_approval: bool = False


class SafetyPolicy:
    """Providers and AI cannot override this policy."""

    _AUTO_ALLOWED = {SafetyClass.PASSIVE.value, SafetyClass.LOW_IMPACT.value}

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    def evaluate(
        self,
        *,
        plan_safety_class: str,
        requirement_safety_class: str | None,
        provider_default_safety: str,
        capability_safety_class: str | None = None,
        engagement_allows_low_impact: bool = True,
    ) -> SafetyDecision:
        safety = (
            capability_safety_class
            or plan_safety_class
            or requirement_safety_class
            or provider_default_safety
        )
        if safety == SafetyClass.PROHIBITED.value:
            return SafetyDecision(
                allowed=False,
                reason_codes=["PROHIBITED"],
            )
        if safety == SafetyClass.DESTRUCTIVE.value:
            return SafetyDecision(
                allowed=False,
                reason_codes=["DESTRUCTIVE_NOT_AUTO_EXECUTABLE"],
            )
        if safety == SafetyClass.STATE_CHANGING.value:
            if not self._settings.engagement_allow_state_changing:
                return SafetyDecision(
                    allowed=False,
                    reason_codes=["STATE_CHANGING_REQUIRES_APPROVAL"],
                    requires_manual_approval=True,
                )
            return SafetyDecision(
                allowed=False,
                reason_codes=["STATE_CHANGING_REQUIRES_APPROVAL"],
                requires_manual_approval=True,
            )
        if safety == SafetyClass.LOW_IMPACT.value and not engagement_allows_low_impact:
            return SafetyDecision(
                allowed=False,
                reason_codes=["LOW_IMPACT_NOT_PERMITTED"],
            )
        if safety in self._AUTO_ALLOWED:
            return SafetyDecision(allowed=True)
        return SafetyDecision(
            allowed=False,
            reason_codes=["SAFETY_POLICY_REJECTED"],
        )
