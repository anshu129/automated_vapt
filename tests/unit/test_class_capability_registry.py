"""Unit tests for class capability registry."""

from vapt_platform.domain.class_capability_registry import ClassCapabilityRegistry


def test_sql_injection_maps_multiple_capabilities() -> None:
    registry = ClassCapabilityRegistry.from_yaml()
    mapping = registry.resolve("SQL_INJECTION")
    assert mapping is not None
    assert mapping.capabilities == (
        "WEB_PASSIVE_ASSESSMENT",
        "TEMPLATE_BASED_ASSESSMENT",
        "INJECTION_VALIDATION",
    )
    assert mapping.primary_capability == "WEB_PASSIVE_ASSESSMENT"


def test_object_level_authorization_maps_assisted_and_manual() -> None:
    registry = ClassCapabilityRegistry.from_yaml()
    mapping = registry.resolve("OBJECT_LEVEL_AUTHORIZATION")
    assert mapping is not None
    assert "AUTHORIZATION_SURFACE_ANALYSIS" in mapping.capabilities
    assert "ASSISTED_VALIDATION" in mapping.capabilities
    assert "MANUAL_VALIDATION" in mapping.capabilities
    assert mapping.credential_requirement == "AUTHENTICATED"


def test_capabilities_for_merges_profile_extras() -> None:
    registry = ClassCapabilityRegistry.from_yaml()
    caps = registry.capabilities_for(
        "SECURITY_HEADERS",
        profile_capabilities=["CUSTOM_CAPABILITY"],
    )
    assert caps[0] == "WEB_PASSIVE_ASSESSMENT"
    assert "CUSTOM_CAPABILITY" in caps
