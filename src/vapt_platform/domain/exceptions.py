"""Domain exceptions."""


class VaptPlatformError(Exception):
    """Base platform error."""


class EntityNotFoundError(VaptPlatformError):
    """Entity not found."""


class ScopeDeniedError(VaptPlatformError):
    """Scope validation denied the operation."""


class DuplicateTaskError(VaptPlatformError):
    """Task uniqueness constraint violated."""


class SafetyPolicyDeniedError(VaptPlatformError):
    """Test safety policy denied execution."""


class InvalidStateTransitionError(VaptPlatformError):
    """Invalid lifecycle transition."""
