"""MCP-style tool validation connectors.

The platform acts as an MCP *client* here: each connector wraps an external
security tool (nuclei CLI, Burp SSE MCP, sqlmap stdio MCP) and is used to
gather corroborating evidence for applicable vulnerability classes.
Connectors never auto-confirm findings; they produce evidence and open
validation tasks for human confirmation, preserving the assessment audit trail.
"""

from vapt_platform.validators.base import (
    ValidationConnector,
    ValidationFinding,
    ValidationOutcome,
    nuclei_tags_for_class,
)
from vapt_platform.validators.burp import BurpMcpValidator
from vapt_platform.validators.nuclei import NucleiValidator
from vapt_platform.validators.registry import build_validation_connectors
from vapt_platform.validators.sqlmap_mcp import SqlmapMcpValidator

__all__ = [
    "ValidationConnector",
    "ValidationFinding",
    "ValidationOutcome",
    "NucleiValidator",
    "BurpMcpValidator",
    "SqlmapMcpValidator",
    "build_validation_connectors",
    "nuclei_tags_for_class",
]
