"""Deterministic report content hashing (Phase 7/8)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

_VOLATILE_HASH_KEYS = {
    "evaluation_timestamp",
    "generated_at",
    "created_at",
    "updated_at",
    "report_snapshot",
    "report_delivery",
}


def canonical_report_for_hash(report: dict[str, Any]) -> dict[str, Any]:
    def _strip(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: _strip(v) for k, v in obj.items() if k not in _VOLATILE_HASH_KEYS}
        if isinstance(obj, list):
            return [_strip(item) for item in obj]
        return obj

    return _strip(report)


def compute_report_content_hash(report: dict[str, Any]) -> str:
    canonical = canonical_report_for_hash(report)
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def compute_live_fingerprint_hash(fingerprint: dict[str, Any]) -> str:
    payload = json.dumps(fingerprint, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()
