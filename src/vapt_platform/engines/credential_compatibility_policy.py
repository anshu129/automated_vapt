"""Credential compatibility checks for provider routing (Phase 2)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.db.tables.models import AuthenticationContext, CredentialReference, TestRequirement
from vapt_platform.domain.capability_provider import TestPlanContext


@dataclass
class CredentialCompatibilityDecision:
    compatible: bool
    reason_codes: list[str] = field(default_factory=list)
    credential_context_id: str | None = None
    authentication_type: str | None = None
    role_name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


_PROVIDER_AUTH_SUPPORT: dict[str, set[str]] = {
    "nuclei": {"BASIC", "HTTP_BASIC", "FORM", "WEB_FORM", "BEARER", "HTTP_BEARER", "NONE"},
    "burp_mcp": {"BASIC", "HTTP_BASIC", "FORM", "WEB_FORM", "BEARER", "HTTP_BEARER", "SESSION", "COOKIE_SESSION", "NONE"},
    "sqlmap_mcp": {"BASIC", "HTTP_BASIC", "FORM", "WEB_FORM", "BEARER", "HTTP_BEARER", "NONE"},
}


class CredentialCompatibilityPolicy:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def evaluate(
        self,
        *,
        scan_id: uuid.UUID,
        requirement: TestRequirement | None,
        plan: TestPlanContext,
        provider_id: str,
        asset_id: str | None,
    ) -> CredentialCompatibilityDecision:
        if not requirement or not requirement.credential_requirement:
            return CredentialCompatibilityDecision(compatible=True)

        if requirement.credential_requirement not in {"AUTHENTICATED", "ROLE_SPECIFIC"}:
            return CredentialCompatibilityDecision(compatible=True)

        if not asset_id:
            return CredentialCompatibilityDecision(
                compatible=False,
                reason_codes=["CREDENTIAL_CONTEXT_REQUIRED"],
            )

        contexts = list(
            (
                await self.session.execute(
                    select(AuthenticationContext, CredentialReference)
                    .join(
                        CredentialReference,
                        CredentialReference.id == AuthenticationContext.credential_id,
                    )
                    .where(
                        AuthenticationContext.scan_id == scan_id,
                        AuthenticationContext.asset_id == uuid.UUID(asset_id),
                    )
                )
            ).all()
        )
        if not contexts:
            return CredentialCompatibilityDecision(
                compatible=False,
                reason_codes=["CREDENTIAL_CONTEXT_REQUIRED"],
            )

        supported = _PROVIDER_AUTH_SUPPORT.get(provider_id, {"NONE"})
        for auth_ctx, cred_ref in contexts:
            auth_method = (auth_ctx.auth_method or cred_ref.credential_type or "NONE").upper()
            if auth_method not in supported and "NONE" not in supported:
                continue
            role_name = cred_ref.role_name
            if requirement.credential_requirement == "ROLE_SPECIFIC" and not role_name:
                continue
            return CredentialCompatibilityDecision(
                compatible=True,
                credential_context_id=str(auth_ctx.id),
                authentication_type=auth_method,
                role_name=role_name,
                metadata={"asset_id": asset_id},
            )

        return CredentialCompatibilityDecision(
            compatible=False,
            reason_codes=["CREDENTIAL_CONTEXT_INCOMPATIBLE"],
        )
