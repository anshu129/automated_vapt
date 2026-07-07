"""Credential reference and authenticated coverage services."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.db.tables.models import (
    Asset,
    AuditEvent,
    AuthenticationContext,
    CredentialReference,
    CredentialScopeBinding,
    Project,
    RoleContext,
    Scan,
    ScopeRule,
)
from vapt_platform.domain.enums import (
    AssessmentMode,
    Capability,
    CredentialStatus,
    CredentialType,
)
from vapt_platform.domain.exceptions import EntityNotFoundError


class CredentialContextService:
    """Manage credential metadata and coverage without resolving secrets."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_reference(
        self,
        project_id: uuid.UUID,
        credential_type: str,
        secret_backend_reference: str,
        *,
        label: str | None = None,
        role_name: str | None = None,
        expiry: datetime | None = None,
        allowed_capabilities: list[str] | None = None,
    ) -> CredentialReference:
        if not await self.session.get(Project, project_id):
            raise EntityNotFoundError("Project not found")
        normalized_type = CredentialType(credential_type.upper()).value
        allowed = [Capability(cap).value for cap in (allowed_capabilities or [])]
        credential = CredentialReference(
            project_id=project_id,
            credential_type=normalized_type,
            label=label,
            secret_backend_reference=secret_backend_reference,
            role_name=role_name,
            expiry=expiry,
            allowed_capabilities=allowed,
            status=CredentialStatus.ACTIVE.value,
        )
        self.session.add(credential)
        await self.session.flush()
        self._audit(
            "CREDENTIAL_REFERENCE_CREATED",
            "credential_reference",
            credential.id,
            {
                "project_id": str(project_id),
                "credential_type": normalized_type,
                "role_name": role_name,
                "allowed_capabilities": allowed,
                "secret_reference_hash": _stable_ref_hash(secret_backend_reference),
            },
        )
        return credential

    async def list_project_references(self, project_id: uuid.UUID) -> list[CredentialReference]:
        stmt = select(CredentialReference).where(CredentialReference.project_id == project_id)
        return list((await self.session.execute(stmt)).scalars().all())

    async def create_binding(
        self,
        credential_id: uuid.UUID,
        *,
        scope_rule_id: uuid.UUID | None = None,
        asset_id: uuid.UUID | None = None,
        application_id: uuid.UUID | None = None,
        url_prefix: str | None = None,
        assessment_mode: str = AssessmentMode.CREDENTIALED.value,
    ) -> CredentialScopeBinding:
        credential = await self._get_reference(credential_id)
        if not any((scope_rule_id, asset_id, application_id, url_prefix)):
            raise ValueError(
                "Credential binding requires a scope rule, asset, application, or URL prefix"
            )
        if assessment_mode != AssessmentMode.CREDENTIALED.value:
            raise ValueError("Credential bindings must use CREDENTIALED assessment mode")
        await self._validate_binding_targets(
            credential,
            scope_rule_id=scope_rule_id,
            asset_id=asset_id,
            application_id=application_id,
        )
        binding = CredentialScopeBinding(
            credential_id=credential.id,
            scope_rule_id=scope_rule_id,
            asset_id=asset_id,
            application_id=application_id,
            url_prefix=url_prefix.rstrip("/") if url_prefix else None,
            assessment_mode=assessment_mode,
        )
        self.session.add(binding)
        await self.session.flush()
        self._audit(
            "CREDENTIAL_SCOPE_BOUND",
            "credential_scope_binding",
            binding.id,
            {
                "credential_id": str(credential.id),
                "scope_rule_id": str(scope_rule_id) if scope_rule_id else None,
                "asset_id": str(asset_id) if asset_id else None,
                "application_id": str(application_id) if application_id else None,
                "url_prefix": binding.url_prefix,
            },
        )
        return binding

    async def get_eligible_credentials(
        self,
        asset_id: uuid.UUID,
        capability: Capability | str,
    ) -> list[CredentialReference]:
        asset = await self.session.get(Asset, asset_id)
        if not asset:
            raise EntityNotFoundError("Asset not found")
        cap = Capability(capability).value if isinstance(capability, str) else capability.value
        credentials = list(
            (
                await self.session.execute(
                    select(CredentialReference).where(
                        CredentialReference.project_id == asset.project_id
                    )
                )
            )
            .scalars()
            .all()
        )
        eligible: list[CredentialReference] = []
        for credential in credentials:
            if not self._reference_active(credential):
                continue
            if credential.allowed_capabilities and cap not in credential.allowed_capabilities:
                continue
            if await self._credential_bound_to_asset(credential.id, asset):
                eligible.append(credential)
        return eligible

    async def bind_session(
        self,
        credential_id: uuid.UUID,
        asset_id: uuid.UUID,
        *,
        scan_id: uuid.UUID | None = None,
        session_established: bool = True,
        session_expires_at: datetime | None = None,
        coverage_dimensions: list[str] | None = None,
        coverage_status: dict[str, str] | None = None,
    ) -> AuthenticationContext:
        credential = await self._get_reference(credential_id)
        if not self._reference_active(credential):
            raise ValueError("Credential reference is not active")
        asset = await self.session.get(Asset, asset_id)
        if not asset:
            raise EntityNotFoundError("Asset not found")
        if asset.project_id != credential.project_id:
            raise ValueError("Credential and asset belong to different projects")
        if scan_id is None:
            scan_id = asset.scan_id
        scan = await self.session.get(Scan, scan_id)
        if not scan:
            raise EntityNotFoundError("Scan not found")
        if scan.project_id != credential.project_id or asset.scan_id != scan.id:
            raise ValueError("Authentication context is outside credential scope")
        if not await self._credential_bound_to_asset(credential.id, asset):
            raise ValueError("Credential is not bound to this asset")

        dimensions = list(dict.fromkeys(coverage_dimensions or ["AUTHENTICATED"]))
        context = AuthenticationContext(
            scan_id=scan.id,
            credential_id=credential.id,
            asset_id=asset.id,
            auth_method=credential.credential_type,
            session_established=session_established,
            session_expires_at=session_expires_at,
            last_validated_at=datetime.now(UTC),
            coverage_dimensions=dimensions,
        )
        self.session.add(context)
        await self.session.flush()
        if credential.role_name:
            self.session.add(
                RoleContext(
                    scan_id=scan.id,
                    authentication_context_id=context.id,
                    asset_id=asset.id,
                    role_name=credential.role_name,
                    authorized=True,
                    coverage_status=coverage_status or {dim: "COMPLETE" for dim in dimensions},
                )
            )
        self._mark_asset_credential_metadata(asset, credential, dimensions)
        self._audit(
            "AUTHENTICATION_CONTEXT_ESTABLISHED",
            "authentication_context",
            context.id,
            {
                "credential_id": str(credential.id),
                "asset_id": str(asset.id),
                "scan_id": str(scan.id),
                "role_name": credential.role_name,
                "coverage_dimensions": dimensions,
            },
        )
        return context

    async def get_auth_coverage(self, scan_id: uuid.UUID) -> dict[str, Any]:
        assets = list(
            (await self.session.execute(select(Asset).where(Asset.scan_id == scan_id)))
            .scalars()
            .all()
        )
        contexts = list(
            (
                await self.session.execute(
                    select(AuthenticationContext).where(AuthenticationContext.scan_id == scan_id)
                )
            )
            .scalars()
            .all()
        )
        roles = list(
            (await self.session.execute(select(RoleContext).where(RoleContext.scan_id == scan_id)))
            .scalars()
            .all()
        )
        contexts_by_asset: dict[uuid.UUID, list[AuthenticationContext]] = {}
        for context in contexts:
            contexts_by_asset.setdefault(context.asset_id, []).append(context)
        roles_by_asset: dict[uuid.UUID, list[RoleContext]] = {}
        for role in roles:
            roles_by_asset.setdefault(role.asset_id, []).append(role)

        items = []
        for asset in assets:
            asset_contexts = contexts_by_asset.get(asset.id, [])
            established = [ctx for ctx in asset_contexts if ctx.session_established]
            dimensions = sorted(
                {dim for ctx in established for dim in (ctx.coverage_dimensions or [])}
            )
            role_names = sorted({role.role_name for role in roles_by_asset.get(asset.id, [])})
            status = "AUTHENTICATED" if established else "UNAUTHENTICATED"
            if len(role_names) > 1:
                status = "ROLE_SPECIFIC"
            items.append(
                {
                    "asset_id": str(asset.id),
                    "asset_type": asset.asset_type,
                    "display_name": asset.display_name,
                    "auth_coverage_status": status,
                    "session_established": bool(established),
                    "coverage_dimensions": dimensions,
                    "roles": role_names,
                    "auth_context_count": len(asset_contexts),
                }
            )
        return {
            "scan_id": str(scan_id),
            "items": items,
            "total": len(items),
            "secret_values_excluded": True,
        }

    async def get_role_coverage(self, scan_id: uuid.UUID) -> dict[str, Any]:
        roles = list(
            (await self.session.execute(select(RoleContext).where(RoleContext.scan_id == scan_id)))
            .scalars()
            .all()
        )
        asset_ids = {role.asset_id for role in roles}
        assets = (
            {
                asset.id: asset
                for asset in (
                    await self.session.execute(select(Asset).where(Asset.id.in_(asset_ids)))
                ).scalars()
            }
            if asset_ids
            else {}
        )
        return {
            "scan_id": str(scan_id),
            "items": [
                {
                    "id": str(role.id),
                    "auth_context_id": str(role.authentication_context_id),
                    "asset_id": str(role.asset_id),
                    "asset": _asset_ref(assets.get(role.asset_id)),
                    "role_name": role.role_name,
                    "authorized": role.authorized,
                    "coverage_status": role.coverage_status,
                }
                for role in roles
            ],
            "total": len(roles),
            "secret_values_excluded": True,
        }

    async def _get_reference(self, credential_id: uuid.UUID) -> CredentialReference:
        credential = await self.session.get(CredentialReference, credential_id)
        if not credential:
            raise EntityNotFoundError("Credential reference not found")
        return credential

    async def _validate_binding_targets(
        self,
        credential: CredentialReference,
        *,
        scope_rule_id: uuid.UUID | None,
        asset_id: uuid.UUID | None,
        application_id: uuid.UUID | None,
    ) -> None:
        if scope_rule_id:
            rule = await self.session.get(ScopeRule, scope_rule_id)
            if not rule or rule.project_id != credential.project_id:
                raise ValueError("Scope rule is outside credential project")
        for target_id in (asset_id, application_id):
            if target_id:
                asset = await self.session.get(Asset, target_id)
                if not asset or asset.project_id != credential.project_id:
                    raise ValueError("Bound asset is outside credential project")

    async def _credential_bound_to_asset(self, credential_id: uuid.UUID, asset: Asset) -> bool:
        bindings = list(
            (
                await self.session.execute(
                    select(CredentialScopeBinding).where(
                        CredentialScopeBinding.credential_id == credential_id
                    )
                )
            )
            .scalars()
            .all()
        )
        if not bindings:
            return False
        asset_url = (asset.metadata_ or {}).get("base_url") or asset.normalized_key
        for binding in bindings:
            if binding.asset_id == asset.id or binding.application_id == asset.id:
                return True
            if binding.url_prefix and str(asset_url).startswith(binding.url_prefix):
                return True
            if binding.scope_rule_id:
                rule = await self.session.get(ScopeRule, binding.scope_rule_id)
                if rule and _rule_matches_asset(rule, asset):
                    return True
        return False

    @staticmethod
    def _reference_active(credential: CredentialReference) -> bool:
        if credential.status != CredentialStatus.ACTIVE.value:
            return False
        if credential.expiry and credential.expiry <= datetime.now(UTC):
            credential.status = CredentialStatus.EXPIRED.value
            return False
        return True

    @staticmethod
    def _mark_asset_credential_metadata(
        asset: Asset,
        credential: CredentialReference,
        dimensions: list[str],
    ) -> None:
        meta = dict(asset.metadata_ or {})
        meta["credentials_available"] = True
        meta["authenticated_coverage"] = sorted(
            set(meta.get("authenticated_coverage", [])) | set(dimensions)
        )
        if credential.role_name:
            roles = set(meta.get("authorized_roles", []))
            roles.add(credential.role_name)
            meta["authorized_roles"] = sorted(roles)
        asset.metadata_ = meta

    def _audit(
        self,
        event_type: str,
        resource_type: str,
        resource_id: uuid.UUID,
        details: dict[str, Any],
    ) -> None:
        self.session.add(
            AuditEvent(
                event_type=event_type,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details,
                correlation_id=uuid.uuid4(),
            )
        )


def credential_metadata(credential: CredentialReference) -> dict[str, Any]:
    """Return a credential reference without secret backend material."""

    return {
        "id": str(credential.id),
        "project_id": str(credential.project_id),
        "credential_type": credential.credential_type,
        "label": credential.label,
        "role_name": credential.role_name,
        "expiry": credential.expiry.isoformat() if credential.expiry else None,
        "allowed_capabilities": credential.allowed_capabilities,
        "status": credential.status,
        "created_at": credential.created_at.isoformat() if credential.created_at else None,
        "updated_at": credential.updated_at.isoformat() if credential.updated_at else None,
        "secret_backend_reference_present": bool(credential.secret_backend_reference),
    }


def binding_metadata(binding: CredentialScopeBinding) -> dict[str, Any]:
    return {
        "id": str(binding.id),
        "credential_id": str(binding.credential_id),
        "scope_rule_id": str(binding.scope_rule_id) if binding.scope_rule_id else None,
        "asset_id": str(binding.asset_id) if binding.asset_id else None,
        "application_id": str(binding.application_id) if binding.application_id else None,
        "url_prefix": binding.url_prefix,
        "assessment_mode": binding.assessment_mode,
    }


def auth_context_metadata(context: AuthenticationContext) -> dict[str, Any]:
    return {
        "id": str(context.id),
        "scan_id": str(context.scan_id),
        "credential_id": str(context.credential_id),
        "asset_id": str(context.asset_id),
        "auth_method": context.auth_method,
        "session_established": context.session_established,
        "session_expires_at": (
            context.session_expires_at.isoformat() if context.session_expires_at else None
        ),
        "last_validated_at": (
            context.last_validated_at.isoformat() if context.last_validated_at else None
        ),
        "coverage_dimensions": context.coverage_dimensions,
    }


def _stable_ref_hash(secret_backend_reference: str) -> str:
    return hashlib.sha256(secret_backend_reference.encode()).hexdigest()[:16]


def _rule_matches_asset(rule: ScopeRule, asset: Asset) -> bool:
    pattern = rule.pattern.lower().rstrip("/")
    key = asset.normalized_key.lower().rstrip("/")
    if rule.rule_type == "URL_PREFIX":
        return key.startswith(pattern)
    if rule.rule_type in {"HOSTNAME", "ROOT_DOMAIN", "SUBDOMAIN_PATTERN"}:
        host = (asset.metadata_ or {}).get("hostname") or key.replace("https://", "").split("/")[0]
        return host == pattern or host.endswith(f".{pattern}")
    return False


def _asset_ref(asset: Asset | None) -> dict[str, Any] | None:
    if not asset:
        return None
    return {
        "id": str(asset.id),
        "asset_type": asset.asset_type,
        "display_name": asset.display_name,
        "normalized_key": asset.normalized_key,
    }
