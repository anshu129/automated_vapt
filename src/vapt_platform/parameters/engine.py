"""Explainable deterministic parameter selection."""

import base64
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import yaml

from vapt_platform.parameters.context import OperationalContext
from vapt_platform.parameters.references import find_parameter_in_reference, reference_for_tool

HTTP_BASIC_HEADER_TOOLS = {
    "arjun",
    "ffuf",
    "feroxbuster",
    "httpx",
    "katana",
}


@dataclass
class ParameterDecision:
    """Auditable result of parameter rule evaluation."""

    tool: str
    base_args: list[str]
    added_args: list[str]
    final_args: list[str]
    redacted_command: str
    rule_ids: list[str]
    explanations: list[str]
    input_facts: dict[str, Any]
    reference_doc: str | None = None
    rule_version: str = "1.0"


class ParameterSelectionEngine:
    """
    Derives tool-specific CLI arguments from operational context.
    Every added flag must correlate to evidence via a versioned rule
    documented in config/parameters/references/.
    """

    def __init__(self, rules_path: Path | None = None) -> None:
        self.rules: list[dict[str, Any]] = []
        self.rule_version = "1.0"
        self._load_rules(rules_path)

    def _load_rules(self, rules_path: Path | None) -> None:
        if rules_path and rules_path.exists():
            self._ingest_rules_file(rules_path)
            return
        base = Path("config/parameters")
        legacy = base / "rules.yaml"
        rules_dir = base / "rules"
        if rules_dir.exists():
            for path in sorted(rules_dir.glob("*.yaml")):
                self._ingest_rules_file(path)
        elif legacy.exists():
            self._ingest_rules_file(legacy)

    def _ingest_rules_file(self, path: Path) -> None:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        self.rule_version = data.get("version", self.rule_version)
        self.rules.extend(data.get("rules", []))

    def derive(
        self,
        tool_name: str,
        base_args: list[str],
        target: dict[str, Any],
        context: OperationalContext,
    ) -> ParameterDecision:
        added: list[str] = []
        rule_ids: list[str] = []
        explanations: list[str] = []
        facts = context.to_dict()

        for rule in self.rules:
            if rule.get("tool") != tool_name:
                continue
            if not self._rule_matches(rule, context):
                continue
            for arg in rule.get("add_args", []):
                resolved = self._resolve_placeholders(arg, target)
                if resolved not in added and resolved not in base_args:
                    added.append(resolved)
            rule_ids.append(rule["id"])
            ref_key = rule.get("reference_param")
            explanation = rule.get("explanation", rule["id"])
            if ref_key:
                explanation = self._enrich_from_reference(tool_name, ref_key, explanation)
            explanations.append(explanation)

        auth_args = self._http_basic_auth_args(tool_name, target, base_args + added)
        if auth_args:
            for arg in auth_args:
                if arg not in added and arg not in base_args:
                    added.append(arg)
            rule_ids.append("target-http-basic-auth")
            explanations.append("HTTP Basic credentials were provided for this target.")

        final = self._merge_args(tool_name, base_args, added)
        final = [self._resolve_placeholders(a, target) for a in final]
        redacted = self._redact_command(tool_name, final, target)
        ref = reference_for_tool(tool_name)
        doc_url = None
        if ref and ref.get("official_docs"):
            docs = ref["official_docs"]
            doc_url = docs[0] if isinstance(docs, list) else docs

        return ParameterDecision(
            tool=tool_name,
            base_args=list(base_args),
            added_args=added,
            final_args=final,
            redacted_command=redacted,
            rule_ids=rule_ids,
            explanations=explanations,
            input_facts=facts,
            reference_doc=doc_url,
            rule_version=self.rule_version,
        )

    def _enrich_from_reference(self, tool: str, param_key: str, fallback: str) -> str:
        param = find_parameter_in_reference(tool, param_key)
        if param:
            return param.get("rationale") or param.get("description") or fallback
        return fallback

    def _rule_matches(self, rule: dict[str, Any], ctx: OperationalContext) -> bool:
        if rule.get("never"):
            return False
        when = rule.get("when", {})
        if when.get("always"):
            return True

        if caps := when.get("capability_in"):
            if ctx.capability not in caps:
                return False
        elif cap := when.get("capability"):
            if ctx.capability != cap:
                return False

        if profiles := when.get("profile_in"):
            if ctx.execution_profile not in profiles:
                return False

        if when.get("never"):
            return False

        if when.get("passive_only") and not ctx.passive_only:
            return False

        if min_t := when.get("min_previous_timeouts"):
            if ctx.previous_timeouts < int(min_t):
                return False

        if codes := when.get("reason_code_in"):
            if not any(c in ctx.reason_codes for c in codes):
                return False

        flags = self._context_flags(ctx)

        if none_of := when.get("none_of"):
            if any(flags.get(k, False) for k in none_of):
                return False

        if any_of := when.get("any_of"):
            if not any(flags.get(k, False) for k in any_of):
                return False

        if all_of := when.get("all_of"):
            if not all(flags.get(k, False) for k in all_of):
                return False

        return bool(
            when.get("always")
            or when.get("capability")
            or when.get("capability_in")
            or when.get("profile_in")
            or when.get("any_of")
            or when.get("all_of")
            or when.get("passive_only")
            or when.get("min_previous_timeouts")
            or when.get("reason_code_in")
        )

    @staticmethod
    def _context_flags(ctx: OperationalContext) -> dict[str, bool]:
        return {
            "waf_detected": ctx.waf_detected,
            "firewall_inferred": ctx.firewall_inferred,
            "icmp_blocked": ctx.icmp_blocked,
            "filtered_ports_observed": ctx.filtered_ports_observed,
            "proxy_arp_suspected": ctx.proxy_arp_suspected,
            "local_network_target": ctx.local_network_target,
            "cdn_detected": ctx.cdn_detected,
            "rate_limited": ctx.rate_limited,
            "auth_required": ctx.auth_required,
            "tls_enforced": ctx.tls_enforced,
            "http_only_service": ctx.http_only_service,
            "wildcard_dns_suspected": ctx.wildcard_dns_suspected,
            "inconclusive_dns": ctx.inconclusive_dns,
            "low_subdomain_gain": ctx.low_subdomain_gain,
            "large_target_set": ctx.large_target_set,
            "cidr_scope": ctx.cidr_scope,
            "api_surface_detected": ctx.api_surface_detected,
            "cloud_asset_candidate": ctx.cloud_asset_candidate,
            "graphql_endpoint": ctx.graphql_endpoint,
            "passive_only": ctx.passive_only,
        }

    def _resolve_placeholders(self, arg: str, target: dict[str, Any]) -> str:
        hostname = target.get("hostname") or target.get("ip", "")
        domain = target.get("domain", hostname)
        url = target.get("url", f"https://{hostname}" if hostname else "")
        ip = target.get("ip", "")
        username, password = self._credentials_from_target(target)
        basic_auth_token = (
            base64.b64encode(f"{username}:{password}".encode()).decode()
            if username is not None and password is not None
            else ""
        )
        token = target.get("token", "")
        wordlist = target.get("wordlist", "config/wordlists/common.txt")
        resolvers = target.get("resolvers", "config/resolvers.txt")
        targets_file = target.get("targets_file", "")
        hosts_file = target.get("hosts_file", targets_file)
        output = target.get("output", "-")
        path = target.get("path", ".")
        payload = target.get("payload", "FUZZ")
        pattern = target.get("pattern", "xss")
        return (
            arg.replace("{hostname}", hostname)
            .replace("{domain}", domain)
            .replace("{url}", url)
            .replace("{target}", ip or hostname or domain)
            .replace("{ip}", ip)
            .replace("{username}", username or "")
            .replace("{password}", password or "")
            .replace("{basic_auth_token}", basic_auth_token)
            .replace("{token}", token)
            .replace("{wordlist}", wordlist)
            .replace("{resolvers}", resolvers)
            .replace("{targets_file}", targets_file)
            .replace("{hosts_file}", hosts_file)
            .replace("{output}", output)
            .replace("{path}", path)
            .replace("{payload}", payload)
            .replace("{pattern}", pattern)
        )

    def _http_basic_auth_args(
        self,
        tool: str,
        target: dict[str, Any],
        existing_args: list[str],
    ) -> list[str]:
        if tool not in HTTP_BASIC_HEADER_TOOLS:
            return []
        username, password = self._credentials_from_target(target)
        if username is None or password is None:
            return []
        if any("authorization:" in arg.lower() for arg in existing_args):
            return []
        return ["-H", "Authorization: Basic {basic_auth_token}"]

    @staticmethod
    def _credentials_from_target(target: dict[str, Any]) -> tuple[str | None, str | None]:
        username = target.get("username")
        password = target.get("password")
        url = target.get("url") or ""
        parsed = urlparse(url) if "://" in url else None
        if parsed and parsed.username and username is None:
            username = unquote(parsed.username)
        if parsed and parsed.password and password is None:
            password = unquote(parsed.password)
        return username, password

    def _merge_args(self, tool: str, base: list[str], added: list[str]) -> list[str]:
        if tool == "nmap":
            result = list(base)
            for flag in added:
                if flag not in result:
                    result.insert(0, flag) if flag.startswith("-") else result.append(flag)
            return result
        return base + added

    def _redact_command(self, tool: str, args: list[str], target: dict[str, Any]) -> str:
        username, password = self._credentials_from_target(target)
        safe = []
        skip_next = False
        for a in args:
            if skip_next:
                skip_next = False
                safe.append("***")
                continue
            if a in ("-api-key", "--api-key", "-token", "--token", "--password"):
                skip_next = True
                safe.append(a)
            elif "authorization:" in a.lower():
                safe.append("Authorization: ***")
            else:
                redacted = re.sub(r"://([^:/@\s]+):([^/@\s]+)@", r"://***:***@", a)
                if password:
                    if redacted == password:
                        redacted = "***"
                    redacted = re.sub(
                        rf"(?i)(password=){re.escape(password)}",
                        r"\1***",
                        redacted,
                    )
                if username and password:
                    redacted = redacted.replace(f"{username}:***", "***:***")
                safe.append(redacted)
        return f"{tool} {' '.join(safe)}"
