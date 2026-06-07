"""Compliance & Security Agent service (AGENT-015).

The Compliance & Security Agent is a *type config* that plugs into the Worker
Agent Framework (AGENT-003). It owns:

* security_config storage/validation on the ``agent_types`` table
* security finding CRUD + status workflow on the ``compliance_security_findings`` table
* periodic / manual audit lifecycle on the ``compliance_security_audits`` table
* deterministic, mockable scanning lifecycle (PR review + full audit) so E2E is
  reproducible
* finding-trend aggregation + per-framework compliance status
* auto-creation of remediation tickets (``type:security``) on high/critical findings

Real scanning execution (cloning the repo, running secret/dependency scanners,
git/PR operations) is gated behind ``S.compliance_agent_execute_commands``.
When disabled (the default, and always in E2E), the workflow is generated and
its transitions are driven in-memory so tests are deterministic.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.core.validate_url import validate_repo_url
from app.services import tickets as tickets_svc

logger = logging.getLogger("app.agent_compliance")

COMPLIANCE_AGENT_TYPE = "compliance"

# ---------------------------------------------------------------------------
# Enums / vocab
# ---------------------------------------------------------------------------

SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SOURCES = ("pr_review", "ticket_review", "periodic_audit", "manual_scan")

# open is the initial state; the rest are reachable via the status workflow.
FINDING_STATUSES = ("open", "acknowledged", "remediated", "false_positive", "accepted_risk")
# Statuses settable via the status-update endpoint (open is implicit at creation).
_SETTABLE_STATUSES = ("acknowledged", "remediated", "false_positive", "accepted_risk")
_TERMINAL_STATUSES = ("remediated", "false_positive", "accepted_risk")

AUDIT_STATUSES = ("running", "completed", "failed")

# OWASP + compliance finding categories (ticket §3.1.4).
CATEGORIES = (
    # OWASP Top 10
    "injection",
    "broken_auth",
    "xss",
    "insecure_design",
    "security_misconfig",
    "vulnerable_components",
    "crypto_failure",
    "access_control",
    "logging_monitoring",
    "ssrf",
    # GDPR
    "gdpr_pii",
    "gdpr_rights",
    # PCI DSS
    "pci_card_data",
    "pci_transmission",
    # WCAG
    "wcag_contrast",
    "wcag_keyboard",
    "wcag_aria",
)

_CATEGORY_FRAMEWORK = {
    "injection": "owasp_top_10",
    "broken_auth": "owasp_top_10",
    "xss": "owasp_top_10",
    "insecure_design": "owasp_top_10",
    "security_misconfig": "owasp_top_10",
    "vulnerable_components": "owasp_top_10",
    "crypto_failure": "owasp_top_10",
    "access_control": "owasp_top_10",
    "logging_monitoring": "owasp_top_10",
    "ssrf": "owasp_top_10",
    "gdpr_pii": "gdpr",
    "gdpr_rights": "gdpr",
    "pci_card_data": "pci_dss",
    "pci_transmission": "pci_dss",
    "wcag_contrast": "wcag",
    "wcag_keyboard": "wcag",
    "wcag_aria": "wcag",
}

_FRAMEWORK_NAMES = {
    "owasp_top_10": "OWASP Top 10",
    "gdpr": "GDPR",
    "pci_dss": "PCI DSS",
    "wcag": "WCAG",
}

_DESCRIPTION_MAX = 5000
_TITLE_MAX = 200
_CODE_SNIPPET_MAX = 1000
_REMEDIATION_MAX = 2000

_DEFAULT_SECURITY_CONFIG: Dict[str, Any] = {
    "scan_on_pr": True,
    "scan_on_ticket_update": True,
    "block_merge_on_critical": True,
    "block_merge_on_high": False,
    "periodic_audit_frequency": "weekly",
    "periodic_audit_day": "sunday",
    "periodic_audit_hour_utc": 2,
    "compliance_frameworks": ["owasp_top_10", "gdpr", "pci_dss"],
    "wcag_level": "AA",
    "severity_thresholds": {
        "hardcoded_secret": "critical",
        "sql_injection": "critical",
        "xss": "high",
        "insecure_auth": "high",
        "missing_csrf": "high",
        "pii_logging": "high",
        "missing_input_validation": "medium",
        "insecure_dependency": "medium",
        "missing_rate_limit": "low",
    },
    "ignored_paths": ["node_modules/", ".venv/", "tests/", "frontend/e2e/"],
    "auto_create_remediation_tickets": True,
    "remediation_ticket_min_severity": "high",
    # GAP-0101: SSRF allowlist for repo URLs touched by the agent. Only repos
    # whose host matches one of these entries (exact or subdomain) may be cloned
    # / have PRs created against them when real execution is enabled.
    "allowed_repo_hosts": ["github.com", "gitlab.com"],
    # GAP-0102: indirection for the GitHub credential. This stores ONLY the name
    # / ARN of an AWS Secrets Manager secret, never the raw token. The raw token
    # is resolved at execution time and is never persisted in DDB nor returned in
    # any API response.
    "github_token_secret_name": "",
}

# Fields that are persisted to DynamoDB. ``github_token`` (the raw token) is
# intentionally NOT a config field and must never be added here (GAP-0102).
_CONFIG_FIELDS = tuple(_DEFAULT_SECURITY_CONFIG.keys())


# ---------------------------------------------------------------------------
# Table bootstrap (idempotent; tables are additive per AGENT-001/015)
# ---------------------------------------------------------------------------

_BOOTSTRAPPED = False


def ensure_tables() -> None:
    """Create the agent_types / findings / audits tables on first use if absent.

    The shared local-ddb-init script is the canonical place tables are defined,
    but the compliance feature is fully self-contained so it works in any
    environment (E2E live DDB, fresh stacks) without requiring a stack re-init.
    """
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    client = ddb.meta.client
    specs = [
        (
            S.agent_types_table_name,
            [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            None,
        ),
        (
            S.compliance_security_findings_table_name,
            [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "N"},
                {"AttributeName": "GSI2PK", "AttributeType": "S"},
                {"AttributeName": "GSI2SK", "AttributeType": "N"},
                {"AttributeName": "GSI3PK", "AttributeType": "S"},
                {"AttributeName": "GSI3SK", "AttributeType": "N"},
            ],
            [
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI2",
                    "KeySchema": [
                        {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI3",
                    "KeySchema": [
                        {"AttributeName": "GSI3PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI3SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
        ),
        (
            S.compliance_security_audits_table_name,
            [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "N"},
            ],
            [
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
        ),
    ]
    for name, key_schema, attr_defs, gsi in specs:
        kwargs: Dict[str, Any] = {
            "TableName": name,
            "KeySchema": key_schema,
            "AttributeDefinitions": attr_defs,
            "BillingMode": "PAY_PER_REQUEST",
        }
        if gsi:
            kwargs["GlobalSecondaryIndexes"] = gsi
        try:
            client.create_table(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ResourceInUseException",):
                logger.warning("ensure_tables: could not create %s: %s", name, exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("ensure_tables: %s create error: %s", name, exc)
    _BOOTSTRAPPED = True


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def _user_pk(user_id: str) -> str:
    return f"USER#{user_id}"


def _finding_sk(finding_id: str) -> str:
    return f"FINDING#{finding_id}"


def _audit_sk(audit_id: str) -> str:
    return f"AUDIT#{audit_id}"


def _type_pk(type_id: str) -> str:
    return f"TYPE#{type_id}"


def _coerce_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity, -1)


# ---------------------------------------------------------------------------
# Configuration (security_config on agent_types record)
# ---------------------------------------------------------------------------


def validate_security_config(config: Dict[str, Any]) -> List[str]:
    """Return a list of validation errors (empty = valid)."""
    errors: List[str] = []

    freq = config.get("periodic_audit_frequency")
    if freq is not None and freq not in ("daily", "weekly", "biweekly", "monthly"):
        errors.append("periodic_audit_frequency must be daily, weekly, biweekly, or monthly")

    hour = config.get("periodic_audit_hour_utc")
    if hour is not None:
        h = _coerce_int(hour)
        if h is None or h < 0 or h > 23:
            errors.append("periodic_audit_hour_utc must be between 0 and 23")

    frameworks = config.get("compliance_frameworks")
    if frameworks is not None:
        if not isinstance(frameworks, list):
            errors.append("compliance_frameworks must be a list")
        else:
            for fw in frameworks:
                if fw not in ("owasp_top_10", "gdpr", "pci_dss", "wcag"):
                    errors.append(f"Invalid compliance framework: {fw}")

    wcag = config.get("wcag_level")
    if wcag is not None and wcag not in ("A", "AA", "AAA"):
        errors.append("wcag_level must be A, AA, or AAA")

    thresholds = config.get("severity_thresholds")
    if thresholds is not None:
        if not isinstance(thresholds, dict):
            errors.append("severity_thresholds must be an object")
        else:
            for key, val in thresholds.items():
                if val not in SEVERITIES:
                    errors.append(f"severity_thresholds[{key}] must be a valid severity")

    ignored = config.get("ignored_paths")
    if ignored is not None and not isinstance(ignored, list):
        errors.append("ignored_paths must be a list")

    min_sev = config.get("remediation_ticket_min_severity")
    if min_sev is not None and min_sev not in ("critical", "high", "medium", "low"):
        errors.append("remediation_ticket_min_severity must be critical, high, medium, or low")

    hosts = config.get("allowed_repo_hosts")
    if hosts is not None:
        if not isinstance(hosts, list) or not all(isinstance(h, str) for h in hosts):
            errors.append("allowed_repo_hosts must be a list of strings")

    secret_name = config.get("github_token_secret_name")
    if secret_name is not None and not isinstance(secret_name, str):
        errors.append("github_token_secret_name must be a string")

    # GAP-0102: the raw token must never be accepted through the config API.
    if "github_token" in config:
        errors.append("github_token must not be stored in config; use github_token_secret_name")

    return errors


def _normalize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = dict(_DEFAULT_SECURITY_CONFIG)
    for key in _CONFIG_FIELDS:
        if key in config and config[key] is not None:
            out[key] = config[key]
    hour = _coerce_int(out.get("periodic_audit_hour_utc"))
    if hour is not None:
        out["periodic_audit_hour_utc"] = hour
    # GAP-0102: the raw token must never round-trip through the persisted config.
    # Strip it defensively in case a caller ever smuggles it into the dict.
    out.pop("github_token", None)
    return out


# ---------------------------------------------------------------------------
# GAP-0101: repo_url host allowlist validation (SSRF guard)
# ---------------------------------------------------------------------------


def validate_repo_host(repo_url: str, allowed_hosts: List[str]) -> str:
    """Validate ``repo_url`` for shell safety AND host allowlisting (GAP-0101).

    Reuses :func:`app.core.validate_url.validate_repo_url` to reject shell
    metacharacters / dangerous protocols / control chars, then enforces that the
    URL's hostname is in ``allowed_hosts`` (exact match or a subdomain of an
    allowed host). This blocks SSRF to attacker-controlled or internal hosts
    (e.g. ``169.254.169.254``, internal VPC endpoints) before any clone / PR /
    token usage.

    Empty input is allowed (CLI mode makes no outbound call); returns the URL
    unchanged when valid; raises ``ValueError`` otherwise.
    """
    if not repo_url:
        return repo_url
    # Shell-safety / protocol checks first (raises ValueError on failure).
    validate_repo_url(repo_url)
    try:
        parsed = urlparse(repo_url)
    except Exception as exc:  # pragma: no cover - urlparse rarely raises
        raise ValueError(f"invalid_repo_url: could not parse {repo_url!r}") from exc
    # git@host:owner/repo SSH form has no scheme://; extract the host manually.
    host = (parsed.hostname or "").lower()
    if not host and repo_url.startswith("git@"):
        host = repo_url[len("git@"):].split(":", 1)[0].split("/", 1)[0].lower()
    allowed = [h.lower() for h in (allowed_hosts or [])]
    if not any(host == a or host.endswith("." + a) for a in allowed):
        logger.warning("repo_url validation rejected host=%r", host)
        raise ValueError(f"repo_url host {host!r} is not in allowed_repo_hosts")
    return repo_url


# ---------------------------------------------------------------------------
# GAP-0102: GitHub token resolution via Secrets Manager indirection
# ---------------------------------------------------------------------------


def resolve_github_token(*, user_id: str) -> str:
    """Resolve the raw GitHub token at execution time (GAP-0102).

    Dev/prod parity (SECOPS-007): both environments run the same code path.

    * In dev mode the token comes from the ``GITHUB_TOKEN`` env var
      (``S.github_token``) — empty by default, no Secrets Manager call.
    * In prod the per-user ``github_token_secret_name`` (falling back to the
      platform-level ``S.github_token_secret_name`` env var) names an AWS Secrets
      Manager secret; the raw token is fetched via ``get_secret_value``.

    The raw token is NEVER stored in DynamoDB nor returned in API responses.
    Returns an empty string when no secret/token is configured.
    """
    if S.dev_mode:
        return S.github_token
    cfg = get_effective_config(user_id=user_id)
    secret_name = cfg.get("github_token_secret_name") or ""
    if not secret_name:
        secret_name = getattr(S, "github_token_secret_name", "") or os.environ.get(
            "GITHUB_TOKEN_SECRET_NAME", ""
        )
    if not secret_name:
        return ""
    import boto3  # local import: avoids a hard dependency at module import time

    sm = boto3.client("secretsmanager")
    resp = sm.get_secret_value(SecretId=secret_name)
    return resp.get("SecretString", "") or ""


def config_response_dict(config: Dict[str, Any]) -> Dict[str, Any]:
    """Project a stored/effective config into the shape returned by the API.

    GAP-0102: derives the ``has_github_token`` boolean indicator and guarantees
    the raw ``github_token`` is never present in the response. ``has_github_token``
    is true when a Secrets Manager reference is configured (per-user or
    platform-level) or, in dev, when the ``GITHUB_TOKEN`` env var is set.
    """
    out = dict(config or {})
    out.pop("github_token", None)
    secret_name = out.get("github_token_secret_name") or getattr(
        S, "github_token_secret_name", ""
    )
    has_token = bool(secret_name)
    if S.dev_mode and S.github_token:
        has_token = True
    out["has_github_token"] = has_token
    return out


def get_agent_type(*, agent_type_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_types.get_item(Key={"pk": _type_pk(agent_type_id), "sk": "META"})
    return resp.get("Item")


def _create_agent_type(*, agent_type_id: str, owner_sub: str, name: str = "") -> Dict[str, Any]:
    ensure_tables()
    ts = now_ts()
    item = {
        "pk": _type_pk(agent_type_id),
        "sk": "META",
        "agent_type_id": agent_type_id,
        "agent_type": COMPLIANCE_AGENT_TYPE,
        "name": name or agent_type_id,
        "owner_sub": owner_sub,
        "created_at": ts,
        "updated_at": ts,
    }
    T.agent_types.put_item(Item=item)
    return item


def get_security_config(*, agent_type_id: str) -> Optional[Dict[str, Any]]:
    """Fetch security_config from agent_types table (CONFIG item)."""
    ensure_tables()
    resp = T.agent_types.get_item(Key={"pk": _type_pk(agent_type_id), "sk": "CONFIG"})
    item = resp.get("Item")
    if not item:
        return None
    config = item.get("security_config")
    if not config:
        return None
    return _normalize_config(config)


def update_security_config(
    *, agent_type_id: str, owner_sub: str, config: Dict[str, Any]
) -> Dict[str, Any]:
    """Validate, merge over existing/defaults, and persist security_config.

    Auto-creates the type META if absent. Only provided keys are overridden so
    PATCH-style partial updates work.
    """
    ensure_tables()
    if get_agent_type(agent_type_id=agent_type_id) is None:
        _create_agent_type(agent_type_id=agent_type_id, owner_sub=owner_sub)
    existing = get_security_config(agent_type_id=agent_type_id) or dict(_DEFAULT_SECURITY_CONFIG)
    merged = dict(existing)
    for key in _CONFIG_FIELDS:
        if key in config and config[key] is not None:
            merged[key] = config[key]
    normalized = _normalize_config(merged)
    ts = now_ts()
    T.agent_types.put_item(
        Item={
            "pk": _type_pk(agent_type_id),
            "sk": "CONFIG",
            "agent_type_id": agent_type_id,
            "agent_type": COMPLIANCE_AGENT_TYPE,
            "owner_sub": owner_sub,
            "security_config": normalized,
            "updated_at": ts,
        }
    )
    T.agent_types.update_item(
        Key={"pk": _type_pk(agent_type_id), "sk": "META"},
        UpdateExpression="SET agent_type = :t, updated_at = :u",
        ExpressionAttributeValues={":t": COMPLIANCE_AGENT_TYPE, ":u": ts},
    )
    result = dict(normalized)
    result["updated_at"] = ts
    return result


def get_effective_config(*, user_id: str) -> Dict[str, Any]:
    """Return the user's security config, falling back to defaults.

    Looks up a per-user agent type (``compliance_{user_id}``) first; if no
    config has been saved, the platform defaults are used. This keeps findings
    creation working before any explicit config save.
    """
    cfg = get_security_config(agent_type_id=f"{COMPLIANCE_AGENT_TYPE}_{user_id}")
    if cfg:
        return cfg
    return dict(_DEFAULT_SECURITY_CONFIG)


def config_schema() -> Dict[str, Any]:
    """Return a lightweight JSON schema describing security_config fields."""
    return {
        "fields": {
            "scan_on_pr": {"type": "boolean", "default": True},
            "scan_on_ticket_update": {"type": "boolean", "default": True},
            "block_merge_on_critical": {"type": "boolean", "default": True},
            "block_merge_on_high": {"type": "boolean", "default": False},
            "periodic_audit_frequency": {
                "type": "enum",
                "values": ["daily", "weekly", "biweekly", "monthly"],
                "default": "weekly",
            },
            "periodic_audit_day": {"type": "string", "default": "sunday"},
            "periodic_audit_hour_utc": {"type": "integer", "min": 0, "max": 23, "default": 2},
            "compliance_frameworks": {
                "type": "array",
                "items": ["owasp_top_10", "gdpr", "pci_dss", "wcag"],
            },
            "wcag_level": {"type": "enum", "values": ["A", "AA", "AAA"], "default": "AA"},
            "severity_thresholds": {"type": "object"},
            "ignored_paths": {"type": "array", "items": "string"},
            "auto_create_remediation_tickets": {"type": "boolean", "default": True},
            "remediation_ticket_min_severity": {
                "type": "enum",
                "values": ["critical", "high", "medium", "low"],
                "default": "high",
            },
        },
        "categories": list(CATEGORIES),
        "severities": list(SEVERITIES),
    }


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def _finding_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Project a raw DDB item to the API finding shape."""
    out: Dict[str, Any] = {
        "finding_id": item.get("finding_id", ""),
        "agent_id": item.get("agent_id", ""),
        "source": item.get("source", ""),
        "source_ref": item.get("source_ref", ""),
        "severity": item.get("severity", ""),
        "category": item.get("category", ""),
        "title": item.get("title", ""),
        "description": item.get("description", ""),
        "remediation": item.get("remediation", "") or "",
        "status": item.get("status", "open"),
        "created_at": int(item.get("created_at", 0) or 0),
    }
    for opt in ("file_path", "line_range", "code_snippet", "remediation_ticket_id"):
        if item.get(opt):
            out[opt] = item.get(opt)
    resolved = _coerce_int(item.get("resolved_at"))
    if resolved is not None:
        out["resolved_at"] = resolved
    if item.get("note"):
        out["note"] = item.get("note")
    return out


def create_finding(
    *,
    user_id: str,
    agent_id: str,
    source: str,
    source_ref: str,
    severity: str,
    category: str,
    title: str,
    description: str,
    file_path: Optional[str] = None,
    line_range: Optional[str] = None,
    code_snippet: Optional[str] = None,
    remediation: str = "",
) -> Dict[str, Any]:
    """Create a security finding from an agent review.

    Raises ValueError("invalid_severity") / ValueError("invalid_category") /
    ValueError("invalid_source") on bad enums.
    """
    ensure_tables()
    if severity not in SEVERITIES:
        raise ValueError("invalid_severity")
    if category not in CATEGORIES:
        raise ValueError("invalid_category")
    if source not in SOURCES:
        raise ValueError("invalid_source")

    finding_id = uuid.uuid4().hex
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _user_pk(user_id),
        "sk": _finding_sk(finding_id),
        "finding_id": finding_id,
        "user_id": user_id,
        "agent_id": agent_id,
        "source": source,
        "source_ref": source_ref,
        "severity": severity,
        "category": category,
        "title": (title or "")[:_TITLE_MAX],
        "description": (description or "")[:_DESCRIPTION_MAX],
        "remediation": (remediation or "")[:_REMEDIATION_MAX],
        "status": "open",
        "created_at": ts,
        "GSI1PK": f"USER#{user_id}#SEVERITY#{severity}",
        "GSI1SK": ts,
        "GSI2PK": f"USER#{user_id}#STATUS#open",
        "GSI2SK": ts,
        "GSI3PK": f"USER#{user_id}#SOURCE#{source_ref}",
        "GSI3SK": ts,
    }
    if file_path:
        item["file_path"] = file_path
    if line_range:
        item["line_range"] = line_range
    if code_snippet:
        item["code_snippet"] = code_snippet[:_CODE_SNIPPET_MAX]

    # Auto-create remediation ticket if config + severity threshold warrant it.
    config = get_effective_config(user_id=user_id)
    if config.get("auto_create_remediation_tickets"):
        min_sev = config.get("remediation_ticket_min_severity", "high")
        if severity_rank(severity) >= severity_rank(min_sev):
            try:
                ticket = tickets_svc.STORE.create_ticket(
                    owner_sub=user_id,
                    subject=f"[security/{severity}] {item['title']}",
                    description=_remediation_ticket_body(item, remediation),
                    category="security",
                    labels=["type:security", f"severity:{severity}", f"category:{category}"],
                    metadata={"finding_id": finding_id, "source_ref": source_ref},
                )
                item["remediation_ticket_id"] = ticket.get("ticket_id")
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("create_finding: remediation ticket failed: %s", exc)

    T.compliance_findings.put_item(Item=item)
    return _finding_to_out(item)


def _remediation_ticket_body(item: Dict[str, Any], remediation: str) -> str:
    parts = [
        item.get("description", ""),
        "",
        f"Severity: {item.get('severity')}",
        f"Category: {item.get('category')}",
    ]
    if item.get("file_path"):
        loc = item["file_path"]
        if item.get("line_range"):
            loc += f":{item['line_range']}"
        parts.append(f"Location: {loc}")
    if remediation:
        parts += ["", "Suggested remediation:", remediation]
    return "\n".join(parts)


def get_finding(*, user_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.compliance_findings.get_item(
        Key={"pk": _user_pk(user_id), "sk": _finding_sk(finding_id)}
    )
    item = resp.get("Item")
    if not item:
        return None
    return _finding_to_out(item)


def list_findings(
    *,
    user_id: str,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source_ref: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List findings filtered by severity, status, or source_ref.

    Uses the most-selective GSI available for the supplied filter; otherwise a
    base-table query on the user's partition. Validates severity/status enums.
    """
    ensure_tables()
    if severity is not None and severity not in SEVERITIES:
        raise ValueError("invalid_severity")
    if status is not None and status not in FINDING_STATUSES:
        raise ValueError("invalid_status")

    limit = max(1, min(int(limit or 50), 200))
    start_key = decode_cursor(cursor)

    query_kwargs: Dict[str, Any] = {
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if start_key:
        query_kwargs["ExclusiveStartKey"] = start_key

    extra_filter_severity: Optional[str] = None
    extra_filter_status: Optional[str] = None

    if severity is not None:
        query_kwargs["IndexName"] = "GSI1"
        query_kwargs["KeyConditionExpression"] = "GSI1PK = :pk"
        query_kwargs["ExpressionAttributeValues"] = {
            ":pk": f"USER#{user_id}#SEVERITY#{severity}"
        }
        extra_filter_status = status
    elif status is not None:
        query_kwargs["IndexName"] = "GSI2"
        query_kwargs["KeyConditionExpression"] = "GSI2PK = :pk"
        query_kwargs["ExpressionAttributeValues"] = {
            ":pk": f"USER#{user_id}#STATUS#{status}"
        }
    elif source_ref is not None:
        query_kwargs["IndexName"] = "GSI3"
        query_kwargs["KeyConditionExpression"] = "GSI3PK = :pk"
        query_kwargs["ExpressionAttributeValues"] = {
            ":pk": f"USER#{user_id}#SOURCE#{source_ref}"
        }
    else:
        query_kwargs["KeyConditionExpression"] = "pk = :pk AND begins_with(sk, :sk)"
        query_kwargs["ExpressionAttributeValues"] = {
            ":pk": _user_pk(user_id),
            ":sk": "FINDING#",
        }

    resp = T.compliance_findings.query(**query_kwargs)
    items = resp.get("Items", [])
    findings: List[Dict[str, Any]] = []
    for it in items:
        if extra_filter_status and it.get("status") != extra_filter_status:
            continue
        if extra_filter_severity and it.get("severity") != extra_filter_severity:
            continue
        findings.append(_finding_to_out(it))

    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"findings": findings, "count": len(findings), "next_cursor": next_cursor}


def update_finding_status(
    *, user_id: str, finding_id: str, status: str, note: Optional[str] = None
) -> Dict[str, Any]:
    """Update finding status (acknowledge, remediate, false positive, accepted risk).

    Raises LookupError if missing, ValueError("invalid_status") on bad enum, and
    ValueError("invalid_transition") when the finding is already in a terminal
    state.
    """
    ensure_tables()
    if status not in _SETTABLE_STATUSES:
        raise ValueError("invalid_status")
    resp = T.compliance_findings.get_item(
        Key={"pk": _user_pk(user_id), "sk": _finding_sk(finding_id)}
    )
    item = resp.get("Item")
    if not item:
        raise LookupError("finding_not_found")
    current = item.get("status", "open")
    if current in _TERMINAL_STATUSES and current != status:
        raise ValueError("invalid_transition")

    ts = now_ts()
    update_parts = ["#st = :s", "GSI2PK = :g2pk"]
    names = {"#st": "status"}
    values: Dict[str, Any] = {
        ":s": status,
        ":g2pk": f"USER#{user_id}#STATUS#{status}",
    }
    if note is not None:
        update_parts.append("note = :n")
        values[":n"] = note[:1000]
    if status == "remediated":
        update_parts.append("resolved_at = :r")
        values[":r"] = ts
    update_parts.append("updated_at = :u")
    values[":u"] = ts

    T.compliance_findings.update_item(
        Key={"pk": _user_pk(user_id), "sk": _finding_sk(finding_id)},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )
    updated = T.compliance_findings.get_item(
        Key={"pk": _user_pk(user_id), "sk": _finding_sk(finding_id)}
    ).get("Item", {})
    return _finding_to_out(updated)


def verify_remediation(*, user_id: str, finding_id: str, agent_id: str) -> Dict[str, Any]:
    """Return the context an agent needs to re-check a remediation ticket fix."""
    finding = get_finding(user_id=user_id, finding_id=finding_id)
    if finding is None:
        raise LookupError("finding_not_found")
    ticket_id = finding.get("remediation_ticket_id")
    ticket = tickets_svc.STORE.get_ticket(ticket_id) if ticket_id else None
    return {
        "finding": finding,
        "agent_id": agent_id,
        "remediation_ticket_id": ticket_id,
        "ticket_status": ticket.get("status") if ticket else None,
        "recheck_target": {
            "file_path": finding.get("file_path"),
            "line_range": finding.get("line_range"),
            "category": finding.get("category"),
        },
    }


# ---------------------------------------------------------------------------
# Audits
# ---------------------------------------------------------------------------


def _audit_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    counts = item.get("finding_counts") or {}
    compliance = item.get("compliance_summary") or {}
    out: Dict[str, Any] = {
        "audit_id": item.get("audit_id", ""),
        "agent_id": item.get("agent_id", ""),
        "worker_id": item.get("worker_id", ""),
        "status": item.get("status", ""),
        "started_at": int(item.get("started_at", 0) or 0),
        "finding_counts": {k: int(v) for k, v in counts.items()},
        "files_scanned": int(item.get("files_scanned", 0) or 0),
        "compliance_summary": compliance,
    }
    completed = _coerce_int(item.get("completed_at"))
    if completed is not None:
        out["completed_at"] = completed
    if item.get("report_s3_key"):
        out["report_s3_key"] = item.get("report_s3_key")
    return out


# Per-user "a running audit exists" lock. A stable SK lets us claim it with an
# atomic conditional write so two concurrent start_audit calls cannot both
# create a running audit (GAP-0100 TOCTOU fix). ``ttl`` enables DynamoDB TTL
# auto-expiry so a stale lock (worker crash before complete_audit) is reclaimed.
_RUNNING_LOCK_SK = "RUNNING_LOCK"
_LOCK_TTL_SECONDS = 3600  # 1 hour: covers the longest expected audit


def _acquire_audit_lock(*, user_id: str) -> bool:
    """Atomically acquire the per-user running-audit lock.

    Returns True if the lock was acquired (no audit currently running). Returns
    False if the lock is already held (ConditionalCheckFailedException). Raises
    ClientError for any other DynamoDB error. Identical semantics on DynamoDB
    Local (dev) and AWS DynamoDB (prod) — no feature flag (SECOPS-007).
    """
    expires_at = now_ts() + _LOCK_TTL_SECONDS
    try:
        T.compliance_audits.put_item(
            Item={
                "pk": _user_pk(user_id),
                "sk": _RUNNING_LOCK_SK,
                "lock_type": "running_audit",
                "acquired_at": now_ts(),
                "expires_at": expires_at,
                "ttl": expires_at,
            },
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def _release_audit_lock(*, user_id: str) -> None:
    """Release the running-audit lock. Best-effort; TTL handles crash cleanup."""
    try:
        T.compliance_audits.delete_item(
            Key={"pk": _user_pk(user_id), "sk": _RUNNING_LOCK_SK}
        )
    except Exception:  # noqa: BLE001 - non-fatal: TTL expires the lock eventually
        pass


def get_running_audit(*, user_id: str) -> Optional[Dict[str, Any]]:
    """Return an in-progress audit for the user, if any."""
    ensure_tables()
    resp = T.compliance_audits.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
        ExpressionAttributeValues={":pk": _user_pk(user_id), ":sk": "AUDIT#"},
    )
    for it in resp.get("Items", []):
        if it.get("status") == "running":
            return _audit_to_out(it)
    return None


def start_audit(
    *, user_id: str, agent_id: str, worker_id: str = "", source: str = "manual_scan"
) -> Dict[str, Any]:
    """Start a security audit. Raises ValueError("audit_in_progress") if one runs.

    In mock mode (the default), the audit is created in ``running`` state and the
    deterministic completion is driven immediately by the caller via
    ``run_mock_audit``. The state machine is fully driveable for tests.

    The running-audit guard is an atomic conditional write (``_acquire_audit_lock``)
    rather than a read-then-write check, so two concurrent callers cannot both
    create a running audit (GAP-0100). The lock is released by ``complete_audit``;
    if the audit-item write fails here the lock is released immediately so the
    user is not left permanently blocked.
    """
    ensure_tables()
    if not _acquire_audit_lock(user_id=user_id):
        raise ValueError("audit_in_progress")
    try:
        audit_id = uuid.uuid4().hex
        ts = now_ts()
        item = {
            "pk": _user_pk(user_id),
            "sk": _audit_sk(audit_id),
            "audit_id": audit_id,
            "user_id": user_id,
            "agent_id": agent_id,
            "worker_id": worker_id,
            "status": "running",
            "source": source,
            "started_at": ts,
            "finding_counts": {},
            "files_scanned": 0,
            "compliance_summary": {},
            "GSI1PK": f"USER#{user_id}#AUDITS",
            "GSI1SK": ts,
        }
        T.compliance_audits.put_item(Item=item)
    except Exception:
        _release_audit_lock(user_id=user_id)
        raise
    return _audit_to_out(item)


def complete_audit(
    *,
    user_id: str,
    audit_id: str,
    finding_counts: Dict[str, int],
    files_scanned: int,
    compliance_summary: Dict[str, Any],
    report_s3_key: Optional[str] = None,
    status: str = "completed",
) -> Dict[str, Any]:
    """Mark an audit as completed (or failed) with results."""
    ensure_tables()
    resp = T.compliance_audits.get_item(
        Key={"pk": _user_pk(user_id), "sk": _audit_sk(audit_id)}
    )
    if not resp.get("Item"):
        raise LookupError("audit_not_found")
    ts = now_ts()
    counts = {k: int(v) for k, v in (finding_counts or {}).items()}
    update_expr = (
        "SET #st = :s, finding_counts = :fc, files_scanned = :files, "
        "compliance_summary = :cs, completed_at = :c"
    )
    values: Dict[str, Any] = {
        ":s": status if status in AUDIT_STATUSES else "completed",
        ":fc": counts,
        ":files": int(files_scanned or 0),
        ":cs": compliance_summary or {},
        ":c": ts,
    }
    if report_s3_key:
        update_expr += ", report_s3_key = :r"
        values[":r"] = report_s3_key
    T.compliance_audits.update_item(
        Key={"pk": _user_pk(user_id), "sk": _audit_sk(audit_id)},
        UpdateExpression=update_expr,
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues=values,
    )
    updated = T.compliance_audits.get_item(
        Key={"pk": _user_pk(user_id), "sk": _audit_sk(audit_id)}
    ).get("Item", {})
    # Release the running-audit lock so a subsequent audit can start (GAP-0100).
    _release_audit_lock(user_id=user_id)
    return _audit_to_out(updated)


def get_audit(*, user_id: str, audit_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.compliance_audits.get_item(
        Key={"pk": _user_pk(user_id), "sk": _audit_sk(audit_id)}
    )
    item = resp.get("Item")
    if not item:
        return None
    return _audit_to_out(item)


def list_audits(*, user_id: str, limit: int = 20, cursor: Optional[str] = None) -> Dict[str, Any]:
    ensure_tables()
    limit = max(1, min(int(limit or 20), 100))
    query_kwargs: Dict[str, Any] = {
        "IndexName": "GSI1",
        "KeyConditionExpression": "GSI1PK = :pk",
        "ExpressionAttributeValues": {":pk": f"USER#{user_id}#AUDITS"},
        "ScanIndexForward": False,
        "Limit": limit,
    }
    start_key = decode_cursor(cursor)
    if start_key:
        query_kwargs["ExclusiveStartKey"] = start_key
    resp = T.compliance_audits.query(**query_kwargs)
    audits = [_audit_to_out(it) for it in resp.get("Items", [])]
    return {"audits": audits, "count": len(audits), "next_cursor": encode_cursor(resp.get("LastEvaluatedKey"))}


def run_mock_audit(*, user_id: str, agent_id: str, worker_id: str = "") -> Dict[str, Any]:
    """Drive the deterministic audit lifecycle (no real scanning).

    Gated: when ``S.compliance_agent_execute_commands`` is true this would
    dispatch the real scanning workflow to the Worker Agent Framework. For now
    mock is the only path so the state machine is fully driveable/testable. The
    audit summarises the user's current open findings.
    """
    audit = start_audit(user_id=user_id, agent_id=agent_id, worker_id=worker_id)
    audit_id = audit["audit_id"]

    # Aggregate current open findings into deterministic audit results.
    open_findings = list_findings(user_id=user_id, status="open", limit=200)["findings"]
    counts: Dict[str, int] = {s: 0 for s in SEVERITIES}
    for f in open_findings:
        sev = f.get("severity")
        if sev in counts:
            counts[sev] += 1
    compliance_summary = _compute_compliance_summary(open_findings)
    return complete_audit(
        user_id=user_id,
        audit_id=audit_id,
        finding_counts=counts,
        files_scanned=len(open_findings) * 3 + 1,
        compliance_summary=compliance_summary,
    )


# ---------------------------------------------------------------------------
# Trends & compliance status
# ---------------------------------------------------------------------------


def _all_findings(user_id: str, *, since_ts: Optional[int] = None) -> List[Dict[str, Any]]:
    ensure_tables()
    out: List[Dict[str, Any]] = []
    start_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": "pk = :pk AND begins_with(sk, :sk)",
            "ExpressionAttributeValues": {":pk": _user_pk(user_id), ":sk": "FINDING#"},
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = T.compliance_findings.query(**kwargs)
        for it in resp.get("Items", []):
            created = int(it.get("created_at", 0) or 0)
            if since_ts is not None and created < since_ts:
                continue
            out.append(_finding_to_out(it))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    return out


def get_finding_trends(*, user_id: str, days: int = 90) -> Dict[str, Any]:
    """Aggregate finding counts by severity and category into weekly buckets.

    Raises ValueError("days_out_of_range") for days outside 1..365.
    """
    if days < 1 or days > 365:
        raise ValueError("days_out_of_range")
    now = now_ts()
    since = now - days * 86400
    findings = _all_findings(user_id, since_ts=since)

    week_seconds = 7 * 86400
    buckets: Dict[int, Dict[str, Any]] = {}
    for f in findings:
        created = f.get("created_at", 0)
        week_index = (created - since) // week_seconds
        week_start = since + week_index * week_seconds
        bucket = buckets.setdefault(
            week_start,
            {"week_start": week_start, "by_severity": {}, "by_category": {}, "total": 0},
        )
        sev = f.get("severity", "info")
        cat = f.get("category", "unknown")
        bucket["by_severity"][sev] = bucket["by_severity"].get(sev, 0) + 1
        bucket["by_category"][cat] = bucket["by_category"].get(cat, 0) + 1
        bucket["total"] += 1

    weeks = [buckets[k] for k in sorted(buckets.keys())]
    return {"weeks": weeks, "days": days, "total": len(findings)}


def _compute_compliance_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Per-framework open-finding rollup for an audit's compliance_summary."""
    summary: Dict[str, Dict[str, int]] = {}
    for fw in _FRAMEWORK_NAMES:
        summary[fw] = {"passed": 0, "failed": 0, "open": 0}
    for f in findings:
        fw = _CATEGORY_FRAMEWORK.get(f.get("category", ""))
        if not fw:
            continue
        summary[fw]["open"] += 1
        summary[fw]["failed"] += 1
    return summary


def get_compliance_status(*, user_id: str) -> Dict[str, Any]:
    """Get current compliance status per framework based on open findings."""
    open_findings = list_findings(user_id=user_id, status="open", limit=200)["findings"]
    frameworks: Dict[str, Any] = {}
    config = get_effective_config(user_id=user_id)
    enabled = set(config.get("compliance_frameworks", [])) | {"wcag"}
    for fw, name in _FRAMEWORK_NAMES.items():
        open_count = sum(
            1 for f in open_findings if _CATEGORY_FRAMEWORK.get(f.get("category", "")) == fw
        )
        if fw not in enabled:
            status = "unknown"
        elif open_count > 0:
            status = "failing"
        else:
            status = "passing"
        frameworks[fw] = {
            "name": name,
            "passed": 0 if open_count else 1,
            "failed": open_count,
            "open_findings": open_count,
            "status": status,
        }
    return {"frameworks": frameworks}


# ---------------------------------------------------------------------------
# Mock PR review (deterministic scanning lifecycle)
# ---------------------------------------------------------------------------


def review_pr_mock(
    *, user_id: str, agent_id: str, pr_ref: str, diff_findings: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Deterministically record findings from a PR diff review (mock mode).

    Gated by ``S.compliance_agent_execute_commands`` for real scanning. Returns
    the created findings and whether a merge block should apply per config.
    """
    config = get_effective_config(user_id=user_id)
    # GAP-0101: when real execution is enabled, ``pr_ref`` may resolve to a repo
    # URL that gets cloned / scanned. Reject hosts outside the allowlist before
    # any outbound action to prevent SSRF / token exfiltration.
    if S.compliance_agent_execute_commands:
        validate_repo_host(pr_ref, config.get("allowed_repo_hosts", ["github.com"]))
    created: List[Dict[str, Any]] = []
    for df in diff_findings or []:
        try:
            f = create_finding(
                user_id=user_id,
                agent_id=agent_id,
                source="pr_review",
                source_ref=pr_ref,
                severity=df.get("severity", "low"),
                category=df.get("category", "security_misconfig"),
                title=df.get("title", "Security finding"),
                description=df.get("description", ""),
                file_path=df.get("file_path"),
                line_range=df.get("line_range"),
                code_snippet=df.get("code_snippet"),
                remediation=df.get("remediation", ""),
            )
            created.append(f)
        except ValueError:
            continue
    block = False
    has_critical = any(f["severity"] == "critical" for f in created)
    has_high = any(f["severity"] == "high" for f in created)
    if has_critical and config.get("block_merge_on_critical"):
        block = True
    if has_high and config.get("block_merge_on_high"):
        block = True
    return {
        "pr_ref": pr_ref,
        "findings": created,
        "finding_count": len(created),
        "block_merge": block,
    }
