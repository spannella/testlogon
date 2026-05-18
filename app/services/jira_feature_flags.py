from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
from threading import Lock
from urllib.parse import urlparse

from app.core.settings import S


@dataclass(frozen=True)
class JiraFeatureFlags:
    enabled: bool
    read_enabled: bool
    outbound_enabled: bool
    inbound_enabled: bool
    workspace_allowlist: tuple[str, ...]
    outbound_kill_switch: bool


_runtime_lock = Lock()
_runtime_outbound_kill_switch_override: bool | None = None


def _parse_allowlist(raw: str | None) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for chunk in (raw or "").split(","):
        token = chunk.strip()
        if not token or token in seen:
            continue
        seen.add(token)
        out.append(token)
    return tuple(out)


def get_jira_feature_flags(*, settings: object | None = None) -> JiraFeatureFlags:
    cfg = settings or S
    with _runtime_lock:
        kill_switch = bool(
            _runtime_outbound_kill_switch_override
            if _runtime_outbound_kill_switch_override is not None
            else cfg.jira_sync_outbound_kill_switch
        )

    return JiraFeatureFlags(
        enabled=bool(cfg.jira_sync_enabled),
        read_enabled=bool(cfg.jira_sync_read_enabled),
        outbound_enabled=bool(cfg.jira_sync_outbound_enabled),
        inbound_enabled=bool(cfg.jira_sync_inbound_enabled),
        workspace_allowlist=_parse_allowlist(cfg.jira_sync_workspace_allowlist),
        outbound_kill_switch=kill_switch,
    )


def set_runtime_outbound_kill_switch(*, disabled: bool, settings: object | None = None) -> JiraFeatureFlags:
    global _runtime_outbound_kill_switch_override
    with _runtime_lock:
        _runtime_outbound_kill_switch_override = bool(disabled)
    return get_jira_feature_flags(settings=settings)


def reset_runtime_outbound_kill_switch_override() -> None:
    global _runtime_outbound_kill_switch_override
    with _runtime_lock:
        _runtime_outbound_kill_switch_override = None


def is_workspace_allowed(workspace_id: str, *, settings: object | None = None) -> bool:
    flags = get_jira_feature_flags(settings=settings)
    if not flags.workspace_allowlist:
        return True
    return workspace_id in flags.workspace_allowlist


def _is_blank(value: object) -> bool:
    return not str(value or "").strip()


def _validate_webhook_source_ip_policy_env() -> None:
    mode = str(os.getenv("JIRA_WEBHOOK_IP_POLICY_MODE", "enforce")).strip().lower()
    if mode not in {"off", "monitor", "enforce"}:
        raise RuntimeError(
            "JIRA startup check failed: invalid JIRA_WEBHOOK_IP_POLICY_MODE; expected one of off|monitor|enforce."
        )
    raw_allowed = str(os.getenv("JIRA_WEBHOOK_ALLOWED_IPS", "")).strip()
    if not raw_allowed:
        return
    invalid_tokens: list[str] = []
    has_valid = False
    for token in (chunk.strip() for chunk in raw_allowed.split(",")):
        if not token:
            continue
        try:
            ipaddress.ip_network(token, strict=False)
            has_valid = True
        except ValueError:
            invalid_tokens.append(token)
    if invalid_tokens:
        raise RuntimeError(
            "JIRA startup check failed: invalid JIRA_WEBHOOK_ALLOWED_IPS CIDR entries: " + ", ".join(invalid_tokens)
        )
    if not has_valid:
        raise RuntimeError(
            "JIRA startup check failed: JIRA_WEBHOOK_ALLOWED_IPS is set but contains no valid CIDR entries."
        )


def _validate_webhook_runtime_limits_env() -> None:
    raw_ttl = str(os.getenv("JIRA_WEBHOOK_REPLAY_TTL_SECONDS", "600")).strip() or "600"
    try:
        ttl = int(raw_ttl)
    except ValueError as exc:
        raise RuntimeError(
            "JIRA startup check failed: JIRA_WEBHOOK_REPLAY_TTL_SECONDS must be an integer >= 60."
        ) from exc
    if ttl < 60:
        raise RuntimeError(
            "JIRA startup check failed: JIRA_WEBHOOK_REPLAY_TTL_SECONDS must be >= 60."
        )

    raw_max = str(os.getenv("JIRA_WEBHOOK_REPLAY_MAX_KEYS", "50000")).strip() or "50000"
    try:
        max_keys = int(raw_max)
    except ValueError as exc:
        raise RuntimeError(
            "JIRA startup check failed: JIRA_WEBHOOK_REPLAY_MAX_KEYS must be an integer >= 100."
        ) from exc
    if max_keys < 100:
        raise RuntimeError(
            "JIRA startup check failed: JIRA_WEBHOOK_REPLAY_MAX_KEYS must be >= 100."
        )


def _validate_webhook_queue_env(*, cfg: object) -> None:
    if not bool(getattr(cfg, "jira_sync_inbound_enabled", False)):
        return
    queue_url = str(os.getenv("JIRA_WEBHOOK_QUEUE_URL", "")).strip()
    if not queue_url:
        raise RuntimeError(
            "JIRA startup check failed: inbound webhook sync requires non-empty JIRA_WEBHOOK_QUEUE_URL."
        )
    if not (queue_url.startswith("https://") or queue_url.startswith("http://")):
        raise RuntimeError(
            "JIRA startup check failed: JIRA_WEBHOOK_QUEUE_URL must be an absolute http(s) URL."
        )
    parsed = urlparse(queue_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError(
            "JIRA startup check failed: JIRA_WEBHOOK_QUEUE_URL must include valid scheme and host."
        )


def validate_jira_integration_startup_config(*, settings: object | None = None) -> None:
    cfg = settings or S
    if not cfg.jira_sync_enabled:
        return

    if not cfg.jira_sync_read_enabled and not cfg.jira_sync_outbound_enabled and not cfg.jira_sync_inbound_enabled:
        raise RuntimeError(
            "JIRA startup check failed: JIRA_SYNC_ENABLED=true requires at least one mode enabled (JIRA_SYNC_READ_ENABLED, JIRA_SYNC_OUTBOUND_ENABLED, or JIRA_SYNC_INBOUND_ENABLED)."
        )

    if (cfg.jira_sync_outbound_enabled or cfg.jira_sync_inbound_enabled) and not cfg.jira_sync_read_enabled:
        raise RuntimeError(
            "JIRA startup check failed: outbound/inbound sync requires JIRA_SYNC_READ_ENABLED=true so the local Jira mirror remains authoritative."
        )

    if cfg.jira_sync_require_oauth_config and (_is_blank(cfg.jira_sync_oauth_client_id) or _is_blank(cfg.jira_sync_oauth_client_secret_ref)):
        raise RuntimeError(
            "JIRA startup check failed: OAuth configuration missing; set non-empty JIRA_SYNC_OAUTH_CLIENT_ID and JIRA_SYNC_OAUTH_CLIENT_SECRET_REF."
        )

    if cfg.jira_sync_require_workspace_allowlist and not _parse_allowlist(cfg.jira_sync_workspace_allowlist):
        raise RuntimeError(
            "JIRA startup check failed: workspace allowlist required; set JIRA_SYNC_WORKSPACE_ALLOWLIST or disable JIRA_SYNC_REQUIRE_WORKSPACE_ALLOWLIST."
        )

    required_indexes = {
        "TICKETS_JIRA_WORKSPACE_INDEX_NAME": cfg.tickets_jira_workspace_index_name,
        "TICKETS_JIRA_ISSUE_INDEX_NAME": cfg.tickets_jira_issue_index_name,
        "TICKETS_JIRA_SYNC_STATE_INDEX_NAME": cfg.tickets_jira_sync_state_index_name,
    }
    missing = [name for name, value in required_indexes.items() if _is_blank(value)]
    if missing:
        raise RuntimeError(
            "JIRA startup check failed: missing required Jira index settings: " + ", ".join(sorted(missing))
        )

    _validate_webhook_source_ip_policy_env()
    _validate_webhook_runtime_limits_env()
    _validate_webhook_queue_env(cfg=cfg)
