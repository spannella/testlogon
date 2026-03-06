from __future__ import annotations

import ipaddress
import logging
from typing import Optional

from fastapi import HTTPException

from app.core.settings import S
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)


def _mode() -> str:
    raw = str(getattr(S, "filemgr_sftp_destination_policy_mode", "allow_all") or "allow_all").strip().lower()
    return raw if raw in {"allow_all", "allowlist"} else "allow_all"


def _allowed_raw() -> list[str]:
    raw = str(getattr(S, "filemgr_sftp_allowed_destinations", "") or "").strip()
    if not raw:
        return []
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def _host_matches_rule(host: str, rule: str) -> bool:
    h = host.strip().lower()
    r = rule.strip().lower()
    if not h or not r:
        return False
    if r == "*":
        return True
    # CIDR/IP policy
    try:
        h_ip = ipaddress.ip_address(h)
        try:
            net = ipaddress.ip_network(r, strict=False)
            return h_ip in net
        except Exception:
            try:
                return h_ip == ipaddress.ip_address(r)
            except Exception:
                return False
    except Exception:
        pass

    # Hostname/domain policy
    if r.startswith("*."):
        suffix = r[1:]  # .example.com
        return h.endswith(suffix)
    if r.startswith("."):
        return h.endswith(r)
    return h == r


def _deny(*, owner: Optional[str], mount_id: Optional[str], host: str, stage: str, mode: str) -> None:
    details = {
        "owner": owner,
        "mount_id": mount_id,
        "host": host,
        "stage": stage,
        "policy_mode": mode,
        "code": "sftp_destination_not_allowed",
    }
    logger.warning("sftp destination denied by policy", extra=details)
    audit_event(
        "filemgr_sftp_destination_policy_denied",
        str(owner or "system"),
        outcome="failure",
        **details,
    )
    raise HTTPException(
        status_code=403,
        detail={
            "code": "sftp_destination_not_allowed",
            "message": "sftp destination is blocked by outbound destination policy",
            "host": host,
            "policy_mode": mode,
        },
    )


def enforce_sftp_destination_policy(*, host: str, owner: Optional[str] = None, mount_id: Optional[str] = None, stage: str = "connection") -> None:
    mode = _mode()
    if mode == "allow_all":
        return
    allowed = _allowed_raw()
    normalized_host = (host or "").strip().lower()
    if not normalized_host:
        _deny(owner=owner, mount_id=mount_id, host=normalized_host, stage=stage, mode=mode)
    if not allowed:
        _deny(owner=owner, mount_id=mount_id, host=normalized_host, stage=stage, mode=mode)
    for rule in allowed:
        if _host_matches_rule(normalized_host, rule):
            return
    _deny(owner=owner, mount_id=mount_id, host=normalized_host, stage=stage, mode=mode)
