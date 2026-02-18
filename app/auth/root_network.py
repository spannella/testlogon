from __future__ import annotations

import ipaddress
from typing import List, Tuple

from fastapi import HTTPException, Request

from app.core.settings import S


def _parse_cidrs(raw: str) -> List[ipaddress._BaseNetwork]:
    out: List[ipaddress._BaseNetwork] = []
    for part in (raw or "").split(","):
        candidate = part.strip()
        if not candidate:
            continue
        out.append(ipaddress.ip_network(candidate, strict=False))
    return out


def _ip_in_networks(ip_value: ipaddress._BaseAddress, networks: List[ipaddress._BaseNetwork]) -> bool:
    return any(ip_value in net for net in networks)


def _resolve_client_ip(req: Request) -> Tuple[ipaddress._BaseAddress, str]:
    direct_host = req.client.host if req and req.client else ""
    try:
        direct_ip = ipaddress.ip_address(direct_host)
    except ValueError as exc:
        raise HTTPException(
            status_code=403,
            detail={"code": "root_network_restricted", "reason": "unknown_source"},
        ) from exc

    trusted_proxy_networks = _parse_cidrs(S.trusted_proxy_cidrs)
    xff = (req.headers.get("x-forwarded-for") or "").strip()
    if not xff:
        return direct_ip, "direct"

    if not _ip_in_networks(direct_ip, trusted_proxy_networks):
        # Ignore spoofed XFF from untrusted source.
        return direct_ip, "direct_untrusted_proxy"

    first = xff.split(",", 1)[0].strip()
    if not first:
        raise HTTPException(
            status_code=403,
            detail={"code": "root_network_restricted", "reason": "unknown_source"},
        )
    try:
        forwarded_ip = ipaddress.ip_address(first)
    except ValueError as exc:
        raise HTTPException(
            status_code=403,
            detail={"code": "root_network_restricted", "reason": "unknown_source"},
        ) from exc
    return forwarded_ip, "trusted_proxy"


def enforce_root_network_gate(req: Request) -> str:
    source_ip, source_kind = _resolve_client_ip(req)
    allowed_networks = _parse_cidrs(S.root_login_allowed_ips)
    local_only = bool(S.root_login_local_only)

    is_local = source_ip.is_loopback or source_ip.is_private or source_ip.is_link_local
    allow_via_local = local_only and is_local
    allow_via_allowlist = bool(allowed_networks) and _ip_in_networks(source_ip, allowed_networks)

    if allow_via_local or allow_via_allowlist:
        return str(source_ip)

    raise HTTPException(
        status_code=403,
        detail={
            "code": "root_network_restricted",
            "reason": "untrusted_source",
            "source": source_kind,
            "source_ip": str(source_ip),
        },
    )
