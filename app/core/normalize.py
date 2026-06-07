from __future__ import annotations

import ipaddress
import re
from typing import List

from fastapi import HTTPException

from app.core.settings import S


def _trusted_proxy_list() -> List[str]:
    """Parse S.trusted_proxy_cidrs (comma/space separated) into a list of CIDR strings.

    Mirrors the parsing behaviour of root_network._resolve_client_ip so the two
    code paths agree on which TCP peers are trusted proxies. Empty/blank entries
    are dropped; an empty setting yields an empty list (no trusted proxies).
    """
    raw = (S.trusted_proxy_cidrs or "").strip()
    if not raw:
        return []
    parts: List[str] = []
    for chunk in raw.replace(",", " ").split():
        candidate = chunk.strip()
        if candidate:
            parts.append(candidate)
    return parts


def client_ip_from_request(req) -> str:
    """Return the best-guess real client IP for rate-limiting and audit logging.

    Trusts X-Forwarded-For ONLY when the direct TCP peer (req.client.host) falls
    within TRUSTED_PROXY_CIDRS. When the list is empty (dev mode / no proxy) the
    direct host is always returned, preventing XFF injection / IP spoofing.

    SECOPS-007: TRUSTED_PROXY_CIDRS defaults to "" (empty) in dev, so the dev
    environment uses the direct IP just like the test client; production ops sets
    the ALB/NLB CIDR. The code path is identical — no dev-only bypass.
    """
    if req is None:
        return "0.0.0.0"
    direct_host = req.client.host if req.client else "0.0.0.0"
    xff = (req.headers.get("x-forwarded-for") or "").strip()
    if not xff:
        return direct_host
    # Only honour XFF if the direct TCP peer is a known trusted proxy.
    try:
        peer_trusted = ip_in_any_cidr(direct_host, _trusted_proxy_list())
    except ValueError:
        # Malformed direct host (non-IP); treat as untrusted and never honour XFF.
        peer_trusted = False
    if not peer_trusted:
        return direct_host
    # XFF is trusted: the real client IP is the leftmost entry
    # (matches root_network._resolve_client_ip: xff.split(",", 1)[0]).
    first = xff.split(",", 1)[0].strip()
    return first if first else direct_host

def normalize_email(s: str) -> str:
    s = (s or "").strip().lower()
    if "@" not in s or len(s) > 254:
        raise HTTPException(400, "Invalid email")
    return s

def normalize_phone(s: str) -> str:
    s = (s or "").strip()
    if not s:
        raise HTTPException(400, "Invalid phone")
    s2 = re.sub(r"[\s\-\(\)\.]", "", s)
    if s2.startswith("+"):
        digits = re.sub(r"\D", "", s2[1:])
        if not digits:
            raise HTTPException(400, "Invalid phone")
        return "+" + digits
    digits = re.sub(r"\D", "", s2)
    if len(digits) == 10:
        return "+1" + digits
    if len(digits) == 11 and digits.startswith("1"):
        return "+" + digits
    raise HTTPException(400, "Invalid phone format; use +E164 or 10-digit")

def normalize_cidr(s: str) -> str:
    s = (s or "").strip()
    if not s:
        raise HTTPException(400, "Invalid CIDR")
    if "/" not in s:
        ip = ipaddress.ip_address(s)
        return f"{ip}/32" if ip.version == 4 else f"{ip}/128"
    net = ipaddress.ip_network(s, strict=False)
    return str(net)

def ip_in_any_cidr(ip_str: str, cidrs: List[str]) -> bool:
    if not cidrs:
        return False
    ip = ipaddress.ip_address(ip_str)
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if ip in net:
                return True
        except ValueError:
            continue
    return False
