from __future__ import annotations

import ipaddress
import re
from typing import List

from fastapi import HTTPException

def client_ip_from_request(req) -> str:
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return req.client.host if req.client else "0.0.0.0"

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
        except Exception:
            continue
    return False
