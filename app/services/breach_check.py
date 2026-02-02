from __future__ import annotations

import hashlib
from typing import Optional

import requests
from fastapi import HTTPException

from app.core.settings import S

_HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"

def _sha1_hex(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest().upper()

def check_password_breach(password: str) -> Optional[int]:
    if not S.hibp_enabled:
        return None
    pw_hash = _sha1_hex(password)
    prefix, suffix = pw_hash[:5], pw_hash[5:]
    headers = {"User-Agent": "security-backend"}
    if S.hibp_api_key:
        headers["hibp-api-key"] = S.hibp_api_key
    try:
        resp = requests.get(f"{_HIBP_RANGE_URL}{prefix}", headers=headers, timeout=10)
        resp.raise_for_status()
    except Exception as exc:
        raise HTTPException(502, "Breach check unavailable") from exc
    for line in resp.text.splitlines():
        if ":" not in line:
            continue
        hash_suffix, count = line.split(":", 1)
        if hash_suffix.strip().upper() == suffix:
            try:
                return int(count.strip())
            except ValueError:
                return 1
    return 0
