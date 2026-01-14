from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Dict, Optional

from .aws import kms
from .settings import S

def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def kms_encrypt(plaintext: str) -> str:
    if not S.kms_key_id:
        raise RuntimeError("KMS_KEY_ID not set")
    r = kms.encrypt(KeyId=S.kms_key_id, Plaintext=plaintext.encode("utf-8"))
    return base64.b64encode(r["CiphertextBlob"]).decode("ascii")

def kms_decrypt(ct_b64: str) -> bytes:
    ct = base64.b64decode(ct_b64)
    r = kms.decrypt(CiphertextBlob=ct)
    return r["Plaintext"]

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def b64url_decode(s: str) -> bytes:
    s = s.strip()
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def mint_ws_token(user_sub: str, ttl_seconds: int = 60) -> str:
    if not S.ws_token_secret:
        raise RuntimeError("WS_TOKEN_SECRET not set")
    import time
    now = int(time.time())
    payload = {"user_sub": user_sub, "exp": now + ttl_seconds, "iat": now}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(S.ws_token_secret.encode("utf-8"), raw, hashlib.sha256).digest()
    return f"{b64url(raw)}.{b64url(sig)}"

def verify_ws_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        raw_b64, sig_b64 = token.split(".", 1)
        raw = b64url_decode(raw_b64)
        sig = b64url_decode(sig_b64)
        expected = hmac.new(S.ws_token_secret.encode("utf-8"), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        obj = json.loads(raw.decode("utf-8"))
        if int(obj.get("exp", 0)) < int(__import__("time").time()):
            return None
        return obj
    except Exception:
        return None
