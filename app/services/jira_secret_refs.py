from __future__ import annotations

from threading import Lock
import secrets

_store_lock = Lock()
_secret_store: dict[str, str] = {}


def put_secret(secret_value: str, *, prefix: str) -> str:
    token = secrets.token_urlsafe(18)
    ref = f"{prefix.rstrip('/')}/{token}"
    with _store_lock:
        _secret_store[ref] = secret_value
    return ref


def get_secret(ref: str) -> str | None:
    with _store_lock:
        return _secret_store.get(ref)
