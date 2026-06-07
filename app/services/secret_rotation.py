"""Secret rotation primitives for the rootctl ``rotate-secrets`` command (GAP-0345).

This module owns the *real* rotation logic that backs the previously-placeholder
``root rotate-secrets`` CLI command:

  * Generation of new, cryptographically-strong secret values.
  * Persistence of those values to whichever secret store is active
    (AWS Secrets Manager / SSM-style backend in prod, the local ``.env.local``
    file in dev — SECOPS-007 parity: same code path, only the backend differs).
  * Rotation of the KMS break-glass key (enable automatic rotation on the
    existing CMK, best-effort, via the existing KMS client abstraction).

SECURITY: this module never logs, prints, or returns raw secret VALUES. Callers
receive only the names of rotated secrets and identifiers (e.g. the KMS key id).
"""
from __future__ import annotations

import os
import re
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.settings import S

# Logical scope name -> env var name for the secrets we know how to rotate.
SECRET_ENV_FOR_SCOPE: Dict[str, str] = {
    "ui_access_token": "UI_ACCESS_TOKEN_SECRET",
    "api_key_pepper": "API_KEY_PEPPER",
    "ws_token": "WS_TOKEN_SECRET",
}

# Token byte-strength per scope (token_urlsafe(n) -> ~1.3*n chars).
_SCOPE_STRENGTH: Dict[str, int] = {
    "ui_access_token": 64,
    "api_key_pepper": 48,
    "ws_token": 48,
}

VALID_SCOPES = {"all"} | set(SECRET_ENV_FOR_SCOPE.keys())


def generate_new_secrets(scope: str = "all") -> Dict[str, str]:
    """Return ``{ENV_VAR: new_value}`` for every secret selected by ``scope``.

    Uses ``secrets.token_urlsafe`` for cryptographically-strong values.
    """
    if scope not in VALID_SCOPES:
        raise ValueError(
            "invalid scope; choose from: " + ", ".join(sorted(VALID_SCOPES))
        )

    new_values: Dict[str, str] = {}
    for logical, env_name in SECRET_ENV_FOR_SCOPE.items():
        if scope == "all" or scope == logical:
            new_values[env_name] = secrets.token_urlsafe(_SCOPE_STRENGTH[logical])
    return new_values


def _find_env_local() -> Optional[Path]:
    """Locate the active ``.env.local`` file used by the dev secret store."""
    override = (os.getenv("ROOTCTL_ENV_FILE", "") or "").strip()
    if override:
        return Path(override)
    # app/services/secret_rotation.py -> repo root is parents[2]
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / ".env.local"


def _update_env_file(env_path: Path, new_values: Dict[str, str]) -> None:
    """Rewrite ``KEY=value`` lines for the given keys, preserving all other lines.

    Keys not already present are appended. The file is written atomically.
    """
    existing = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
    lines = existing.splitlines()
    remaining = dict(new_values)

    out_lines: List[str] = []
    for line in lines:
        stripped = line.lstrip()
        # Match "KEY=..." possibly with a leading "export ".
        m = re.match(r"^(export\s+)?([A-Za-z_][A-Za-z0-9_]*)=", stripped)
        if m:
            key = m.group(2)
            if key in remaining:
                prefix = m.group(1) or ""
                out_lines.append(f"{prefix}{key}={remaining.pop(key)}")
                continue
        out_lines.append(line)

    for key, value in remaining.items():
        out_lines.append(f"{key}={value}")

    tmp_path = env_path.with_suffix(env_path.suffix + ".rotate.tmp")
    tmp_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    os.replace(tmp_path, env_path)


def _persist_via_secretsmanager(new_values: Dict[str, str]) -> List[str]:
    """Persist secrets to AWS Secrets Manager (prod path). Returns secret ids."""
    from app.core.aws_clients import secretsmanager_client

    client = secretsmanager_client()
    env_label = (os.getenv("APP_ENV", "") or "prod").strip() or "prod"
    written: List[str] = []
    for env_name, value in new_values.items():
        secret_id = f"/app/{env_label}/{env_name}"
        try:
            client.put_secret_value(SecretId=secret_id, SecretString=value)
        except Exception:
            # First rotation: secret may not exist yet.
            client.create_secret(Name=secret_id, SecretString=value)
        written.append(secret_id)
    return written


def persist_secrets(new_values: Dict[str, str]) -> Dict[str, Any]:
    """Persist new secret values to the active secret store.

    Dev (``S.dev_mode``): writes to ``.env.local`` so the rotation is real and
    observable. Prod: writes to AWS Secrets Manager. Same calling convention in
    both cases (SECOPS-007 parity — only the backend differs).

    Returns a non-secret descriptor of where the values landed.
    """
    if not new_values:
        return {"backend": "none", "written": []}

    if S.dev_mode:
        env_path = _find_env_local()
        if env_path is None or not env_path.exists():
            raise RuntimeError(
                ".env.local not found; cannot persist rotated secrets in dev mode"
            )
        _update_env_file(env_path, new_values)
        return {"backend": "env_file", "path": str(env_path), "keys": list(new_values.keys())}

    secret_ids = _persist_via_secretsmanager(new_values)
    return {"backend": "secretsmanager", "secret_ids": secret_ids}


def rotate_kms_break_glass_key() -> Dict[str, Any]:
    """Rotate the KMS break-glass key.

    Best-effort: enables automatic key rotation on the configured CMK via the
    existing KMS client. Never hard-fails (mock KMS in dev may lack the op).
    Returns a non-secret descriptor (key id + outcome).
    """
    key_id = (S.kms_key_id or "").strip()
    if not key_id:
        return {"rotated": False, "reason": "kms_key_id_not_set"}

    try:
        from app.core.aws import kms

        kms.enable_key_rotation(KeyId=key_id)
        return {"rotated": True, "key_id": key_id, "method": "enable_key_rotation"}
    except Exception as exc:  # pragma: no cover - exercised via patched spy in tests
        # Mock KMS in dev may not implement enable_key_rotation; degrade gracefully.
        return {"rotated": False, "key_id": key_id, "warning": type(exc).__name__}
