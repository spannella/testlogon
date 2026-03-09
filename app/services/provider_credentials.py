from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
from fastapi import HTTPException

from app.core.crypto import kms_decrypt, kms_encrypt
from app.core.settings import S
from app.core.tables import T
from app.models import ProviderCredentialModel


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _credential_pk(owner: str) -> str:
    return f"OWNER#{owner}"


def _credential_sk(provider: str, org: Optional[str]) -> str:
    suffix = (org or "self").strip().lower()
    return f"PROVIDER_CRED#{provider.strip().lower()}#{suffix}"


def _credential_to_item(model: ProviderCredentialModel) -> Dict[str, Any]:
    return {
        "PK": _credential_pk(model.owner),
        "SK": _credential_sk(model.provider, model.org),
        "entity_type": "provider_credential",
        "owner": model.owner,
        "provider": model.provider,
        "org": model.org,
        "token_ct_b64": model.token_ct_b64,
        "scopes": model.scopes,
        "metadata": model.metadata,
        "created_at": model.created_at,
        "updated_at": model.updated_at,
    }


def _credential_from_item(item: Dict[str, Any]) -> ProviderCredentialModel:
    return ProviderCredentialModel(
        owner=item["owner"],
        provider=item["provider"],
        org=item.get("org"),
        token_ct_b64=item["token_ct_b64"],
        scopes=item.get("scopes") or [],
        metadata=item.get("metadata") or {},
        created_at=item["created_at"],
        updated_at=item["updated_at"],
    )


def _parse_github_scopes(header_value: Optional[str]) -> List[str]:
    if not header_value:
        return []
    out: List[str] = []
    seen = set()
    for raw in header_value.split(","):
        normalized = raw.strip().lower()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out


def _normalize_api_base_url(value: Optional[str], *, default: str, provider: str) -> str:
    candidate = (value or default).strip().rstrip("/")
    if not candidate.startswith("http://") and not candidate.startswith("https://"):
        raise HTTPException(status_code=400, detail=f"{provider} api_base_url must start with http:// or https://")
    return candidate


def normalize_github_api_base_url(value: Optional[str]) -> str:
    return _normalize_api_base_url(
        value,
        default=(S.github_api_base_url or "https://api.github.com"),
        provider="github",
    )


def normalize_gitlab_api_base_url(value: Optional[str]) -> str:
    return _normalize_api_base_url(
        value,
        default=(S.gitlab_api_base_url or "https://gitlab.com/api/v4"),
        provider="gitlab",
    )


def _validate_github_token(token: str, api_base_url: Optional[str] = None) -> Dict[str, Any]:
    normalized_base_url = normalize_github_api_base_url(api_base_url)
    r = requests.get(
        f"{normalized_base_url}/user",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=10,
    )
    if r.status_code in (401, 403):
        raise HTTPException(status_code=401, detail="github token invalid or expired; refresh token and retry")
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"github token validation failed ({r.status_code})")
    body = r.json() if r.content else {}
    return {
        "scopes": _parse_github_scopes(r.headers.get("X-OAuth-Scopes")),
        "metadata": {
            "login": body.get("login"),
            "id": body.get("id"),
            "api_base_url": normalized_base_url,
        },
    }


def _validate_gitlab_token(token: str, api_base_url: Optional[str] = None) -> Dict[str, Any]:
    normalized_base_url = normalize_gitlab_api_base_url(api_base_url)
    r = requests.get(
        f"{normalized_base_url}/personal_access_tokens/self",
        headers={"PRIVATE-TOKEN": token},
        timeout=10,
    )
    if r.status_code in (401, 403):
        raise HTTPException(status_code=401, detail="gitlab token invalid/expired or missing api scope")
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"gitlab token validation failed ({r.status_code})")
    body = r.json() if r.content else {}
    scopes = [str(scope).strip().lower() for scope in (body.get("scopes") or []) if str(scope).strip()]
    return {
        "scopes": scopes,
        "metadata": {
            "token_id": body.get("id"),
            "active": body.get("active"),
            "expires_at": body.get("expires_at"),
            "api_base_url": normalized_base_url,
        },
    }


def _validate_google_drive_token(token: str) -> Dict[str, Any]:
    # GDM-001 only introduces provider acceptance. OAuth code-flow and richer
    # token validation/metadata are added in subsequent tickets.
    if not token or not token.strip():
        raise HTTPException(status_code=400, detail="token is required")
    return {"scopes": [], "metadata": {}}


def validate_provider_token(
    provider: str,
    token: str,
    required_scopes: Optional[List[str]] = None,
    *,
    api_base_url: Optional[str] = None,
) -> Dict[str, Any]:
    normalized_provider = (provider or "").strip().lower()
    if not token or not token.strip():
        raise HTTPException(status_code=400, detail="token is required")

    if normalized_provider == "github":
        result = _validate_github_token(token.strip(), api_base_url=api_base_url)
    elif normalized_provider == "gitlab":
        result = _validate_gitlab_token(token.strip(), api_base_url=api_base_url)
    elif normalized_provider == "google_drive":
        result = _validate_google_drive_token(token.strip())
    else:
        raise HTTPException(status_code=400, detail="unsupported provider")

    required = [s.strip().lower() for s in (required_scopes or []) if s and s.strip()]
    granted = result.get("scopes") or []
    missing = [scope for scope in required if scope not in granted]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"provider token missing required scopes: {', '.join(missing)}",
        )

    return result


def upsert_provider_credential(
    owner: str,
    provider: str,
    token: str,
    *,
    org: Optional[str] = None,
    required_scopes: Optional[List[str]] = None,
    api_base_url: Optional[str] = None,
    metadata_override: Optional[Dict[str, Any]] = None,
    scopes_override: Optional[List[str]] = None,
) -> ProviderCredentialModel:
    validated = validate_provider_token(
        provider,
        token,
        required_scopes=required_scopes,
        api_base_url=api_base_url,
    )

    try:
        token_ct_b64 = kms_encrypt(token.strip())
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail="credential encryption is not configured") from exc

    ts = now_iso()
    existing = get_provider_credential(owner, provider, org=org, allow_missing=True)
    merged_metadata: Dict[str, Any] = dict(validated.get("metadata") or {})
    if metadata_override:
        merged_metadata.update(metadata_override)

    resolved_scopes = list(scopes_override) if scopes_override is not None else (validated.get("scopes") or [])

    model = ProviderCredentialModel(
        owner=owner,
        provider=provider.strip().lower(),
        org=(org or None),
        token_ct_b64=token_ct_b64,
        scopes=resolved_scopes,
        metadata=merged_metadata,
        created_at=existing.created_at if existing else ts,
        updated_at=ts,
    )
    T.projects.put_item(Item=_credential_to_item(model))
    return model


def get_provider_credential(
    owner: str,
    provider: str,
    *,
    org: Optional[str] = None,
    allow_missing: bool = False,
) -> Optional[ProviderCredentialModel]:
    resp = T.projects.get_item(
        Key={
            "PK": _credential_pk(owner),
            "SK": _credential_sk(provider, org),
        },
        ConsistentRead=True,
    )
    item = resp.get("Item")
    if not item or item.get("entity_type") != "provider_credential":
        if allow_missing:
            return None
        raise HTTPException(status_code=404, detail="provider credential not found")
    return _credential_from_item(item)


def get_provider_token(
    owner: str,
    provider: str,
    *,
    org: Optional[str] = None,
    required_scopes: Optional[List[str]] = None,
) -> str:
    cred = get_provider_credential(owner, provider, org=org)
    granted = cred.scopes or []
    required = [s.strip().lower() for s in (required_scopes or []) if s and s.strip()]
    missing = [scope for scope in required if scope not in granted]
    if missing:
        raise HTTPException(status_code=400, detail=f"stored token missing scopes: {', '.join(missing)}")

    try:
        return kms_decrypt(cred.token_ct_b64).decode("utf-8")
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail="credential decryption is not configured") from exc


def get_provider_auth_context(
    owner: str,
    provider: str,
    *,
    org: Optional[str] = None,
    required_scopes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    cred = get_provider_credential(owner, provider, org=org)
    granted = cred.scopes or []
    required = [s.strip().lower() for s in (required_scopes or []) if s and s.strip()]
    missing = [scope for scope in required if scope not in granted]
    if missing:
        raise HTTPException(status_code=400, detail=f"stored token missing scopes: {', '.join(missing)}")

    if cred.provider == "google_drive":
        metadata = dict(cred.metadata or {})
        if bool(metadata.get("reconnect_required")):
            reason = str(metadata.get("auth_failure_reason") or "revoked")
            raise HTTPException(
                status_code=401,
                detail={
                    "code": "provider_reconnect_required",
                    "provider": "google_drive",
                    "reason": reason,
                    "reconnect_required": True,
                },
            )
        expires_at_epoch = _parse_expires_at_epoch(str(metadata.get("expires_at") or ""))
        now_epoch = int(datetime.now(timezone.utc).timestamp())
        # Refresh slightly early to avoid race with near-expired access tokens.
        if expires_at_epoch is not None and expires_at_epoch <= (now_epoch + 60):
            from app.services.provider_oauth import refresh_google_oauth_access_token

            return refresh_google_oauth_access_token(
                owner,
                org=org,
                required_scopes=required,
            )

    try:
        token = kms_decrypt(cred.token_ct_b64).decode("utf-8")
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail="credential decryption is not configured") from exc

    return {
        "token": token,
        "provider": cred.provider,
        "org": cred.org,
        "scopes": list(cred.scopes or []),
        "metadata": dict(cred.metadata or {}),
    }




def _parse_expires_at_epoch(value: Optional[str]) -> Optional[int]:
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def rotate_provider_access_token(
    owner: str,
    provider: str,
    access_token: str,
    *,
    org: Optional[str] = None,
    scopes_override: Optional[List[str]] = None,
    metadata_override: Optional[Dict[str, Any]] = None,
) -> ProviderCredentialModel:
    existing = get_provider_credential(owner, provider, org=org)
    try:
        token_ct_b64 = kms_encrypt((access_token or "").strip())
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail="credential encryption is not configured") from exc

    merged_metadata = dict(existing.metadata or {})
    if metadata_override:
        merged_metadata.update(metadata_override)

    updated = ProviderCredentialModel(
        owner=existing.owner,
        provider=existing.provider,
        org=existing.org,
        token_ct_b64=token_ct_b64,
        scopes=list(scopes_override) if scopes_override is not None else list(existing.scopes or []),
        metadata=merged_metadata,
        created_at=existing.created_at,
        updated_at=now_iso(),
    )
    T.projects.put_item(Item=_credential_to_item(updated))
    return updated


def merge_provider_credential_metadata(
    owner: str,
    provider: str,
    *,
    metadata_updates: Dict[str, Any],
    org: Optional[str] = None,
) -> ProviderCredentialModel:
    existing = get_provider_credential(owner, provider, org=org)
    merged_metadata = dict(existing.metadata or {})
    merged_metadata.update(metadata_updates or {})

    updated = ProviderCredentialModel(
        owner=existing.owner,
        provider=existing.provider,
        org=existing.org,
        token_ct_b64=existing.token_ct_b64,
        scopes=list(existing.scopes or []),
        metadata=merged_metadata,
        created_at=existing.created_at,
        updated_at=now_iso(),
    )
    T.projects.put_item(Item=_credential_to_item(updated))
    return updated

def delete_provider_credential(owner: str, provider: str, *, org: Optional[str] = None) -> Dict[str, bool]:
    key = {"PK": _credential_pk(owner), "SK": _credential_sk(provider, org)}
    resp = T.projects.get_item(Key=key, ConsistentRead=True)
    item = resp.get("Item")
    if not item:
        return {"ok": True, "deleted": False}
    if item.get("entity_type") != "provider_credential" or item.get("owner") != owner:
        raise HTTPException(status_code=404, detail="provider credential not found")
    T.projects.delete_item(Key=key)
    return {"ok": True, "deleted": True}
