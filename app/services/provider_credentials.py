from __future__ import annotations

from datetime import datetime, timezone
import logging
import json
from typing import Any, Dict, List, Optional

import boto3
import requests
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError
from fastapi import HTTPException

from app.core.crypto import kms_decrypt, kms_encrypt
from app.core.settings import S
from app.core.tables import T
from app.models import ProviderCredentialModel

logger = logging.getLogger(__name__)


def _redacted_credential_log_payload(
    *,
    provider: str,
    org: Optional[str],
    has_token: bool,
    has_access_key_id: bool,
    has_secret_access_key: bool,
    has_session_token: bool,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "provider": (provider or "").strip().lower(),
        "org": org,
        "has_token": bool(has_token),
        "has_access_key_id": bool(has_access_key_id),
        "has_secret_access_key": bool(has_secret_access_key),
        "has_session_token": bool(has_session_token),
        "metadata_keys": sorted(list((metadata or {}).keys())),
    }


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


def _normalize_s3_endpoint_url(value: Optional[str]) -> Optional[str]:
    candidate = (value or "").strip().rstrip("/")
    if not candidate:
        return None
    if not candidate.startswith("http://") and not candidate.startswith("https://"):
        raise HTTPException(status_code=400, detail="s3 endpoint_url must start with http:// or https://")
    return candidate


def _map_s3_client_error(exc: ClientError) -> HTTPException:
    err = (exc.response or {}).get("Error", {})
    code = str(err.get("Code") or "").strip()
    msg = str(err.get("Message") or "").strip() or "s3 credential validation failed"

    if code in {"InvalidAccessKeyId", "SignatureDoesNotMatch", "ExpiredToken", "InvalidToken", "AuthFailure"}:
        return HTTPException(status_code=401, detail=f"s3 credentials invalid: {msg}")
    if code in {"AccessDenied", "AllAccessDisabled"}:
        return HTTPException(status_code=403, detail=f"s3 access denied: {msg}")
    if code in {"NoSuchBucket", "NotFound", "404"}:
        return HTTPException(status_code=400, detail=f"s3 bucket not found: {msg}")
    if code in {"PermanentRedirect", "AuthorizationHeaderMalformed"}:
        return HTTPException(status_code=400, detail=f"s3 region/endpoint mismatch: {msg}")
    return HTTPException(status_code=502, detail=f"s3 validation error ({code or 'unknown'}): {msg}")


def _probe_s3_credentials(
    *,
    access_key_id: str,
    secret_access_key: str,
    session_token: Optional[str],
    region: Optional[str],
    endpoint_url: Optional[str],
    path_style: bool,
    validation_bucket: str,
) -> None:
    cfg = Config(s3={"addressing_style": "path" if path_style else "auto"})
    client = boto3.client(
        "s3",
        region_name=region or S.aws_region,
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token,
        config=cfg,
    )
    try:
        client.head_bucket(Bucket=validation_bucket)
        client.list_objects_v2(Bucket=validation_bucket, MaxKeys=1)
    except ClientError as exc:
        raise _map_s3_client_error(exc) from exc
    except EndpointConnectionError as exc:
        raise HTTPException(status_code=502, detail="s3 endpoint unreachable during credential validation") from exc
    except BotoCoreError as exc:
        raise HTTPException(status_code=502, detail="s3 credential validation failed due to transport error") from exc


def _validate_s3_credentials_payload(
    *,
    token: Optional[str],
    access_key_id: Optional[str],
    secret_access_key: Optional[str],
    session_token: Optional[str],
    region: Optional[str],
    endpoint_url: Optional[str],
    path_style: Optional[bool],
    auth_mode: Optional[str],
    validation_bucket: Optional[str],
) -> Dict[str, Any]:
    resolved_access_key_id = (access_key_id or "").strip()
    resolved_secret_access_key = (secret_access_key or "").strip()
    if not resolved_access_key_id or not resolved_secret_access_key:
        parsed_from_token: Dict[str, Any] = {}
        raw_token = (token or "").strip()
        if raw_token:
            try:
                parsed = json.loads(raw_token)
                if isinstance(parsed, dict):
                    parsed_from_token = parsed
            except ValueError:
                parsed_from_token = {}
        resolved_access_key_id = resolved_access_key_id or str(parsed_from_token.get("access_key_id") or "").strip()
        resolved_secret_access_key = resolved_secret_access_key or str(parsed_from_token.get("secret_access_key") or "").strip()
        if not session_token:
            session_token = str(parsed_from_token.get("session_token") or "").strip() or None

    if not resolved_access_key_id:
        raise HTTPException(status_code=400, detail="s3 access_key_id is required")
    if not resolved_secret_access_key:
        raise HTTPException(status_code=400, detail="s3 secret_access_key is required")

    resolved_region = (region or "").strip() or None
    resolved_endpoint_url = _normalize_s3_endpoint_url(endpoint_url)
    resolved_auth_mode = (auth_mode or "").strip().lower() or ("session_token" if session_token else "access_key")
    if resolved_auth_mode not in {"access_key", "session_token"}:
        raise HTTPException(status_code=400, detail="s3 auth_mode must be one of: access_key, session_token")

    resolved_session_token = (session_token or "").strip() or None
    if resolved_auth_mode == "session_token" and not resolved_session_token:
        raise HTTPException(status_code=400, detail="s3 session_token is required when auth_mode=session_token")

    bucket = (validation_bucket or "").strip()
    if not bucket:
        raise HTTPException(status_code=400, detail="s3 validation_bucket is required")

    _probe_s3_credentials(
        access_key_id=resolved_access_key_id,
        secret_access_key=resolved_secret_access_key,
        session_token=resolved_session_token,
        region=resolved_region,
        endpoint_url=resolved_endpoint_url,
        path_style=bool(path_style) if path_style is not None else False,
        validation_bucket=bucket,
    )

    return {
        "scopes": [],
        "metadata": {
            "region": resolved_region,
            "endpoint_url": resolved_endpoint_url,
            "path_style": bool(path_style) if path_style is not None else False,
            "auth_mode": resolved_auth_mode,
        },
        "secret_payload": {
            "access_key_id": resolved_access_key_id,
            "secret_access_key": resolved_secret_access_key,
            "session_token": resolved_session_token,
        },
    }


def validate_provider_token(
    provider: str,
    token: Optional[str],
    required_scopes: Optional[List[str]] = None,
    *,
    api_base_url: Optional[str] = None,
    access_key_id: Optional[str] = None,
    secret_access_key: Optional[str] = None,
    session_token: Optional[str] = None,
    region: Optional[str] = None,
    endpoint_url: Optional[str] = None,
    path_style: Optional[bool] = None,
    auth_mode: Optional[str] = None,
    validation_bucket: Optional[str] = None,
) -> Dict[str, Any]:
    normalized_provider = (provider or "").strip().lower()

    if normalized_provider == "github":
        if not token or not token.strip():
            raise HTTPException(status_code=400, detail="token is required")
        result = _validate_github_token(token.strip(), api_base_url=api_base_url)
    elif normalized_provider == "gitlab":
        if not token or not token.strip():
            raise HTTPException(status_code=400, detail="token is required")
        result = _validate_gitlab_token(token.strip(), api_base_url=api_base_url)
    elif normalized_provider == "google_drive":
        result = _validate_google_drive_token(token.strip())
    elif normalized_provider == "s3":
        result = _validate_s3_credentials_payload(
            token=token,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            region=region,
            endpoint_url=endpoint_url,
            path_style=path_style,
            auth_mode=auth_mode,
            validation_bucket=validation_bucket,
        )
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
    token: Optional[str],
    *,
    org: Optional[str] = None,
    required_scopes: Optional[List[str]] = None,
    api_base_url: Optional[str] = None,
    metadata_override: Optional[Dict[str, Any]] = None,
    scopes_override: Optional[List[str]] = None,
    access_key_id: Optional[str] = None,
    secret_access_key: Optional[str] = None,
    session_token: Optional[str] = None,
    region: Optional[str] = None,
    endpoint_url: Optional[str] = None,
    path_style: Optional[bool] = None,
    auth_mode: Optional[str] = None,
    validation_bucket: Optional[str] = None,
) -> ProviderCredentialModel:
    validated = validate_provider_token(
        provider,
        token,
        required_scopes=required_scopes,
        api_base_url=api_base_url,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        session_token=session_token,
        region=region,
        endpoint_url=endpoint_url,
        path_style=path_style,
        auth_mode=auth_mode,
        validation_bucket=validation_bucket,
    )

    token_to_encrypt = (token or "").strip()
    if (provider or "").strip().lower() == "s3":
        token_to_encrypt = json.dumps(validated.get("secret_payload") or {}, separators=(",", ":"))

    try:
        token_ct_b64 = kms_encrypt(token_to_encrypt)
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
    logger.info(
        "provider credential upserted",
        extra=_redacted_credential_log_payload(
            provider=model.provider,
            org=model.org,
            has_token=bool((token or "").strip()),
            has_access_key_id=bool((access_key_id or "").strip()),
            has_secret_access_key=bool((secret_access_key or "").strip()),
            has_session_token=bool((session_token or "").strip()),
            metadata=model.metadata,
        ),
    )
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

    out = {
        "token": token,
        "provider": cred.provider,
        "org": cred.org,
        "scopes": list(cred.scopes or []),
        "metadata": dict(cred.metadata or {}),
    }
    if (cred.provider or "").lower() == "s3":
        try:
            payload = json.loads(token)
        except ValueError:
            payload = {}
        if isinstance(payload, dict):
            out["access_key_id"] = str(payload.get("access_key_id") or "")
            out["secret_access_key"] = str(payload.get("secret_access_key") or "")
            out["session_token"] = str(payload.get("session_token") or "") or None
            out["token"] = out["secret_access_key"]
    return out




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
        logger.info(
            "provider credential delete no-op",
            extra={"provider": (provider or "").strip().lower(), "org": org, "deleted": False},
        )
        return {"ok": True, "deleted": False}
    if item.get("entity_type") != "provider_credential" or item.get("owner") != owner:
        raise HTTPException(status_code=404, detail="provider credential not found")
    T.projects.delete_item(Key=key)
    logger.info(
        "provider credential deleted",
        extra={"provider": str(item.get("provider") or "").strip().lower(), "org": item.get("org"), "deleted": True},
    )
    return {"ok": True, "deleted": True}
