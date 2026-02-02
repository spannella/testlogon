from __future__ import annotations

import base64
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

try:
    from webauthn import (
        generate_registration_options,
        generate_authentication_options,
        verify_registration_response,
        verify_authentication_response,
    )
    from webauthn.helpers.structs import (
        AuthenticationCredential,
        RegistrationCredential,
    PublicKeyCredentialDescriptor,
        PublicKeyCredentialParameters,
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialUserEntity,
    )
except Exception:  # pragma: no cover
    generate_registration_options = None  # type: ignore
    generate_authentication_options = None  # type: ignore
    verify_registration_response = None  # type: ignore
    verify_authentication_response = None  # type: ignore
    AuthenticationCredential = None  # type: ignore
    RegistrationCredential = None  # type: ignore
    PublicKeyCredentialDescriptor = None  # type: ignore
    PublicKeyCredentialParameters = None  # type: ignore
    PublicKeyCredentialRpEntity = None  # type: ignore
    PublicKeyCredentialUserEntity = None  # type: ignore

def _require_webauthn() -> None:
    if generate_registration_options is None:
        raise HTTPException(500, "webauthn not installed")
    if not S.webauthn_rp_id or not S.webauthn_origin:
        raise HTTPException(500, "WebAuthn not configured")

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def _b64url_to_bytes(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)

def _credential_pk(credential_id: bytes) -> str:
    return f"webauthn#{_b64url(credential_id)}"

def list_credentials(user_sub: str) -> List[Dict[str, Any]]:
    r = T.sessions.query(KeyConditionExpression=Key("user_sub").eq(user_sub), Limit=200)
    out = []
    for it in r.get("Items", []):
        sid = it.get("session_id", "")
        if not sid.startswith("webauthn#"):
            continue
        out.append({
            "credential_id": sid.replace("webauthn#", ""),
            "label": it.get("label", ""),
            "created_at": it.get("created_at", 0),
            "last_used_at": it.get("last_used_at", 0),
            "transports": it.get("transports", []),
        })
    out.sort(key=lambda x: int(x.get("created_at") or 0), reverse=True)
    return out

def store_registration_challenge(user_sub: str, challenge: bytes) -> None:
    T.sessions.put_item(Item={
        "user_sub": user_sub,
        "session_id": "webauthn_chal_register",
        "challenge_b64": _b64url(challenge),
        "created_at": now_ts(),
    })

def store_authentication_challenge(user_sub: str, challenge: bytes) -> None:
    T.sessions.put_item(Item={
        "user_sub": user_sub,
        "session_id": "webauthn_chal_auth",
        "challenge_b64": _b64url(challenge),
        "created_at": now_ts(),
    })

def load_challenge(user_sub: str, sid: str) -> bytes:
    it = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": sid}).get("Item") or {}
    raw = it.get("challenge_b64", "")
    if not raw:
        raise HTTPException(401, "Missing challenge")
    return _b64url_to_bytes(raw)

def delete_challenge(user_sub: str, sid: str) -> None:
    try:
        T.sessions.delete_item(Key={"user_sub": user_sub, "session_id": sid})
    except Exception:
        pass

def registration_options(user_sub: str, username: str) -> Dict[str, Any]:
    _require_webauthn()
    rp = PublicKeyCredentialRpEntity(id=S.webauthn_rp_id, name=S.webauthn_rp_name)
    user = PublicKeyCredentialUserEntity(
        id=user_sub.encode("utf-8"),
        name=username,
        display_name=username,
    )
    existing = [
        PublicKeyCredentialDescriptor(id=_b64url_to_bytes(c["credential_id"]))
        for c in list_credentials(user_sub)
    ]
    options = generate_registration_options(
        rp=rp,
        user=user,
        challenge=None,
        exclude_credentials=existing,
        pub_key_cred_params=[PublicKeyCredentialParameters(type="public-key", alg=-7)],
        timeout=60000,
        authenticator_selection=None,
    )
    store_registration_challenge(user_sub, options.challenge)
    return options.model_dump()

def register_credential(
    user_sub: str,
    username: str,
    credential: Dict[str, Any],
    label: Optional[str],
) -> Dict[str, Any]:
    _require_webauthn()
    challenge = load_challenge(user_sub, "webauthn_chal_register")
    reg = RegistrationCredential.parse_obj(credential)
    verification = verify_registration_response(
        credential=reg,
        expected_challenge=challenge,
        expected_origin=S.webauthn_origin,
        expected_rp_id=S.webauthn_rp_id,
        require_user_verification=True,
    )
    delete_challenge(user_sub, "webauthn_chal_register")
    credential_id = _b64url(verification.credential_id)
    item = {
        "user_sub": user_sub,
        "session_id": _credential_pk(verification.credential_id),
        "credential_id": credential_id,
        "public_key": verification.credential_public_key,
        "sign_count": verification.sign_count,
        "label": (label or "")[:64],
        "created_at": now_ts(),
        "last_used_at": 0,
        "transports": credential.get("transports", []),
    }
    T.sessions.put_item(Item=item)
    return {"credential_id": credential_id}

def authentication_options(user_sub: Optional[str]) -> Dict[str, Any]:
    _require_webauthn()
    allow = []
    if user_sub:
        allow = [
            PublicKeyCredentialDescriptor(id=_b64url_to_bytes(c["credential_id"]))
            for c in list_credentials(user_sub)
        ]
    options = generate_authentication_options(
        rp_id=S.webauthn_rp_id,
        allow_credentials=allow or None,
        timeout=60000,
        user_verification="required",
    )
    if user_sub:
        store_authentication_challenge(user_sub, options.challenge)
    return options.model_dump()

def verify_authentication(
    user_sub: str,
    credential: Dict[str, Any],
) -> Dict[str, Any]:
    _require_webauthn()
    auth = AuthenticationCredential.parse_obj(credential)
    challenge = load_challenge(user_sub, "webauthn_chal_auth")
    sid = _credential_pk(auth.raw_id)
    it = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": sid}).get("Item")
    if not it:
        raise HTTPException(401, "Unknown credential")
    verification = verify_authentication_response(
        credential=auth,
        expected_challenge=challenge,
        expected_origin=S.webauthn_origin,
        expected_rp_id=S.webauthn_rp_id,
        credential_public_key=it["public_key"],
        credential_current_sign_count=int(it.get("sign_count", 0) or 0),
        require_user_verification=True,
    )
    delete_challenge(user_sub, "webauthn_chal_auth")
    try:
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": sid},
            UpdateExpression="SET sign_count=:s, last_used_at=:t",
            ExpressionAttributeValues={":s": verification.new_sign_count, ":t": now_ts()},
        )
    except Exception:
        pass
    return {"credential_id": it.get("credential_id", "")}
