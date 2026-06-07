from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.core.normalize import normalize_email, normalize_phone
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.profile_discoverability import get_profile_discoverability_state
from app.services.filemanager import upload_profile_photo

PROFILE_FIELDS = (
    "display_name",
    "first_name",
    "middle_name",
    "last_name",
    "title",
    "description",
    "birthday",
    "gender",
    "location",
    "displayed_email",
    "displayed_telephone_number",
    "mailing_address",
    "languages",
    "profile_photo_url",
    "cover_photo_url",
    "locale",
)


# Profile fields that influence the discovery search index (GAP-0353 / SOC-003).
# Only these fields are read by app.services.discovery.index_user_for_discovery
# when (re)building a user's discovery tokens/metadata, so we only need to
# re-index when one of them actually changed in a given profile update.
DISCOVERY_FIELDS = frozenset(
    {
        "display_name",
        "description",
        "title",
        "profile_photo_url",
    }
)


# Identity-relevant profile fields whose change must trigger KYC re-screening
# for users with an approved KYC case (GAP-0259 / KYC-006 continuous monitoring).
SCREENING_SENSITIVE_PROFILE_FIELDS = frozenset(
    {
        "display_name",
        "first_name",
        "last_name",
        "birthday",
    }
)


# KYC case statuses whose address verification must be invalidated when the user
# changes their mailing address (GAP-0280 / KYC-018 §4.7). Terminal statuses
# (rejected, expired) are excluded — they need no re-verification. "approved" is
# included so a post-approval address change resets the verified status, closing
# the stale-verified tier-2 bypass.
_ADDRESS_INVALIDATION_STATUSES = frozenset(
    {
        "draft",
        "submitted",
        "under_review",
        "needs_more_info",
        "approved",
    }
)


PROFILE_VISIBILITY_LEVELS = ("public", "member", "private")
PROFILE_AUDIENCES = ("owner", "member", "public")
PROFILE_READ_NOT_FOUND_DETAIL = "Profile not found"

PROFILE_FIELD_VISIBILITY = {
    "display_name": "public",
    "first_name": "member",
    "middle_name": "member",
    "last_name": "member",
    "title": "public",
    "description": "public",
    "birthday": "private",
    "gender": "private",
    "location": "public",
    "displayed_email": "private",
    "displayed_telephone_number": "private",
    "mailing_address": "private",
    "languages": "member",
    "profile_photo_url": "public",
    "cover_photo_url": "public",
    "locale": "private",
}

if set(PROFILE_FIELD_VISIBILITY.keys()) != set(PROFILE_FIELDS):
    raise RuntimeError("PROFILE_FIELD_VISIBILITY must classify every PROFILE_FIELDS entry")
if any(level not in PROFILE_VISIBILITY_LEVELS for level in PROFILE_FIELD_VISIBILITY.values()):
    raise RuntimeError("PROFILE_FIELD_VISIBILITY contains invalid visibility levels")

ALLOWED_GENDERS = {
    "male",
    "female",
    "non_binary",
    "other",
    "prefer_not_to_say",
}

ALLOWED_LANGUAGE_LEVELS = {
    "A1",
    "A2",
    "B1",
    "B2",
    "C1",
    "C2",
    "basic",
    "intermediate",
    "advanced",
    "fluent",
    "native",
}

MAX_NAME_LEN = 80
MAX_TITLE_LEN = 120
MAX_DESC_LEN = 2000
MAX_LOCATION_LEN = 120
MAX_LANGUAGES = 20
MAX_ADDRESS_LINE_LEN = 120
MAX_PHOTO_BYTES = 10 * 1024 * 1024


def _clean_str(value: Optional[str], *, max_len: Optional[int] = None) -> Optional[str]:
    if value is None:
        return None
    trimmed = value.strip()
    if not trimmed:
        return None
    if max_len is not None and len(trimmed) > max_len:
        raise HTTPException(400, f"Value too long (max {max_len})")
    return trimmed


def _validate_birthday(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(400, "birthday must be YYYY-MM-DD") from exc
    if parsed > date.today():
        raise HTTPException(400, "birthday cannot be in the future")
    return value


def _normalize_language(lang: Dict[str, Any]) -> Dict[str, str]:
    name = _clean_str(lang.get("name"), max_len=64)
    level = _clean_str(lang.get("level"), max_len=16)
    if not name:
        raise HTTPException(400, "language name required")
    if not level or level not in ALLOWED_LANGUAGE_LEVELS:
        raise HTTPException(400, "invalid language level")
    return {"name": name, "level": level}


def _normalize_mailing_address(addr: Optional[Dict[str, Any]]) -> Optional[Dict[str, str]]:
    if addr is None:
        return None
    if not isinstance(addr, dict):
        raise HTTPException(400, "mailing_address must be an object")
    cleaned: Dict[str, Optional[str]] = {
        "line1": _clean_str(addr.get("line1"), max_len=MAX_ADDRESS_LINE_LEN),
        "line2": _clean_str(addr.get("line2"), max_len=MAX_ADDRESS_LINE_LEN),
        "city": _clean_str(addr.get("city"), max_len=MAX_ADDRESS_LINE_LEN),
        "state": _clean_str(addr.get("state"), max_len=MAX_ADDRESS_LINE_LEN),
        "postal_code": _clean_str(addr.get("postal_code"), max_len=MAX_ADDRESS_LINE_LEN),
        "country": _clean_str(addr.get("country"), max_len=64),
    }
    if not any(cleaned.values()):
        return None
    return {k: v for k, v in cleaned.items() if v is not None}


def normalize_profile_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if "display_name" in data:
        out["display_name"] = _clean_str(data.get("display_name"), max_len=MAX_NAME_LEN)
    if "first_name" in data:
        out["first_name"] = _clean_str(data.get("first_name"), max_len=MAX_NAME_LEN)
    if "middle_name" in data:
        out["middle_name"] = _clean_str(data.get("middle_name"), max_len=MAX_NAME_LEN)
    if "last_name" in data:
        out["last_name"] = _clean_str(data.get("last_name"), max_len=MAX_NAME_LEN)
    if "title" in data:
        out["title"] = _clean_str(data.get("title"), max_len=MAX_TITLE_LEN)
    if "description" in data:
        out["description"] = _clean_str(data.get("description"), max_len=MAX_DESC_LEN)
    if "birthday" in data:
        out["birthday"] = _validate_birthday(_clean_str(data.get("birthday")))
    if "gender" in data:
        gender = _clean_str(data.get("gender"), max_len=24)
        if gender and gender not in ALLOWED_GENDERS:
            raise HTTPException(400, "invalid gender")
        out["gender"] = gender
    if "location" in data:
        out["location"] = _clean_str(data.get("location"), max_len=MAX_LOCATION_LEN)
    if "displayed_email" in data:
        email = _clean_str(data.get("displayed_email"), max_len=254)
        out["displayed_email"] = normalize_email(email) if email else None
    if "displayed_telephone_number" in data:
        phone = _clean_str(data.get("displayed_telephone_number"), max_len=32)
        out["displayed_telephone_number"] = normalize_phone(phone) if phone else None
    if "mailing_address" in data:
        out["mailing_address"] = _normalize_mailing_address(data.get("mailing_address"))
    if "languages" in data:
        langs = data.get("languages") or []
        if not isinstance(langs, list):
            raise HTTPException(400, "languages must be a list")
        if len(langs) > MAX_LANGUAGES:
            raise HTTPException(400, "too many languages")
        out["languages"] = [_normalize_language(l) for l in langs]
    if "profile_photo_url" in data:
        out["profile_photo_url"] = _clean_str(data.get("profile_photo_url"), max_len=512)
    if "cover_photo_url" in data:
        out["cover_photo_url"] = _clean_str(data.get("cover_photo_url"), max_len=512)
    if "locale" in data:
        locale_val = _clean_str(data.get("locale"), max_len=10)
        # Validate against supported locales
        from app.core.settings import S as _settings
        supported = [loc.strip() for loc in _settings.i18n_supported_locales.split(",") if loc.strip()]
        if locale_val and locale_val not in supported:
            raise HTTPException(400, "unsupported locale")
        out["locale"] = locale_val
    return out


def empty_profile() -> Dict[str, Any]:
    return {
        "display_name": None,
        "first_name": None,
        "middle_name": None,
        "last_name": None,
        "title": None,
        "description": None,
        "birthday": None,
        "gender": None,
        "location": None,
        "displayed_email": None,
        "displayed_telephone_number": None,
        "mailing_address": None,
        "languages": [],
        "profile_photo_url": None,
        "cover_photo_url": None,
        "locale": None,
    }


def get_profile(user_sub: str) -> Dict[str, Any]:
    item = T.profile.get_item(Key={"user_sub": user_sub}).get("Item")
    if not item:
        return empty_profile()
    profile = item.get("profile") or {}
    merged = empty_profile()
    merged.update(profile)
    return merged


def resolve_profile_audience(*, requester_user_sub: Optional[str], target_user_sub: str) -> str:
    if requester_user_sub and requester_user_sub == target_user_sub:
        return "owner"
    if requester_user_sub:
        return "member"
    return "public"


def filter_profile_by_audience(profile: Dict[str, Any], *, audience: str) -> Dict[str, Any]:
    if audience not in PROFILE_AUDIENCES:
        raise ValueError(f"invalid profile audience: {audience}")
    if audience == "owner":
        return dict(profile)

    allowed_levels = {"public", "member"} if audience == "member" else {"public"}
    filtered = empty_profile()
    for field in PROFILE_FIELDS:
        if PROFILE_FIELD_VISIBILITY[field] in allowed_levels:
            filtered[field] = profile.get(field)
    return filtered


def get_profile_for_requester(*, target_user_sub: str, requester_user_sub: Optional[str]) -> Dict[str, Any]:
    audience = resolve_profile_audience(requester_user_sub=requester_user_sub, target_user_sub=target_user_sub)
    discoverability = get_profile_discoverability_state(target_user_sub).get("discoverability_status", "active")
    if discoverability == "deleted":
        raise HTTPException(status_code=404, detail=PROFILE_READ_NOT_FOUND_DETAIL)
    if discoverability in {"hidden", "deactivated"} and audience != "owner":
        raise HTTPException(status_code=404, detail=PROFILE_READ_NOT_FOUND_DETAIL)
    profile = get_profile(target_user_sub)
    return filter_profile_by_audience(profile, audience=audience)


def get_profile_identity(user_sub: str) -> Dict[str, Optional[str]]:
    profile = get_profile(user_sub)
    display_name = profile.get("display_name")
    if not display_name:
        parts = [profile.get("first_name"), profile.get("last_name")]
        display_name = " ".join(p for p in parts if p) or None
    return {
        "display_name": display_name,
        "email": profile.get("displayed_email"),
        "phone": profile.get("displayed_telephone_number"),
        "profile_photo_url": profile.get("profile_photo_url"),
    }


def get_audit_log(user_sub: str) -> List[Dict[str, Any]]:
    item = T.profile.get_item(Key={"user_sub": user_sub}).get("Item")
    return list(item.get("audit", [])) if item else []


def save_profile(user_sub: str, profile: Dict[str, Any], audit_entries: List[Dict[str, Any]]) -> None:
    item = T.profile.get_item(Key={"user_sub": user_sub}).get("Item") or {}
    existing_audit = list(item.get("audit", []))
    combined_audit = (audit_entries + existing_audit)[:50]
    T.profile.put_item(Item={
        "user_sub": user_sub,
        "profile": profile,
        "audit": combined_audit,
        "updated_at": now_ts(),
    })


def apply_profile_update(user_sub: str, updates: Dict[str, Any], *, replace: bool) -> Dict[str, Any]:
    current = get_profile(user_sub)
    base = empty_profile() if replace else current
    normalized = normalize_profile_payload(updates)
    updated = {**base, **normalized}

    audit_entries: List[Dict[str, Any]] = []
    ts = now_ts()
    address_changed = False
    discovery_changed = False
    for field in PROFILE_FIELDS:
        if current.get(field) != updated.get(field):
            audit_entries.append({
                "ts": ts,
                "field": field,
                "from": current.get(field),
                "to": updated.get(field),
            })
            if field == "mailing_address":
                address_changed = True
            if field in DISCOVERY_FIELDS:
                discovery_changed = True

    save_profile(user_sub, updated, audit_entries)

    # GAP-0280 (KYC-018 §4.7): when the user's mailing address changes, any active
    # KYC case's address verification must be invalidated so a stale "verified"
    # status cannot pass tier-2 readiness with an outdated address. Best-effort:
    # the profile write above is already committed and must never be rolled back.
    if address_changed:
        _invalidate_address_verification_for_user(user_sub)

    # GAP-0353 (SOC-003 §4.6): (re)populate the discovery search index after the
    # profile is saved so updated/new profiles appear and refresh in discovery
    # search immediately (previously they were only findable by their old name
    # until the periodic re-index ran, and brand-new users were never indexed).
    # Guarded on whether a discovery-relevant field actually changed (idempotent
    # + cheaper). Best-effort: a discovery-index failure must NEVER fail the
    # profile update, and the import is lazy to avoid any circular-import risk.
    if discovery_changed:
        _reindex_user_for_discovery(user_sub)

    return updated


def _reindex_user_for_discovery(user_sub: str) -> None:
    """(Re)build the user's discovery search index after a profile save.

    Called only when a discovery-relevant profile field changed. Never raises —
    failures are logged and suppressed so a legitimate profile update is never
    blocked by a discovery-index error (the profile write is already committed).
    The import is lazy to avoid a circular dependency with app.services.discovery.

    Runs identically in dev and prod (SECOPS-007): index_user_for_discovery
    writes to the same DynamoDB discovery table in either environment.
    """
    import logging

    _log = logging.getLogger(__name__)
    try:
        from app.services.discovery import index_user_for_discovery

        index_user_for_discovery(user_sub)
    except Exception:  # pragma: no cover - defensive; must never block profile save
        _log.exception(
            "discovery.reindex_on_profile_update_error user_sub=%s", user_sub
        )


def _invalidate_address_verification_for_user(user_sub: str) -> None:
    """Invalidate address verification for the user's active KYC cases.

    Called after a successful profile save when a mailing-address field changed.
    Never raises — failures are logged and suppressed so a legitimate profile
    update is never blocked by a cross-service KYC error. Imports are lazy to
    avoid a circular dependency (kyc_cases / kyc_address_verification import
    table handles that the profile service does not need at module load).

    Runs identically in dev and prod (SECOPS-007): both stores write to the same
    DynamoDB tables in either environment, and invalidate_verification exits
    silently when no verification record exists.
    """
    import logging

    _log = logging.getLogger(__name__)
    try:
        from app.services.kyc_cases import STORE as _case_store
        from app.services.kyc_address_verification import STORE as _address_store

        cases = _case_store.list_cases_by_owner(user_sub=user_sub, limit=25)
        for case in cases:
            if str(case.get("status", "")) not in _ADDRESS_INVALIDATION_STATUSES:
                continue
            case_id = str(case.get("kyc_case_id") or "")
            if not case_id:
                continue
            _address_store.invalidate_verification(
                case_id=case_id,
                reason="address_changed",
            )
            _log.info(
                "kyc.address.invalidated_on_profile_update user_sub=%s case_id=%s",
                user_sub,
                case_id,
            )
    except Exception:  # pragma: no cover - defensive; must never block profile save
        _log.exception(
            "kyc.address.profile_invalidation_error user_sub=%s", user_sub
        )


def store_profile_photo(
    user_sub: str,
    kind: str,
    file_name: str,
    content: bytes,
    *,
    content_type: Optional[str] = None,
) -> str:
    if kind not in {"profile", "cover"}:
        raise HTTPException(400, "invalid photo kind")
    if len(content) > MAX_PHOTO_BYTES:
        raise HTTPException(400, "photo too large")
    if S.filemgr_table_name and S.filemgr_bucket:
        result = upload_profile_photo(
            user_sub,
            kind=kind,
            file_name=file_name,
            content=content,
            content_type=content_type,
        )
        url = result.get("url")
        if url:
            return url
    safe_name = file_name.replace("/", "_")
    upload_dir = Path(__file__).resolve().parents[1] / "static" / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    ts = now_ts()
    out_name = f"{user_sub}_{kind}_{ts}_{safe_name}"
    out_path = upload_dir / out_name
    out_path.write_bytes(content)
    return f"{S.public_base_url}/static/uploads/{out_name}"
