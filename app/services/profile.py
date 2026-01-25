from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.core.normalize import normalize_email, normalize_phone
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
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
)

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
        "country": _clean_str(addr.get("country"), max_len=2),
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
    }


def get_profile(user_sub: str) -> Dict[str, Any]:
    item = T.profile.get_item(Key={"user_sub": user_sub}).get("Item")
    if not item:
        return empty_profile()
    profile = item.get("profile") or {}
    merged = empty_profile()
    merged.update(profile)
    return merged


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
    for field in PROFILE_FIELDS:
        if current.get(field) != updated.get(field):
            audit_entries.append({
                "ts": ts,
                "field": field,
                "from": current.get(field),
                "to": updated.get(field),
            })

    save_profile(user_sub, updated, audit_entries)
    return updated


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
        return result["url"]
    safe_name = file_name.replace("/", "_")
    upload_dir = Path(__file__).resolve().parents[1] / "static" / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    ts = now_ts()
    out_name = f"{user_sub}_{kind}_{ts}_{safe_name}"
    out_path = upload_dir / out_name
    out_path.write_bytes(content)
    return f"{S.public_base_url}/static/uploads/{out_name}"
