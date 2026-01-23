# app.py
import os
import re
import time
import json
import secrets
from datetime import date
from typing import Any, Dict, List, Optional, Literal, Tuple

import boto3
from botocore.exceptions import ClientError
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, constr

# --------------------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------------------

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
DDB_TABLE = os.environ["DDB_TABLE"]

S3_BUCKET = os.environ["S3_BUCKET"]
S3_PREFIX = os.environ.get("S3_PREFIX", "profiles").strip("/")

# URL base that clients will use to view the file after upload (CDN or s3 public base)
S3_PUBLIC_BASE_URL = os.environ.get("S3_PUBLIC_BASE_URL", "").rstrip("/")

PHOTO_MAX_BYTES = int(os.environ.get("PHOTO_MAX_BYTES", str(10 * 1024 * 1024)))  # 10MB
PHOTO_URL_TTL_SECONDS = int(os.environ.get("PHOTO_URL_TTL_SECONDS", "900"))  # 15 min

MAX_LANGUAGES = int(os.environ.get("MAX_LANGUAGES", "20"))
MAX_DESC_LEN = int(os.environ.get("MAX_DESC_LEN", "2000"))
MAX_TITLE_LEN = int(os.environ.get("MAX_TITLE_LEN", "120"))
MAX_LOCATION_LEN = int(os.environ.get("MAX_LOCATION_LEN", "120"))
MAX_NAME_LEN = int(os.environ.get("MAX_NAME_LEN", "80"))
MAX_ADDRESS_LINE_LEN = int(os.environ.get("MAX_ADDRESS_LINE_LEN", "120"))
MAX_AGE_YEARS = int(os.environ.get("MAX_AGE_YEARS", "120"))

ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
tbl = ddb.Table(DDB_TABLE)

s3 = boto3.client("s3", region_name=AWS_REGION)
ddb_client = boto3.client("dynamodb", region_name=AWS_REGION)

app = FastAPI(title="Profile Service (FastAPI + DynamoDB + S3 Uploads + Field Audit + Validations)")

# --------------------------------------------------------------------------------------
# Validation regex / constants
# --------------------------------------------------------------------------------------

_email_re = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# E.164-ish (allow spaces/parens/dashes); if you want strict E.164, tighten this.
_phone_re = re.compile(r"^\+?[0-9][0-9 \-\(\)]{6,}$")

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'\-]{0,79}$")
DISPLAY_NAME_RE = re.compile(r"^[^\s].{0,79}[^\s]$")
TITLE_RE = re.compile(r"^[^\s].{0,119}[^\s]$")
LOCATION_RE = re.compile(r"^[^\s].{0,119}[^\s]$")
LANGUAGE_RE = re.compile(r"^[A-Za-z][A-Za-z \-']{0,63}$")
COUNTRY_ISO2_RE = re.compile(r"^[A-Z]{2}$")
POSTAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 \-]{0,15}$")
STATE_RE = re.compile(r"^[A-Za-z0-9 .'\-]{0,64}$")

ALLOWED_LANGUAGE_LEVELS = {
    "A1", "A2", "B1", "B2", "C1", "C2",
    "basic", "intermediate", "advanced", "fluent", "native",
}

ALLOWED_IMAGE_CT = {"image/jpeg", "image/png", "image/webp"}

# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

def now_ms() -> int:
    return int(time.time() * 1000)

def require_user_id(x_user_id: Optional[str]) -> str:
    if not x_user_id or not x_user_id.strip():
        raise HTTPException(status_code=401, detail="Missing X-User-Id")
    return x_user_id.strip()

def key_for_user(user_id: str) -> Dict[str, str]:
    return {"pk": f"USER#{user_id}", "sk": "PROFILE"}

def audit_pk(user_id: str) -> str:
    return f"USER#{user_id}"

def audit_sk(ts_ms: int) -> str:
    return f"AUDIT#{ts_ms:013d}#{secrets.token_hex(4)}"

def s3_object_url(key: str) -> str:
    if S3_PUBLIC_BASE_URL:
        return f"{S3_PUBLIC_BASE_URL}/{key}"
    return f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{key}"

def get_actor_context(req: Request, user_id: str) -> Dict[str, Any]:
    return {
        "actor_user_id": user_id,
        "ip": req.client.host if req.client else None,
        "user_agent": req.headers.get("user-agent"),
        "request_id": req.headers.get("x-request-id"),
    }

def _clean(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    s2 = s.strip()
    return s2 if s2 else None

def validate_email(email: str) -> None:
    if not _email_re.match(email):
        raise HTTPException(status_code=400, detail="Invalid displayed_email")

def validate_phone(phone: str) -> None:
    if not _phone_re.match(phone):
        raise HTTPException(status_code=400, detail="Invalid displayed_telephone_number")

def validate_name(field: str, value: Optional[str]) -> Optional[str]:
    value = _clean(value)
    if value is None:
        return None
    if len(value) > MAX_NAME_LEN:
        raise HTTPException(status_code=400, detail=f"{field} too long")
    if not NAME_RE.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {field}")
    return value

def validate_display_name(value: Optional[str]) -> Optional[str]:
    value = _clean(value)
    if value is None:
        return None
    if len(value) > MAX_NAME_LEN:
        raise HTTPException(status_code=400, detail="display_name too long")
    if not DISPLAY_NAME_RE.match(value):
        raise HTTPException(status_code=400, detail="Invalid display_name")
    return value

def validate_title(value: Optional[str]) -> Optional[str]:
    value = _clean(value)
    if value is None:
        return None
    if len(value) > MAX_TITLE_LEN:
        raise HTTPException(status_code=400, detail="title too long")
    if not TITLE_RE.match(value):
        raise HTTPException(status_code=400, detail="Invalid title")
    return value

def validate_description(value: Optional[str]) -> Optional[str]:
    value = _clean(value)
    if value is None:
        return None
    if len(value) > MAX_DESC_LEN:
        raise HTTPException(status_code=400, detail="description too long")
    return value

def validate_location(value: Optional[str]) -> Optional[str]:
    value = _clean(value)
    if value is None:
        return None
    if len(value) > MAX_LOCATION_LEN:
        raise HTTPException(status_code=400, detail="location too long")
    if not LOCATION_RE.match(value):
        raise HTTPException(status_code=400, detail="Invalid location")
    return value

def validate_birthday_str(bday: Optional[str]) -> Optional[str]:
    bday = _clean(bday)
    if bday is None:
        return None
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", bday):
        raise HTTPException(status_code=400, detail="birthday must be YYYY-MM-DD")
    try:
        y, m, d = map(int, bday.split("-"))
        bd = date(y, m, d)
    except Exception:
        raise HTTPException(status_code=400, detail="birthday is not a valid calendar date")

    today = date.today()
    if bd > today:
        raise HTTPException(status_code=400, detail="birthday cannot be in the future")

    age_years = today.year - bd.year - ((today.month, today.day) < (bd.month, bd.day))
    if age_years > MAX_AGE_YEARS:
        raise HTTPException(status_code=400, detail=f"birthday implies age > {MAX_AGE_YEARS}")

    return bday

def validate_mailing_address(addr: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if addr is None:
        return None
    if not isinstance(addr, dict):
        raise HTTPException(status_code=400, detail="mailing_address must be an object")

    out: Dict[str, Optional[str]] = {}
    for k in ["line1", "line2", "city", "state", "postal_code", "country"]:
        out[k] = _clean(addr.get(k))

    provided = any(v is not None for v in out.values())
    if not provided:
        return None

    if not out["line1"] or len(out["line1"]) > MAX_ADDRESS_LINE_LEN:
        raise HTTPException(status_code=400, detail="mailing_address.line1 required (reasonable length)")
    if out["line2"] and len(out["line2"]) > MAX_ADDRESS_LINE_LEN:
        raise HTTPException(status_code=400, detail="mailing_address.line2 too long")
    if not out["city"] or len(out["city"]) > 80:
        raise HTTPException(status_code=400, detail="mailing_address.city required")
    if out["state"] and (len(out["state"]) > 64 or not STATE_RE.match(out["state"])):
        raise HTTPException(status_code=400, detail="mailing_address.state invalid")
    if out["postal_code"] and (len(out["postal_code"]) > 16 or not POSTAL_RE.match(out["postal_code"])):
        raise HTTPException(status_code=400, detail="mailing_address.postal_code invalid")

    if not out["country"]:
        raise HTTPException(status_code=400, detail="mailing_address.country required (ISO-2)")
    out["country"] = out["country"].upper()
    if not COUNTRY_ISO2_RE.match(out["country"]):
        raise HTTPException(status_code=400, detail="mailing_address.country must be ISO-2 (e.g. US, PR, GB)")

    return {k: v for k, v in out.items() if v is not None}

def validate_languages_list(langs: Optional[List[Dict[str, Any]]]) -> Optional[List[Dict[str, str]]]:
    if langs is None:
        return None
    if not isinstance(langs, list):
        raise HTTPException(status_code=400, detail="languages must be a list")
    if len(langs) > MAX_LANGUAGES:
        raise HTTPException(status_code=400, detail=f"Too many languages (max {MAX_LANGUAGES})")

    seen: Dict[str, Dict[str, str]] = {}
    for entry in langs:
        if not isinstance(entry, dict):
            raise HTTPException(status_code=400, detail="languages entries must be objects")
        lang = _clean(entry.get("language"))
        lvl = _clean(entry.get("level"))
        if not lang or not lvl:
            raise HTTPException(status_code=400, detail="languages entries require language and level")
        if not LANGUAGE_RE.match(lang):
            raise HTTPException(status_code=400, detail=f"Invalid language name: {lang}")

        lvl_norm = lvl.upper() if lvl.upper() in {"A1","A2","B1","B2","C1","C2"} else lvl.lower()
        if lvl_norm not in ALLOWED_LANGUAGE_LEVELS:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid language level '{lvl}'. Allowed: {sorted(ALLOWED_LANGUAGE_LEVELS)}"
            )
        seen[lang.casefold()] = {"language": lang, "level": lvl_norm}

    return list(seen.values())

def validate_filename_optional(name: Optional[str]) -> None:
    if not name:
        return
    name = name.strip()
    if len(name) > 256:
        raise HTTPException(status_code=400, detail="filename too long")
    if "/" in name or "\\" in name:
        raise HTTPException(status_code=400, detail="filename must not contain path separators")

def validate_profile_fields(p: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates and normalizes known profile fields. Returns a sanitized copy.
    """
    out = dict(p)

    if "display_name" in out:
        out["display_name"] = validate_display_name(out.get("display_name"))
    if "first_name" in out:
        out["first_name"] = validate_name("first_name", out.get("first_name"))
    if "last_name" in out:
        out["last_name"] = validate_name("last_name", out.get("last_name"))
    if "middle_name" in out:
        out["middle_name"] = validate_name("middle_name", out.get("middle_name"))
    if "title" in out:
        out["title"] = validate_title(out.get("title"))
    if "description" in out:
        out["description"] = validate_description(out.get("description"))

    if "birthday" in out:
        out["birthday"] = validate_birthday_str(out.get("birthday"))

    if "location" in out:
        out["location"] = validate_location(out.get("location"))

    if "displayed_email" in out:
        out["displayed_email"] = _clean(out.get("displayed_email"))
        if out["displayed_email"] is not None:
            validate_email(out["displayed_email"])

    if "displayed_telephone_number" in out:
        out["displayed_telephone_number"] = _clean(out.get("displayed_telephone_number"))
        if out["displayed_telephone_number"] is not None:
            validate_phone(out["displayed_telephone_number"])

    if "mailing_address" in out:
        addr = out.get("mailing_address")
        if hasattr(addr, "model_dump"):
            addr = addr.model_dump()
        out["mailing_address"] = validate_mailing_address(addr)

    if "languages" in out:
        langs = out.get("languages")
        if langs is not None and hasattr(langs, "__iter__") and not isinstance(langs, list):
            # defensive
            langs = list(langs)
        out["languages"] = validate_languages_list(langs)

    return out

def validate_patch_fields(updates: Dict[str, Any]) -> Dict[str, Any]:
    sanitized = validate_profile_fields(dict(updates))
    return {k: sanitized.get(k) for k in updates.keys()}

# --------------------------------------------------------------------------------------
# DynamoDB access
# --------------------------------------------------------------------------------------

def ddb_get_profile(user_id: str) -> Dict[str, Any]:
    try:
        resp = tbl.get_item(Key=key_for_user(user_id), ConsistentRead=True)
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {e.response.get('Error', {}).get('Message', str(e))}")
    item = resp.get("Item")
    if not item:
        return {}
    return item.get("profile", {}) or {}

def compute_field_changes(old_profile: Dict[str, Any], new_profile: Dict[str, Any]) -> List[Tuple[str, Any, Any]]:
    fields = [
        "display_name", "first_name", "last_name", "middle_name", "title", "description",
        "birthday", "location", "profile_photo", "cover_photo",
        "displayed_email", "displayed_telephone_number", "gender",
        "languages", "mailing_address",
    ]
    changes: List[Tuple[str, Any, Any]] = []
    for f in fields:
        o = old_profile.get(f)
        n = new_profile.get(f)
        if o != n:
            changes.append((f, o, n))
    return changes

def write_profile_and_audit(
    user_id: str,
    old_profile: Dict[str, Any],
    new_profile: Dict[str, Any],
    actor: Dict[str, Any],
    reason: str,
) -> None:
    ts = now_ms()
    changes = compute_field_changes(old_profile, new_profile)

    profile_item = {
        "pk": f"USER#{user_id}",
        "sk": "PROFILE",
        "profile": new_profile,
        "updated_at_ms": ts,
    }
    if not old_profile:
        profile_item["created_at_ms"] = ts

    transact_items = [{"Put": {"TableName": DDB_TABLE, "Item": profile_item}}]

    for (field, oldv, newv) in changes:
        audit_item = {
            "pk": audit_pk(user_id),
            "sk": audit_sk(ts),
            "ts_ms": ts,
            "event": "PROFILE_FIELD_CHANGED",
            "field": field,
            "old_value": oldv,
            "new_value": newv,
            "reason": reason,
            **actor,
        }
        transact_items.append({"Put": {"TableName": DDB_TABLE, "Item": audit_item}})

    if len(transact_items) > 25:
        # Should never happen with our bounded fields; safe-guard.
        raise HTTPException(status_code=500, detail="Too many audit items in one transaction")

    try:
        ddb_client.transact_write_items(TransactItems=transact_items)
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"DynamoDB transact error: {e.response.get('Error', {}).get('Message', str(e))}")

# --------------------------------------------------------------------------------------
# S3 upload helpers
# --------------------------------------------------------------------------------------

def assert_image_content_type(ct: str) -> None:
    if ct.lower() not in ALLOWED_IMAGE_CT:
        raise HTTPException(status_code=400, detail=f"Unsupported content_type. Allowed: {sorted(ALLOWED_IMAGE_CT)}")

def build_photo_key(user_id: str, kind: str, content_type: str) -> str:
    ext = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp"}.get(content_type.lower(), "bin")
    ts = now_ms()
    rand = secrets.token_hex(8)
    return f"{S3_PREFIX}/{user_id}/photos/{kind}/{ts}_{rand}.{ext}"

def presign_put_url(bucket: str, key: str, content_type: str) -> Tuple[str, Dict[str, str]]:
    try:
        url = s3.generate_presigned_url(
            ClientMethod="put_object",
            Params={"Bucket": bucket, "Key": key, "ContentType": content_type},
            ExpiresIn=PHOTO_URL_TTL_SECONDS,
        )
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"S3 presign error: {e.response.get('Error', {}).get('Message', str(e))}")
    headers = {"Content-Type": content_type}
    return url, headers

def ensure_key_is_under_user(user_id: str, key: str) -> None:
    prefix = f"{S3_PREFIX}/{user_id}/photos/"
    if not key.startswith(prefix):
        raise HTTPException(status_code=400, detail="s3_key not in allowed prefix for this user")

def head_object_or_400(key: str) -> Dict[str, Any]:
    try:
        return s3.head_object(Bucket=S3_BUCKET, Key=key)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("404", "NoSuchKey", "NotFound"):
            raise HTTPException(status_code=400, detail="Uploaded object not found (head_object failed)")
        raise HTTPException(status_code=500, detail=f"S3 head_object error: {e.response.get('Error', {}).get('Message', str(e))}")

# --------------------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------------------

Gender = Literal["male", "female", "non_binary", "other", "prefer_not_to_say"]
PhotoKind = Literal["profile_photo", "cover_photo"]

class MailingAddress(BaseModel):
    line1: Optional[str] = None
    line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None

class LanguageEntry(BaseModel):
    language: constr(strip_whitespace=True, min_length=1, max_length=64)
    level: constr(strip_whitespace=True, min_length=1, max_length=32)

class Profile(BaseModel):
    display_name: Optional[constr(strip_whitespace=True, min_length=1, max_length=80)] = None
    first_name: Optional[constr(strip_whitespace=True, min_length=1, max_length=80)] = None
    last_name: Optional[constr(strip_whitespace=True, min_length=1, max_length=80)] = None
    middle_name: Optional[constr(strip_whitespace=True, min_length=1, max_length=80)] = None
    title: Optional[constr(strip_whitespace=True, min_length=1, max_length=120)] = None
    description: Optional[constr(strip_whitespace=True, min_length=1, max_length=2000)] = None
    birthday: Optional[constr(strip_whitespace=True, min_length=10, max_length=10)] = Field(default=None, description="YYYY-MM-DD")
    location: Optional[constr(strip_whitespace=True, min_length=1, max_length=120)] = None
    mailing_address: Optional[MailingAddress] = None

    profile_photo: Optional[constr(strip_whitespace=True, min_length=1, max_length=2048)] = None
    cover_photo: Optional[constr(strip_whitespace=True, min_length=1, max_length=2048)] = None

    displayed_email: Optional[constr(strip_whitespace=True, min_length=3, max_length=254)] = None
    displayed_telephone_number: Optional[constr(strip_whitespace=True, min_length=7, max_length=32)] = None

    languages: Optional[List[LanguageEntry]] = None
    gender: Optional[Gender] = None

class ProfileSetRequest(Profile):
    pass

class ProfilePatchRequest(BaseModel):
    display_name: Optional[constr(strip_whitespace=True, min_length=1, max_length=80)] = None
    first_name: Optional[constr(strip_whitespace=True, min_length=1, max_length=80)] = None
    last_name: Optional[constr(strip_whitespace=True, min_length=1, max_length=80)] = None
    middle_name: Optional[constr(strip_whitespace=True, min_length=1, max_length=80)] = None
    title: Optional[constr(strip_whitespace=True, min_length=1, max_length=120)] = None
    description: Optional[constr(strip_whitespace=True, min_length=1, max_length=2000)] = None
    birthday: Optional[constr(strip_whitespace=True, min_length=10, max_length=10)] = None
    location: Optional[constr(strip_whitespace=True, min_length=1, max_length=120)] = None
    mailing_address: Optional[MailingAddress] = None
    displayed_email: Optional[constr(strip_whitespace=True, min_length=3, max_length=254)] = None
    displayed_telephone_number: Optional[constr(strip_whitespace=True, min_length=7, max_length=32)] = None
    gender: Optional[Gender] = None

class LanguageAddRequest(LanguageEntry):
    pass

class LanguageRemoveRequest(BaseModel):
    language: constr(strip_whitespace=True, min_length=1, max_length=64)

class ClearFieldRequest(BaseModel):
    field: Literal[
        "display_name", "first_name", "last_name", "middle_name", "title", "description",
        "birthday", "location", "mailing_address", "profile_photo", "cover_photo",
        "displayed_email", "displayed_telephone_number", "languages", "gender"
    ]

class PhotoPresignRequest(BaseModel):
    kind: PhotoKind
    content_type: constr(strip_whitespace=True, min_length=3, max_length=128)
    size_bytes: int = Field(ge=1, le=PHOTO_MAX_BYTES)
    filename: Optional[constr(strip_whitespace=True, min_length=1, max_length=256)] = None

class PhotoPresignResponse(BaseModel):
    upload_url: str
    method: Literal["PUT"] = "PUT"
    headers: Dict[str, str]
    s3_key: str
    public_url: str
    expires_in_seconds: int

class PhotoCommitRequest(BaseModel):
    kind: PhotoKind
    s3_key: constr(strip_whitespace=True, min_length=1, max_length=1024)

class AuditEvent(BaseModel):
    ts_ms: int
    event: str
    field: str
    old_value: Any = None
    new_value: Any = None
    reason: Optional[str] = None
    actor_user_id: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None

# --------------------------------------------------------------------------------------
# Routes: Profile
# --------------------------------------------------------------------------------------

@app.get("/v1/profile", response_model=Profile)
def get_profile(x_user_id: Optional[str] = Header(default=None, alias="X-User-Id")):
    user_id = require_user_id(x_user_id)
    return ddb_get_profile(user_id)

@app.put("/v1/profile", response_model=Profile)
async def set_profile(req: ProfileSetRequest, request: Request, x_user_id: Optional[str] = Header(default=None, alias="X-User-Id")):
    user_id = require_user_id(x_user_id)
    actor = get_actor_context(request, user_id)

    old = ddb_get_profile(user_id)
    newp = validate_profile_fields(req.model_dump())

    write_profile_and_audit(
        user_id=user_id,
        old_profile=old,
        new_profile=newp,
        actor=actor,
        reason="PROFILE_PUT",
    )
    return newp

@app.patch("/v1/profile", response_model=Profile)
async def patch_profile(req: ProfilePatchRequest, request: Request, x_user_id: Optional[str] = Header(default=None, alias="X-User-Id")):
    user_id = require_user_id(x_user_id)
    actor = get_actor_context(request, user_id)

    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    updates = validate_patch_fields(updates)

    old = ddb_get_profile(user_id)
    newp = dict(old)
    newp.update(updates)

    write_profile_and_audit(
        user_id=user_id,
        old_profile=old,
        new_profile=newp,
        actor=actor,
        reason="PROFILE_PATCH",
    )
    return newp

@app.post("/v1/profile/languages", response_model=Profile)
async def add_language(req: LanguageAddRequest, request: Request, x_user_id: Optional[str] = Header(default=None, alias="X-User-Id")):
    user_id = require_user_id(x_user_id)
    actor = get_actor_context(request, user_id)

    old = ddb_get_profile(user_id)
    langs = old.get("languages") or []
    lang_key = req.language.strip().casefold()

    new_langs: List[Dict[str, str]] = []
    replaced = False
    for e in langs:
        if (e.get("language") or "").strip().casefold() == lang_key:
            new_langs.append({"language": req.language.strip(), "level": req.level.strip()})
            replaced = True
        else:
            new_langs.append(e)
    if not replaced:
        new_langs.append({"language": req.language.strip(), "level": req.level.strip()})

    validated_langs = validate_languages_list(new_langs) or []
    if len(validated_langs) > MAX_LANGUAGES:
        raise HTTPException(status_code=400, detail=f"Too many languages (max {MAX_LANGUAGES})")

    newp = dict(old)
    newp["languages"] = validated_langs

    write_profile_and_audit(
        user_id=user_id,
        old_profile=old,
        new_profile=newp,
        actor=actor,
        reason="LANGUAGE_UPSERT",
    )
    return newp

@app.delete("/v1/profile/languages", response_model=Profile)
async def remove_language(req: LanguageRemoveRequest, request: Request, x_user_id: Optional[str] = Header(default=None, alias="X-User-Id")):
    user_id = require_user_id(x_user_id)
    actor = get_actor_context(request, user_id)

    old = ddb_get_profile(user_id)
    langs = old.get("languages") or []
    target = req.language.strip().casefold()

    newp = dict(old)
    newp["languages"] = [e for e in langs if (e.get("language") or "").strip().casefold() != target]

    # Validate after removal too (also normalizes levels)
    newp = validate_profile_fields(newp)

    write_profile_and_audit(
        user_id=user_id,
        old_profile=old,
        new_profile=newp,
        actor=actor,
        reason="LANGUAGE_REMOVE",
    )
    return newp

@app.post("/v1/profile/clear", response_model=Profile)
async def clear_field(req: ClearFieldRequest, request: Request, x_user_id: Optional[str] = Header(default=None, alias="X-User-Id")):
    user_id = require_user_id(x_user_id)
    actor = get_actor_context(request, user_id)

    old = ddb_get_profile(user_id)
    newp = dict(old)
    newp.pop(req.field, None)

    write_profile_and_audit(
        user_id=user_id,
        old_profile=old,
        new_profile=newp,
        actor=actor,
        reason=f"FIELD_CLEAR:{req.field}",
    )
    return newp

# --------------------------------------------------------------------------------------
# Routes: Photo uploads (presign + commit)
# --------------------------------------------------------------------------------------

@app.post("/v1/profile/photos/presign", response_model=PhotoPresignResponse)
async def presign_photo_upload(req: PhotoPresignRequest, request: Request, x_user_id: Optional[str] = Header(default=None, alias="X-User-Id")):
    user_id = require_user_id(x_user_id)

    assert_image_content_type(req.content_type)
    validate_filename_optional(req.filename)

    if req.size_bytes > PHOTO_MAX_BYTES:
        raise HTTPException(status_code=400, detail=f"size_bytes exceeds max {PHOTO_MAX_BYTES}")

    key = build_photo_key(user_id=user_id, kind=req.kind, content_type=req.content_type)
    url, headers = presign_put_url(S3_BUCKET, key, req.content_type)

    return PhotoPresignResponse(
        upload_url=url,
        headers=headers,
        s3_key=key,
        public_url=s3_object_url(key),
        expires_in_seconds=PHOTO_URL_TTL_SECONDS,
    )

@app.post("/v1/profile/photos/commit", response_model=Profile)
async def commit_photo(req: PhotoCommitRequest, request: Request, x_user_id: Optional[str] = Header(default=None, alias="X-User-Id")):
    user_id = require_user_id(x_user_id)
    actor = get_actor_context(request, user_id)

    ensure_key_is_under_user(user_id, req.s3_key)

    head = head_object_or_400(req.s3_key)
    ct = (head.get("ContentType") or "").lower()
    if ct not in ALLOWED_IMAGE_CT:
        raise HTTPException(status_code=400, detail=f"Uploaded object ContentType not allowed: {ct}")

    size = int(head.get("ContentLength") or 0)
    if size <= 0 or size > PHOTO_MAX_BYTES:
        raise HTTPException(status_code=400, detail="Uploaded object size invalid")

    old = ddb_get_profile(user_id)
    newp = dict(old)
    newp[req.kind] = s3_object_url(req.s3_key)

    write_profile_and_audit(
        user_id=user_id,
        old_profile=old,
        new_profile=newp,
        actor=actor,
        reason=f"PHOTO_COMMIT:{req.kind}",
    )
    return newp

# --------------------------------------------------------------------------------------
# Routes: Audit history
# --------------------------------------------------------------------------------------

@app.get("/v1/profile/audit", response_model=List[AuditEvent])
def list_audit(
    x_user_id: Optional[str] = Header(default=None, alias="X-User-Id"),
    limit: int = 50,
    cursor: Optional[str] = None,
):
    user_id = require_user_id(x_user_id)
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="limit must be 1..200")

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": "#pk = :pk AND begins_with(#sk, :pfx)",
        "ExpressionAttributeNames": {"#pk": "pk", "#sk": "sk"},
        "ExpressionAttributeValues": {":pk": audit_pk(user_id), ":pfx": "AUDIT#"},
        "ScanIndexForward": False,  # newest first
        "Limit": limit,
    }

    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = json.loads(cursor)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid cursor")

    try:
        resp = tbl.query(**kwargs)
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"DynamoDB query error: {e.response.get('Error', {}).get('Message', str(e))}")

    items = resp.get("Items") or []
    out: List[AuditEvent] = []
    for it in items:
        if not (it.get("sk") or "").startswith("AUDIT#"):
            continue
        out.append(AuditEvent(
            ts_ms=int(it.get("ts_ms") or 0),
            event=it.get("event") or "UNKNOWN",
            field=it.get("field") or "",
            old_value=it.get("old_value"),
            new_value=it.get("new_value"),
            reason=it.get("reason"),
            actor_user_id=it.get("actor_user_id"),
            ip=it.get("ip"),
            user_agent=it.get("user_agent"),
            request_id=it.get("request_id"),
        ))

    return out
