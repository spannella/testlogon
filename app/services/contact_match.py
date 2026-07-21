from __future__ import annotations

"""Privacy-safe contact matching (Contacts Feature 2).

Overview
--------
The device contact-sync feature matches a user's native address book against
platform users WITHOUT ever receiving raw contacts. The Android client
normalizes every email/phone locally, hashes each one, and sends ONLY the
hashes. The server keeps a hash -> user_id lookup index built at registration
(email always) and when a profile phone is added/changed (phone).

Hashing scheme (documented, shared byte-for-byte with the client)
-----------------------------------------------------------------
    id_hash = sha256( APP_CONTACT_MATCH_SALT + ":" + normalized_identifier )
              (hex, lowercase)

  - email:  lowercased + trimmed  (reuses app.core.normalize.normalize_email)
  - phone:  E.164, default region +1 (reuses app.core.normalize.normalize_phone)

APP_CONTACT_MATCH_SALT is a FIXED, NON-SECRET application pepper. It is NOT a
security boundary: the platform already holds every user's email (it is the
account primary key) and any phone the user chose to share, so a matching hash
reveals nothing the platform does not already know. The salt only raises the
bar against trivial precomputed-rainbow-table lookups of the raw hashes and
keeps our hashes from colliding with any other system's sha256(identifier).
Because it must be identical on the client and server, it is shipped as a
compile-time BuildConfig constant on Android and an env-overridable setting here
(both default to the same literal).

Index table
-----------
A dedicated lookup table (S.contact_match_index_table_name, default
"ContactMatchIndex"), partition key ``id_hash`` (S). Each item is::

    {"id_hash": <hex>, "user_id": <user_sub>, "kind": "email"|"phone",
     "updated_at": <epoch>}

Only the HASH is stored — never the raw email/phone. Lookups are direct
get_item calls (O(1), no scan, no GSI).
"""

import hashlib
from typing import Dict, List, Optional, Tuple

from fastapi import HTTPException

from app.core.normalize import normalize_email, normalize_phone
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

EMAIL = "email"
PHONE = "phone"


# ── Hashing ──────────────────────────────────────────────────────────────────

def hash_identifier(normalized: str) -> str:
    """sha256(salt + ':' + normalized) -> lowercase hex. Shared with the client."""
    salt = S.contact_match_salt or ""
    return hashlib.sha256(f"{salt}:{normalized}".encode("utf-8")).hexdigest()


def hash_email(raw_email: str) -> Optional[str]:
    """Normalize + hash an email. Returns None on invalid input (never raises)."""
    try:
        return hash_identifier(normalize_email(raw_email))
    except Exception:
        return None


def hash_phone(raw_phone: str) -> Optional[str]:
    """Normalize (E.164, default +1) + hash a phone. None on invalid input."""
    if not raw_phone:
        return None
    try:
        return hash_identifier(normalize_phone(raw_phone))
    except Exception:
        return None


# ── Index maintenance (write path — hooked at registration + profile update) ─

def _put_index(id_hash: str, user_id: str, kind: str) -> None:
    if not id_hash or not user_id:
        return
    try:
        T.contact_match_index.put_item(Item={
            "id_hash": id_hash,
            "user_id": user_id,
            "kind": kind,
            "updated_at": now_ts(),
        })
    except Exception:
        # Best-effort: an index write must NEVER break registration / profile save.
        pass


def index_user_email(user_sub: str) -> bool:
    """Index a user's email hash. user_sub IS the normalized email (users PK).

    Returns True if a hash was written. Best-effort — never raises.
    """
    h = hash_email(user_sub)
    if not h:
        return False
    _put_index(h, user_sub, EMAIL)
    return True


def index_user_phone(user_sub: str, raw_phone: Optional[str]) -> bool:
    """Index a user's phone hash (E.164). No-op when phone is absent/invalid.

    Best-effort — never raises. Returns True if a hash was written.
    """
    if not raw_phone:
        return False
    h = hash_phone(raw_phone)
    if not h:
        return False
    _put_index(h, user_sub, PHONE)
    return True


def index_user(user_sub: str, raw_phone: Optional[str] = None) -> Dict[str, bool]:
    """Index both email (always) and phone (when present) for a user."""
    return {
        "email": index_user_email(user_sub),
        "phone": index_user_phone(user_sub, raw_phone),
    }


# ── Lookup (read path — used by POST /ui/contacts/match) ─────────────────────

def lookup_hashes(hashes: List[str]) -> Dict[str, Tuple[str, str]]:
    """Resolve a list of id_hashes to {id_hash: (user_id, kind)}.

    Direct get_item per hash (deduped). Missing hashes are simply absent from
    the result — a non-match returns nothing, never an error.
    """
    out: Dict[str, Tuple[str, str]] = {}
    for h in {x for x in hashes if x}:
        try:
            item = T.contact_match_index.get_item(Key={"id_hash": h}).get("Item")
        except Exception:
            item = None
        if item and item.get("user_id"):
            out[h] = (str(item["user_id"]), str(item.get("kind") or ""))
    return out


# ── Request caps ─────────────────────────────────────────────────────────────

def clamp_hash_list(hashes: Optional[List[str]], *, cap: int) -> List[str]:
    """Validate + cap a hash list. Drops blanks; rejects oversized payloads."""
    if hashes is None:
        return []
    if not isinstance(hashes, list):
        raise HTTPException(400, "hashes must be a list")
    cleaned = [str(h).strip().lower() for h in hashes if isinstance(h, str) and h.strip()]
    if len(cleaned) > cap:
        raise HTTPException(413, f"Too many hashes (max {cap} per field)")
    # Defensive: reject anything that is not a plausible hex sha256 (64 hex chars).
    return [h for h in cleaned if len(h) == 64 and all(c in "0123456789abcdef" for c in h)]
