#!/usr/bin/env python3
"""Contacts Feature 2 — idempotent in-place patcher for prod's SHARED files.

Applies ONLY the Feature-2 additions to settings.py / tables.py / registration.py /
profile.py / rate_limit.py. Each patch is a no-op if its marker is already present,
so this is safe to re-run. Keeps a .bak of each file it actually modifies.
Runs ON the prod host (cwd = /home/ubuntu/testlogon).
"""
import ast, time

def backup(p):
    import shutil
    shutil.copyfile(p, f"{p}.bak_contactsync_{int(time.time())}")

def patch(p, marker, anchor, replacement):
    s = open(p).read()
    if marker in s:
        print(f"SKIP {p} (already applied)")
        return
    if anchor not in s:
        raise SystemExit(f"ANCHOR MISSING in {p}")
    backup(p)
    s = s.replace(anchor, replacement, 1)
    ast.parse(s)
    open(p, "w").write(s)
    print(f"PATCHED {p}")

# ── settings.py ──────────────────────────────────────────────────────────────
patch(
    "app/core/settings.py",
    "contact_match_salt",
    '    contacts_table_name: str = os.environ.get("DDB_CONTACTS_TABLE", "Contacts")',
    '    contacts_table_name: str = os.environ.get("DDB_CONTACTS_TABLE", "Contacts")\n'
    "\n"
    "    # Contacts Feature 2 — privacy-safe device contact sync (hash -> user_id match index).\n"
    "    # APP_CONTACT_MATCH_SALT is a FIXED, NON-SECRET app pepper (see\n"
    "    # app/services/contact_match.py). It is shared byte-for-byte with the Android client\n"
    "    # (BuildConfig.CONTACT_MATCH_SALT); if you change it you MUST rebuild the app AND\n"
    "    # re-run the backfill, or existing hashes stop matching.\n"
    '    contact_match_salt: str = os.environ.get("APP_CONTACT_MATCH_SALT", "tl_contact_match_v1")\n'
    '    contact_match_index_table_name: str = os.environ.get("DDB_CONTACT_MATCH_INDEX_TABLE", "ContactMatchIndex")\n'
    "    # Rate limit for POST /ui/contacts/match (per-user token bucket).\n"
    '    contact_match_max_per_window: int = int(os.environ.get("CONTACT_MATCH_MAX_PER_WINDOW", "30"))\n'
    '    contact_match_window_seconds: int = int(os.environ.get("CONTACT_MATCH_WINDOW_SECONDS", "3600"))\n'
    "    # Max hashes accepted per field per request (email_hashes / phone_hashes).\n"
    '    contact_match_max_hashes: int = int(os.environ.get("CONTACT_MATCH_MAX_HASHES", "2000"))',
)

# ── tables.py: dataclass field ───────────────────────────────────────────────
patch(
    "app/core/tables.py",
    "contact_match_index: Any",
    "    contacts: Any\n",
    "    contacts: Any\n    contact_match_index: Any  # Contacts Feature 2 — hash->user_id device-sync index\n",
)
# tables.py: instantiation (separate marker guard so both apply)
_s = open("app/core/tables.py").read()
if "contact_match_index=_safe_table" not in _s:
    ianchor = "    contacts=_safe_table(S.contacts_table_name),\n"
    if ianchor not in _s:
        raise SystemExit("tables inst anchor missing")
    backup("app/core/tables.py")
    _s = _s.replace(ianchor, ianchor + "    contact_match_index=_safe_table(S.contact_match_index_table_name),\n", 1)
    ast.parse(_s)
    open("app/core/tables.py", "w").write(_s)
    print("PATCHED app/core/tables.py (instantiation)")
else:
    print("SKIP app/core/tables.py instantiation (already applied)")

# ── registration.py ──────────────────────────────────────────────────────────
patch(
    "app/services/registration.py",
    "index_user_email",
    '''    set_account_state(
        user_sub,
        status,
        reason="initial_registration",
        requested_by=user_sub,
        ttl_epoch=pending_ttl if verification_required else None,
    )
    return {"user_sub": user_sub}''',
    '''    set_account_state(
        user_sub,
        status,
        reason="initial_registration",
        requested_by=user_sub,
        ttl_epoch=pending_ttl if verification_required else None,
    )

    # Contacts Feature 2 — index this user's email hash so devices can privacy-safely
    # match their address book to this account. user_sub IS the normalized email.
    # Best-effort: an index failure must never fail registration.
    try:
        from app.services.contact_match import index_user_email
        index_user_email(user_sub)
    except Exception:
        pass

    return {"user_sub": user_sub}''',
)

# ── profile.py: three coordinated edits (flag init, diff-loop set, reindex) ──
_p = open("app/services/profile.py").read()
if "index_user_phone" not in _p:
    backup("app/services/profile.py")
    a1 = "    address_changed = False\n    discovery_changed = False\n"
    if a1 not in _p:
        raise SystemExit("profile flag-init anchor missing")
    _p = _p.replace(a1, a1 + "    phone_changed = False\n", 1)
    a2 = "            if field in DISCOVERY_FIELDS:\n                discovery_changed = True\n"
    if a2 not in _p:
        raise SystemExit("profile diff-loop anchor missing")
    _p = _p.replace(a2, a2 + '            if field == "displayed_telephone_number":\n                phone_changed = True\n', 1)
    a3 = ("    # PTY-010: re-sync party EMAIL/PHONE contact mechs when those fields change\n"
          "    # (best-effort, doubly flag-gated, never rolls back the profile write).\n"
          "    _sync_party_mechs_after_profile_update(user_sub, current, updated)\n")
    if a3 not in _p:
        raise SystemExit("profile party-sync anchor missing")
    add3 = ('''    # Contacts Feature 2: (re)index this user's phone hash when the displayed phone
    # changes, so devices can privacy-safely match by phone. Best-effort — never
    # rolls back the (already committed) profile write.
    if phone_changed:
        try:
            from app.services.contact_match import index_user_phone
            index_user_phone(user_sub, updated.get("displayed_telephone_number"))
        except Exception:
            pass

''' + a3)
    _p = _p.replace(a3, add3, 1)
    ast.parse(_p)
    open("app/services/profile.py", "w").write(_p)
    print("PATCHED app/services/profile.py")
else:
    print("SKIP app/services/profile.py (already applied)")

# ── rate_limit.py ────────────────────────────────────────────────────────────
patch(
    "app/services/rate_limit.py",
    "rate_limit_contact_match",
    "def rate_limit_feed_query(user_sub: str, mode: str) -> None:",
    '''def rate_limit_contact_match(user_sub: str) -> None:
    """Contacts Feature 2 — cap POST /ui/contacts/match per user (token bucket)."""
    cap = max(1, int(getattr(S, "contact_match_max_per_window", 30) or 30))
    window = max(1, int(getattr(S, "contact_match_window_seconds", 3600) or 3600))
    sid = "rl#contact_match"
    if not _bucket_limit(user_sub, sid, cap, window):
        raise HTTPException(
            status_code=429,
            detail={
                "code": "contact_match_rate_limited",
                "message": "Too many contact-match requests; try again later",
                "limit": cap,
                "window_seconds": window,
            },
            headers={"Retry-After": str(window)},
        )


def rate_limit_feed_query(user_sub: str, mode: str) -> None:''',
)

print("SHARED PATCHES DONE")
