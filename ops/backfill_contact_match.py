#!/usr/bin/env python3
"""Contacts Feature 2 — backfill the ContactMatchIndex for EXISTING users.

Iterates every user, computes:
  - email_hash from the user's PK (user_sub == normalized email), always
  - phone_hash from profile.displayed_telephone_number (E.164), when present
and writes them into the hash -> user_id lookup index. Only HASHES are stored
(never the raw email/phone). Idempotent + re-runnable (put_item upserts).

Run (dev or prod, from the repo root, with the backend env loaded)::

    PYTHONPATH=. python ops/backfill_contact_match.py            # apply
    PYTHONPATH=. python ops/backfill_contact_match.py --dry-run  # count only
"""
from __future__ import annotations

import sys

from app.core.tables import T
from app.services import contact_match as cm
from app.services.profile import get_profile


def _iter_users():
    last_key = None
    while True:
        kwargs = {"Limit": 500}
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.users.scan(**kwargs)
        for it in resp.get("Items", []):
            yield it
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break


def main() -> None:
    dry = "--dry-run" in sys.argv
    n_users = n_email = n_phone = 0
    for it in _iter_users():
        user_sub = it.get("user_sub") or it.get("email")
        if not user_sub:
            continue
        n_users += 1

        eh = cm.hash_email(user_sub)
        phone = None
        try:
            phone = get_profile(user_sub).get("displayed_telephone_number")
        except Exception:
            phone = None
        ph = cm.hash_phone(phone) if phone else None

        if dry:
            if eh:
                n_email += 1
            if ph:
                n_phone += 1
            continue

        if cm.index_user_email(user_sub):
            n_email += 1
        if phone and cm.index_user_phone(user_sub, phone):
            n_phone += 1

    mode = "DRY-RUN" if dry else "APPLIED"
    print(f"[{mode}] users={n_users} email_hashes={n_email} phone_hashes={n_phone}")


if __name__ == "__main__":
    main()
