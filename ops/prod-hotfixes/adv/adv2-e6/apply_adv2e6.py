#!/usr/bin/env python3
"""ADV2-E6 (F7) phase 1 — syndicate advertiser model + cross-member serve.

Idempotent, ANCHOR-matched (not line#) patcher so it runs on the divergent dev
clone AND on prod. Two-phase: (1) each edit checks a marker and no-ops if already
applied; (2) py_compile-safe. Tickets ADV2-701..704 (model + serve eligibility;
the 3-way split is the NEXT phase — this phase mints the syndicate-tagged click).

Patches:
  A) ad_accounts.py  -> owner_type on normal accounts + create_syndicate_ad_account
  B) routers/ads.py  -> POST/GET syndicate ad-account endpoints (admin-gated)
  C) ad_serving.py   -> syndicate cross-member serve eligibility + is_syndicate_ad
                        / syndicate_id tagging onto the AdClicks row + serve response

Usage: apply_adv2e6.py [REPO_ROOT]   (default: cwd's app/.. resolved)
"""
from __future__ import annotations

import os
import sys
import py_compile

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()


def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), "r", encoding="utf-8") as fh:
        return fh.read()


def _write(rel: str, text: str) -> None:
    p = os.path.join(ROOT, rel)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)
    py_compile.compile(p, doraise=True)


def _sub_once(text: str, anchor: str, replacement: str, rel: str) -> str:
    if replacement in text:
        return text  # already applied
    if anchor not in text:
        raise SystemExit(f"ANCHOR MISSING in {rel}: {anchor[:70]!r}")
    if text.count(anchor) != 1:
        raise SystemExit(f"ANCHOR NOT UNIQUE ({text.count(anchor)}) in {rel}: {anchor[:70]!r}")
    return text.replace(anchor, replacement, 1)


results = []

# ── Patch A: ad_accounts.py ────────────────────────────────────────────────
rel = "app/services/ad_accounts.py"
t = _read(rel)

# A1: tag normal accounts owner_type="user" (serve_ad defaults to "user" anyway;
# this makes the field explicit on new rows). Anchored on create_ad_account's item.
t = _sub_once(
    t,
    '        "owner_sub": owner_sub,\n        "company_name": data.company_name,',
    '        "owner_sub": owner_sub,\n        "owner_type": "user",\n        "company_name": data.company_name,',
    rel,
)

# A2: append create_syndicate_ad_account + list_syndicate_ad_accounts.
if "def create_syndicate_ad_account" not in t:
    t = t.rstrip() + '''


def create_syndicate_ad_account(
    syndicate_id: str, admin_sub: str, data: AdAccountCreateIn
) -> dict:
    """Create a SYNDICATE-owned advertiser account (ADV2-701).

    The account is owned by a syndicate: ``owner_type="syndicate"`` +
    ``owner_syndicate_id=syndicate_id``. ``owner_sub`` is set to the creating
    admin so the existing owner-scoped campaign/creative endpoints, funding
    (deposit_funds resolves the owner card) and self-ad-exclusion all keep
    working unchanged. Callers MUST have already verified admin rights (the
    router gates via ``syndicates._require_admin``). Reuses the advertiser model
    + funding + admin-review lifecycle verbatim; only the ownership tags differ.
    """
    if _count_active_accounts_by_owner(admin_sub) >= MAX_ACCOUNTS_PER_USER:
        raise ValueError(
            f"Account limit reached: a user may own at most "
            f"{MAX_ACCOUNTS_PER_USER} ad accounts"
        )

    account_id = f"adacct_{uuid.uuid4().hex[:12]}"
    ts = now_ts()
    item = {
        "pk": f"ACCT#{account_id}",
        "sk": "META",
        "account_id": account_id,
        "owner_sub": admin_sub,
        "owner_type": "syndicate",
        "owner_syndicate_id": syndicate_id,
        "company_name": data.company_name,
        "billing_email": data.billing_email,
        "status": "pending_review",
        "balance_cents": 0,
        "lifetime_spend_cents": 0,
        "created_at": ts,
        "updated_at": ts,
    }
    T.ad_accounts.put_item(Item=item)
    return item


def list_syndicate_ad_accounts(syndicate_id: str, admin_sub: str) -> list[dict]:
    """List ad accounts owned by ``syndicate_id`` (managed by ``admin_sub``).

    Syndicate accounts carry ``owner_sub == admin_sub`` (the admin), so they
    are enumerable via the ByOwner GSI and then filtered to this syndicate.
    """
    return [
        a
        for a in list_accounts_by_owner(admin_sub)
        if str(a.get("owner_type", "")) == "syndicate"
        and str(a.get("owner_syndicate_id", "")) == str(syndicate_id)
    ]
'''

_write(rel, t)
results.append(("A", rel, "ok"))

# ── Patch B: routers/ads.py ────────────────────────────────────────────────
rel = "app/routers/ads.py"
t = _read(rel)

# B1: import the two new service fns.
t = _sub_once(
    t,
    "from app.services.ad_accounts import (\n    create_ad_account,",
    "from app.services.ad_accounts import (\n    create_ad_account,\n    create_syndicate_ad_account,\n    list_syndicate_ad_accounts,",
    rel,
)

# B2: append the syndicate ad-account endpoints (admin-gated). Idempotent.
if "syndicate_ad_account_endpoint" not in t:
    t = t.rstrip() + '''


# ── Syndicate-owned advertiser accounts (ADV2-701) ─────────────────────────
# A syndicate-level advertiser: an ad account owned by a syndicate, managed by
# its admin. Reuses the campaign/creative/funding endpoints above (owner_sub is
# the admin). Gated by syndicates._require_admin.

@router.post("/syndicates/{syndicate_id}/accounts", status_code=201)
async def create_syndicate_ad_account_endpoint(
    syndicate_id: str, body: AdAccountCreateIn, ctx=Depends(require_ui_session)
):
    from app.services.syndicates import _require_admin
    _require_admin(syndicate_id, ctx["user_sub"])  # raises 403/404
    try:
        return create_syndicate_ad_account(syndicate_id, ctx["user_sub"], body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/syndicates/{syndicate_id}/accounts")
async def list_syndicate_ad_accounts_endpoint(
    syndicate_id: str, ctx=Depends(require_ui_session)
):
    from app.services.syndicates import _require_admin
    _require_admin(syndicate_id, ctx["user_sub"])
    return list_syndicate_ad_accounts(syndicate_id, ctx["user_sub"])
'''

_write(rel, t)
results.append(("B", rel, "ok"))

# ── Patch C: ad_serving.py ─────────────────────────────────────────────────
rel = "app/services/ad_serving.py"
t = _read(rel)

# C1: resolve owner_type + owner_syndicate_id right after _owner_sub.
t = _sub_once(
    t,
    '        _owner_sub = str((_acct or {}).get("owner_sub", "") or "")\n',
    '        _owner_sub = str((_acct or {}).get("owner_sub", "") or "")\n'
    '        _owner_type = str((_acct or {}).get("owner_type", "user") or "user")\n'
    '        _owner_syndicate_id = str((_acct or {}).get("owner_syndicate_id", "") or "")\n'
    '        _is_syndicate_ad = _owner_type == "syndicate" and bool(_owner_syndicate_id)\n',
    rel,
)

# C2: cross-member serve eligibility — a syndicate-owned campaign serves ONLY on
# a MEMBER's content slot. Inserted right after the self-ad-exclusion continue.
t = _sub_once(
    t,
    '        if _owner_sub and _owner_sub == str(user_id or ""):\n            continue\n',
    '        if _owner_sub and _owner_sub == str(user_id or ""):\n            continue\n'
    '\n'
    '        # ADV2-701/705 (F7): a syndicate-owned campaign is eligible ONLY when\n'
    '        # the slot\'s content owner is a MEMBER of that syndicate. It never\n'
    '        # serves on a non-member\'s content nor as a standalone unit (empty\n'
    '        # content_owner_id). An EXTERNAL (non-syndicate) campaign is unaffected\n'
    '        # and still serves everywhere as before (no membership gate, no skim).\n'
    '        if _is_syndicate_ad:\n'
    '            if not content_owner_id:\n'
    '                continue\n'
    '            try:\n'
    '                from app.services.syndicates import is_member\n'
    '                if not is_member(_owner_syndicate_id, str(content_owner_id)):\n'
    '                    continue\n'
    '            except Exception:\n'
    '                logger.warning(\n'
    '                    "syndicate_membership_check_failed synd=%s owner=%s",\n'
    '                    _owner_syndicate_id, content_owner_id,\n'
    '                )\n'
    '                continue\n',
    rel,
)

# C3: carry the syndicate tags onto the candidate entry.
t = _sub_once(
    t,
    '        candidates.append({\n            "campaign": campaign,\n            "creatives": creatives,\n            "score": score,\n        })',
    '        candidates.append({\n            "campaign": campaign,\n            "creatives": creatives,\n            "score": score,\n            "is_syndicate_ad": _is_syndicate_ad,\n            "syndicate_id": _owner_syndicate_id if _is_syndicate_ad else "",\n        })',
    rel,
)

# C4: mint is_syndicate_ad + syndicate_id onto the AdClicks row.
t = _sub_once(
    t,
    '            "content_owner_sub": content_owner_id or "",\n            "surface": surface,',
    '            "content_owner_sub": content_owner_id or "",\n'
    '            "is_syndicate_ad": bool(winner.get("is_syndicate_ad")),\n'
    '            "syndicate_id": str(winner.get("syndicate_id") or ""),\n'
    '            "surface": surface,',
    rel,
)

# C5: surface the syndicate tags on the serve response.
t = _sub_once(
    t,
    '        "content_owner_id": content_owner_id or "",\n        "promo_code_id": creative.get("promo_code_id"),',
    '        "content_owner_id": content_owner_id or "",\n'
    '        "is_syndicate_ad": bool(winner.get("is_syndicate_ad")),\n'
    '        "syndicate_id": str(winner.get("syndicate_id") or ""),\n'
    '        "promo_code_id": creative.get("promo_code_id"),',
    rel,
)

_write(rel, t)
results.append(("C", rel, "ok"))

print("ADV2-E6 phase1 apply OK on", ROOT)
for r in results:
    print("  patch", r[0], r[1], r[2])
