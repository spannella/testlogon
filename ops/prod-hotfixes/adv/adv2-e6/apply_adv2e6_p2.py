#!/usr/bin/env python3
"""ADV2-E6 (F7) phase 2 -- the 3-way syndicate placement split (ADV2-705..708).

Idempotent, ANCHOR-matched (not line#) patcher -> runs on the divergent dev
clone AND on prod. Each edit checks a marker and no-ops if already applied;
py_compile-safe at the end.

Money-path: a SYNDICATE-OWNED ad (owner_type=="syndicate") charged in front of a
CURRENT member M's content splits the content-owner (creator) 70% share between
the member (configured member_share_bps) and the syndicate treasury (remainder);
platform 30% is untouched. An EXTERNAL (owner_type=="user") advertiser on a
member keeps member-70 / platform-30 / syndicate-0 (NO skim). The 3 credits sum
EXACTLY to the charge. Reuses _process_charge (funds-guarded, idempotent).

Patches:
  A) syndicate_revenue_split.py -> per-syndicate ad-placement member_share config
     (get/set + default 7000 bps = member keeps 70% of the 70%).
  B) syndicate_treasury.py      -> credit_placement_earning (treasury credit half,
     type/direction "credit"; mirrors refund_advertising's credit).
  C) ad_billing.py              -> _split_revenue syndicate-aware 3-way path +
     _process_charge ledger_meta denormalization of the split pointers.
  D) routers/ads.py             -> GET/PUT syndicate ad-placement-config (admin).
"""
from __future__ import annotations
import os
import sys
import py_compile

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()


def _read(rel):
    with open(os.path.join(ROOT, rel), "r", encoding="utf-8") as fh:
        return fh.read()


def _write(rel, txt):
    with open(os.path.join(ROOT, rel), "w", encoding="utf-8") as fh:
        fh.write(txt)


def _sub_once(txt, anchor, repl, rel, tag):
    n = txt.count(anchor)
    if n != 1:
        raise SystemExit("ANCHOR_ERROR %s [%s]: expected 1 occurrence, found %d" % (rel, tag, n))
    return txt.replace(anchor, repl, 1)


CONFIG_BLOCK = '''\
# ADV2-705 (F7): per-syndicate AD-PLACEMENT split config. When the SYNDICATE
# ITSELF advertises in front of a member's content, the content-owner (creator)
# share -- the creator's normal 70% of the ad charge -- is split between the
# member and the syndicate treasury. member_share_bps = the member's cut of that
# content-owner share; the remainder goes to the treasury. Default 7000 bps =
# the member keeps 70% of the 70% (~49% of the gross charge); treasury gets 30%
# of the 70% (~21%). Platform's 30% is NEVER touched. This does NOT apply to an
# external advertiser on a member (that stays member-70/platform-30/syndicate-0).
# Stored at pk=SYND#{id} sk=AD_PLACEMENT_CONFIG.
DEFAULT_AD_PLACEMENT_MEMBER_SHARE_BPS = 7000


def get_ad_placement_member_share_bps(syndicate_id: str) -> int:
    """Return the member's share (bps) of the content-owner split, or the default."""
    try:
        resp = T.syndicate_revenue_split.get_item(
            Key={"pk": f"SYND#{syndicate_id}", "sk": "AD_PLACEMENT_CONFIG"}
        )
        item = resp.get("Item")
        if item and item.get("member_share_bps") is not None:
            return int(item["member_share_bps"])
    except Exception:
        logger.warning("ad_placement_config_read_failed", extra={"syndicate_id": syndicate_id})
    return DEFAULT_AD_PLACEMENT_MEMBER_SHARE_BPS


def get_ad_placement_config(syndicate_id: str) -> Dict[str, Any]:
    """Return the ad-placement split config (member/treasury bps) for a syndicate."""
    bps = get_ad_placement_member_share_bps(syndicate_id)
    return {
        "syndicate_id": syndicate_id,
        "member_share_bps": bps,
        "treasury_share_bps": TOTAL_BPS - bps,
        "default_member_share_bps": DEFAULT_AD_PLACEMENT_MEMBER_SHARE_BPS,
        "platform_share_note": "platform 30% of the gross charge is unchanged",
    }


def set_ad_placement_member_share_bps(*, syndicate_id: str, admin_sub: str,
                                      member_share_bps: int) -> Dict[str, Any]:
    """Admin-only: set the member's share (bps) of the content-owner split."""
    syndicate_svc._require_admin(syndicate_id, admin_sub)
    member_share_bps = int(member_share_bps)
    if not (0 <= member_share_bps <= TOTAL_BPS):
        raise HTTPException(status_code=400,
                            detail=f"member_share_bps must be 0..{TOTAL_BPS}")
    ts = now_ts()
    T.syndicate_revenue_split.put_item(Item={
        "pk": f"SYND#{syndicate_id}",
        "sk": "AD_PLACEMENT_CONFIG",
        "member_share_bps": member_share_bps,
        "updated_at": ts,
        "updated_by": admin_sub,
    })
    syndicate_svc._write_audit(
        syndicate_id, admin_sub, "ad_placement_config_updated", "",
        {"member_share_bps": member_share_bps},
    )
    return get_ad_placement_config(syndicate_id)


'''

TREASURY_BLOCK = '''\
def credit_placement_earning(
    *,
    syndicate_id: str,
    amount_cents: int,
    member_user_id: str = "",
    account_id: str = "",
    campaign_id: str = "",
) -> Dict[str, Any]:
    """ADV2-705 (F7): credit the syndicate treasury its share of a syndicate-owned
    ad placement served in front of a member's content. Mirrors the credit half of
    refund_advertising (balance ADD + one treasury ledger row, type/direction
    'credit'). The MEMBER is credited separately by the ad-billing split; this only
    moves the treasury's cut. No-op for a non-positive amount."""
    if amount_cents <= 0:
        return {"ok": True, "amount_cents": 0, "ledger_entry_id": ""}
    pk_treasury = _treasury_pk(syndicate_id)
    ts = now_ts()
    T.syndicate_treasury.update_item(
        Key={"pk": pk_treasury, "sk": BALANCE_SK},
        UpdateExpression=(
            "SET balance_cents = if_not_exists(balance_cents, :z) + :amt, "
            "total_ad_earnings_cents = if_not_exists(total_ad_earnings_cents, :z) + :amt, "
            "updated_at = :t, syndicate_id = :sid"
        ),
        ExpressionAttributeValues={
            ":z": 0, ":amt": int(amount_cents), ":t": ts, ":sid": syndicate_id,
        },
    )
    entry_id = _gen_id()
    T.syndicate_treasury.put_item(Item={
        "pk": pk_treasury,
        "sk": ledger_sk(ts, entry_id),
        "entry_id": entry_id,
        "ts": ts,
        "direction": "credit",
        "type": "credit",
        "amount_cents": int(amount_cents),
        "reason": "Syndicate ad placement earnings",
        "actor_user_id": "",
        "counterparty_user_id": member_user_id,
        "account_id": account_id,
        "campaign_id": campaign_id,
        "source_type": "ad_placement",
        "currency": "usd",
        "created_at": ts,
    })
    balance = get_treasury_balance(syndicate_id)
    return {
        "ok": True,
        "amount_cents": int(amount_cents),
        "ledger_entry_id": entry_id,
        "new_treasury_balance_cents": balance["balance_cents"],
    }


'''

SPLIT_RESOLVE_BLOCK = '''\

    # -- ADV2-704/705 (F7): syndicate-aware 3-way placement split resolution ----
    # DEFAULT (external / non-syndicate advertiser): the content owner keeps the
    # FULL creator_share and the syndicate earns nothing (member_share_cents ==
    # creator_share, treasury_share_cents == 0) -- membership NEVER skims a
    # member's external-ad earnings. SYNDICATE-OWNED ad (the paying account has
    # owner_type=="syndicate") served in front of a CURRENT member's content: the
    # content-owner share is split between the member (configured member_share_bps)
    # and the syndicate treasury (the remainder). Platform's 30% is untouched. The
    # 3-way fires ONLY here (is_syndicate_split).
    member_share_cents = creator_share
    treasury_share_cents = 0
    split_syndicate_id = ""
    if creator_share > 0 and creator_id and account_id:
        try:
            from app.services.ad_accounts import get_ad_account as _get_acct_for_split
            _acct_for_split = _get_acct_for_split(account_id) or {}
        except Exception:
            _acct_for_split = {}
        if str(_acct_for_split.get("owner_type", "")) == "syndicate":
            _synd_for_split = str(_acct_for_split.get("owner_syndicate_id", "") or "")
            _is_mem_for_split = False
            if _synd_for_split:
                try:
                    from app.services.syndicates import is_member as _is_member_for_split
                    _is_mem_for_split = bool(_is_member_for_split(_synd_for_split, creator_id))
                except Exception:
                    _is_mem_for_split = False
            if _synd_for_split and _is_mem_for_split:
                try:
                    from app.services.syndicate_revenue_split import (
                        get_ad_placement_member_share_bps as _member_bps_for_split,
                    )
                    _bps_for_split = int(_member_bps_for_split(_synd_for_split))
                except Exception:
                    _bps_for_split = 7000
                _bps_for_split = max(0, min(10000, _bps_for_split))
                member_share_cents = (creator_share * _bps_for_split) // 10000
                treasury_share_cents = creator_share - member_share_cents
                split_syndicate_id = _synd_for_split
'''

TREASURY_CREDIT_BLOCK = '''\
    # ADV2-705 (F7): credit the syndicate TREASURY its share of the content-owner
    # split (type:"credit"). Fires ONLY for a syndicate-owned ad on a member; for
    # an external advertiser treasury_share_cents == 0 so nothing is written.
    treasury_credit_sk = ""
    if treasury_share_cents > 0 and split_syndicate_id:
        try:
            from app.services import syndicate_treasury as _treasury_for_split
            _tres_res = _treasury_for_split.credit_placement_earning(
                syndicate_id=split_syndicate_id,
                amount_cents=treasury_share_cents,
                member_user_id=creator_id,
                account_id=account_id,
                campaign_id=str(meta.get("campaign_id", "") or ""),
            )
            treasury_credit_sk = str(_tres_res.get("ledger_entry_id", "") or "")
        except Exception:
            logger.warning(
                "ad_revenue_syndicate_treasury_credit_failed",
                extra={"syndicate_id": split_syndicate_id, "amount_cents": treasury_share_cents},
            )

'''

ROUTER_BLOCK = '''\


# -- Syndicate ad-placement split config (ADV2-705) -------------------------
# The per-syndicate member_share: when the syndicate ITSELF advertises in front
# of a member's content, member_share_bps = the member's cut of the content-owner
# (creator) share; the remainder goes to the syndicate treasury. Platform 30% is
# unchanged. Admin-gated. Default 7000 bps (member keeps 70% of the 70%). This
# never applies to an external advertiser on a member (no skim).

@router.get("/syndicates/{syndicate_id}/ad-placement-config")
async def get_syndicate_ad_placement_config_endpoint(
    syndicate_id: str, ctx=Depends(require_ui_session)
):
    from app.services.syndicates import _require_admin
    from app.services.syndicate_revenue_split import get_ad_placement_config
    _require_admin(syndicate_id, ctx["user_sub"])
    return get_ad_placement_config(syndicate_id)


@router.put("/syndicates/{syndicate_id}/ad-placement-config")
async def set_syndicate_ad_placement_config_endpoint(
    syndicate_id: str, member_share_bps: int = Body(..., embed=True),
    ctx=Depends(require_ui_session),
):
    from app.services.syndicates import _require_admin
    from app.services.syndicate_revenue_split import set_ad_placement_member_share_bps
    _require_admin(syndicate_id, ctx["user_sub"])
    try:
        return set_ad_placement_member_share_bps(
            syndicate_id=syndicate_id, admin_sub=ctx["user_sub"],
            member_share_bps=member_share_bps,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
'''


def patch_config():
    rel = "app/services/syndicate_revenue_split.py"
    t = _read(rel)
    if "get_ad_placement_member_share_bps" in t:
        print("SKIP %s (already applied)" % rel)
        return
    anchor = "def get_split_config(syndicate_id: str) -> Dict[str, Any]:\n"
    t = _sub_once(t, anchor, CONFIG_BLOCK + anchor, rel, "config")
    _write(rel, t)
    print("PATCHED %s" % rel)


def patch_treasury():
    rel = "app/services/syndicate_treasury.py"
    t = _read(rel)
    if "def credit_placement_earning" in t:
        print("SKIP %s (already applied)" % rel)
        return
    anchor = "def refund_advertising(\n"
    t = _sub_once(t, anchor, TREASURY_BLOCK + anchor, rel, "treasury")
    _write(rel, t)
    print("PATCHED %s" % rel)


def patch_billing():
    rel = "app/services/ad_billing.py"
    t = _read(rel)
    if "split_syndicate_id" in t:
        print("SKIP %s (already applied)" % rel)
        return
    # C1: insert the syndicate-resolution block right after platform_share_pct.
    anchor1 = (
        "    platform_share = charge_cents - creator_share\n"
        "    platform_share_pct = (\n"
        "        (platform_share * 100) // charge_cents if charge_cents > 0 else PLATFORM_REVENUE_SHARE_PCT\n"
        "    )\n"
    )
    t = _sub_once(t, anchor1, anchor1 + SPLIT_RESOLVE_BLOCK, rel, "resolve")
    # C2: credit the MEMBER their (possibly reduced) share instead of the full
    # creator_share. In the non-syndicate case member_share_cents == creator_share
    # so behaviour is byte-identical to today.
    anchor2 = "                amount_cents=creator_share,\n"
    t = _sub_once(t, anchor2, "                amount_cents=member_share_cents,\n", rel, "member_credit")
    # C3: transparency reflects the member's actual earning.
    anchor3 = "                revenue_cents=creator_share,\n"
    t = _sub_once(t, anchor3, "                revenue_cents=member_share_cents,\n", rel, "transparency")
    # C4: credit the treasury before the platform revenue record.
    anchor4 = (
        "    # Write platform revenue record to ad_billing table so the platform's\n"
        "    # share is durably recorded for audit/reconciliation (GAP-0049).\n"
    )
    t = _sub_once(t, anchor4, TREASURY_CREDIT_BLOCK + anchor4, rel, "treasury_credit")
    # C5: extend the split return dict with the syndicate fields.
    anchor5 = (
        "        \"platform_entry_sk\": platform_entry_sk,\n"
        "        \"revenue_share_bps\": creator_bps,\n"
        "    }\n"
    )
    repl5 = (
        "        \"platform_entry_sk\": platform_entry_sk,\n"
        "        \"revenue_share_bps\": creator_bps,\n"
        "        \"member_share_cents\": member_share_cents,\n"
        "        \"syndicate_treasury_share_cents\": treasury_share_cents,\n"
        "        \"syndicate_id\": split_syndicate_id,\n"
        "        \"is_syndicate_split\": bool(split_syndicate_id),\n"
        "        \"treasury_credit_sk\": treasury_credit_sk,\n"
        "    }\n"
    )
    t = _sub_once(t, anchor5, repl5, rel, "return")
    # C6: denormalize the split pointers onto the charge ledger row (_process_charge).
    anchor6 = (
        "        \"creator_credit_sk\": split.get(\"creator_credit_sk\", \"\"),\n"
        "        \"creator_credit_ts\": int(split.get(\"creator_credit_ts\", 0)),\n"
        "        \"platform_entry_sk\": split.get(\"platform_entry_sk\", \"\"),\n"
        "    }\n"
    )
    repl6 = (
        "        \"creator_credit_sk\": split.get(\"creator_credit_sk\", \"\"),\n"
        "        \"creator_credit_ts\": int(split.get(\"creator_credit_ts\", 0)),\n"
        "        \"platform_entry_sk\": split.get(\"platform_entry_sk\", \"\"),\n"
        "        \"member_share_cents\": int(split.get(\"member_share_cents\", 0)),\n"
        "        \"syndicate_treasury_share_cents\": int(split.get(\"syndicate_treasury_share_cents\", 0)),\n"
        "        \"syndicate_id\": split.get(\"syndicate_id\", \"\"),\n"
        "        \"is_syndicate_split\": bool(split.get(\"is_syndicate_split\")),\n"
        "        \"treasury_credit_sk\": split.get(\"treasury_credit_sk\", \"\"),\n"
        "    }\n"
    )
    t = _sub_once(t, anchor6, repl6, rel, "ledger_meta")
    _write(rel, t)
    print("PATCHED %s" % rel)


def patch_router():
    rel = "app/routers/ads.py"
    t = _read(rel)
    if "get_syndicate_ad_placement_config_endpoint" in t:
        print("SKIP %s (already applied)" % rel)
        return
    # ensure Body is importable (append ", Body" to the fastapi import once).
    imp_anchor = "from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, File, Form\n"
    if imp_anchor in t:
        t = _sub_once(
            t, imp_anchor,
            "from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, File, Form, Body\n",
            rel, "import_body",
        )
    else:
        raise SystemExit("ANCHOR_ERROR %s [import_body]: fastapi import line not found" % rel)
    # append the endpoints after the list_syndicate_ad_accounts endpoint (EOF).
    anchor = (
        "    from app.services.syndicates import _require_admin\n"
        "    _require_admin(syndicate_id, ctx[\"user_sub\"])\n"
        "    return list_syndicate_ad_accounts(syndicate_id, ctx[\"user_sub\"])\n"
    )
    t = _sub_once(t, anchor, anchor + ROUTER_BLOCK, rel, "router")
    _write(rel, t)
    print("PATCHED %s" % rel)


def main():
    patch_config()
    patch_treasury()
    patch_billing()
    patch_router()
    for rel in (
        "app/services/syndicate_revenue_split.py",
        "app/services/syndicate_treasury.py",
        "app/services/ad_billing.py",
        "app/routers/ads.py",
    ):
        py_compile.compile(os.path.join(ROOT, rel), doraise=True)
    print("PY_COMPILE_OK")
    print("APPLY_DONE")


if __name__ == "__main__":
    main()
