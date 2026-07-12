#!/usr/bin/env python3
"""PAY-50 + PAY-51 (PAY-F backend): app-facing money-OUT read endpoints
(wallet summary, payout history[existing], per-payout statement/detail) +
payout-detail deep-links on the PAY-D lifecycle alerts.

Anchored + idempotent: safe to run repeatedly on the dev clone AND prod (which
may diverge on line numbers). Each edit is guarded by a marker check.
"""
import io
import os
import sys

ROOT = os.environ.get("TL_ROOT", os.path.expanduser("~/dev/testlogon"))
DRY = os.environ.get("DRY", "0") == "1"
BAK = os.environ.get("BAK_SUFFIX", "")


def _read(p):
    with io.open(p, "r", encoding="utf-8") as f:
        return f.read()


def _write(p, s):
    if BAK:
        import shutil
        shutil.copy2(p, p + BAK)
    with io.open(p, "w", encoding="utf-8") as f:
        f.write(s)


def patch(relpath, edits):
    p = os.path.join(ROOT, relpath)
    src = _read(p)
    orig = src
    for name, anchor, insert, marker in edits:
        if marker in src:
            print("  SKIP %s::%s (marker present)" % (relpath, name))
            continue
        if anchor not in src:
            print("  FAIL %s::%s ANCHOR NOT FOUND" % (relpath, name))
            sys.exit(3)
        if src.count(anchor) != 1:
            print("  FAIL %s::%s anchor count=%d (want 1)" % (relpath, name, src.count(anchor)))
            sys.exit(3)
        src = src.replace(anchor, insert, 1)
        print("  OK   %s::%s" % (relpath, name))
    if src != orig:
        if DRY:
            print("  DRY  %s would change (%+d bytes)" % (relpath, len(src) - len(orig)))
        else:
            _write(p, src)
            print("  WROTE %s" % relpath)
    else:
        print("  NOCHG %s" % relpath)


# ---------------------------------------------------------------- service
SVC_FUNCS = r'''

# --- PAY-50 (PAY-F): app-facing money-OUT read surface ---------------------
# Wallet summary + per-payout statement/detail for the Android wallet. All are
# strictly user-scoped (own records only) and reconcile to the PAY-A ledger:
#   available/held/pending == get_available_balance; lifetime_paid == settled
#   (non-reversed) payout debits. NO new state; pure read over existing rows.

def _held_release_info(user_id: str):
    """(earliest_release_ts, held_count) over credits still inside the 7-day hold."""
    pk = f"USER#{user_id}"
    now = now_ts()
    hold_period = S.payout_hold_period_seconds
    key_cond = Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#")
    filter_expr = (
        Attr("type").eq("credit")
        & Attr("state").ne("reversed")
        & Attr("amount_cents").gt(0)
    )
    next_release = None
    held_count = 0
    kwargs = {"KeyConditionExpression": key_cond, "FilterExpression": filter_expr}
    while True:
        resp = T.billing.query(**kwargs)
        for item in resp.get("Items", []):
            ts = _to_int(item.get("ts", 0))
            rel = ts + hold_period
            if rel > now:
                held_count += 1
                if next_release is None or rel < next_release:
                    next_release = rel
        lk = resp.get("LastEvaluatedKey")
        if not lk:
            break
        kwargs["ExclusiveStartKey"] = lk
    return next_release, held_count


def _count_active_payouts(user_id: str) -> int:
    """Count of the user's in-flight (requested/approved/processing) payouts."""
    count = 0
    kwargs = {
        "IndexName": "ByUserCreatedAt",
        "KeyConditionExpression": Key("user_id").eq(user_id),
        "ScanIndexForward": False,
    }
    while True:
        resp = T.creator_payouts.query(**kwargs)
        for item in resp.get("Items", []):
            if not _is_real_payout(item):
                continue
            if item.get("status", "") in ACTIVE_PAYOUT_STATES:
                count += 1
        lk = resp.get("LastEvaluatedKey")
        if not lk:
            break
        kwargs["ExclusiveStartKey"] = lk
    return count


def get_wallet_summary(user_id: str) -> dict:
    """PAY-50 wallet home: available / held(+release) / pending / lifetime-paid.

    Reconciles to the PAY-A ledger -- available/pending/held/paid_out all come
    from get_available_balance (single source of truth for the money-OUT math),
    plus the earliest hold-release timestamp and in-flight payout count."""
    bal = get_available_balance(user_id)
    next_release, held_count = _held_release_info(user_id)
    return {
        "available_cents": bal["available_cents"],
        "held_cents": bal["hold_cents"],
        "held_count": held_count,
        "held_release_at": next_release,
        "pending_cents": bal["pending_cents"],
        "pending_count": _count_active_payouts(user_id),
        "lifetime_paid_cents": bal["paid_out_cents"],
        "total_earned_cents": bal["total_earned_cents"],
        "currency": "USD",
    }


def _resolve_method_last4(item) -> str:
    """Best-effort last-4 for the destination a payout targeted (bank acct or
    a masked PayPal handle). Looks up the co-located payout_method row."""
    method_id = item.get("method_id", "")
    if method_id:
        mitem = T.creator_payouts.get_item(Key={"payout_id": method_id}).get("Item")
        if mitem and _is_payout_method(mitem):
            l4 = mitem.get("account_last4", "")
            if l4:
                return l4
            email = mitem.get("paypal_email", "")
            if email:
                return email
    return item.get("paypal_email", "") or ""


def _build_payout_timeline(item):
    """Honest lifecycle timeline from the record's real timestamps (best-effort;
    states without a dedicated timestamp carry ts=0 but still order correctly)."""
    events = []
    events.append({"status": "requested", "ts": _to_int(item.get("created_at", 0)), "note": ""})
    if item.get("approved_by"):
        events.append({"status": "approved", "ts": 0, "note": f"by {item.get('approved_by')}"})
    if item.get("held_at"):
        events.append({"status": "held", "ts": _to_int(item.get("held_at", 0)), "note": item.get("hold_reason", "")})
    if item.get("hold_released_at"):
        events.append({"status": "hold_released", "ts": _to_int(item.get("hold_released_at", 0)), "note": ""})
    status = item.get("status", "")
    attempts = _to_int(item.get("transfer_attempts", 0))
    completed_at = _to_int(item.get("completed_at", 0))
    if status in ("processing", "completed", "failed", "returned") or attempts:
        events.append({"status": "processing", "ts": 0, "note": (f"{attempts} transfer attempt(s)" if attempts else "")})
    if completed_at:
        events.append({"status": "paid", "ts": completed_at, "note": item.get("transfer_provider", "")})
    if status in ("failed", "returned"):
        events.append({"status": status, "ts": _to_int(item.get("updated_at", 0)), "note": item.get("fail_reason", "")})
    if status in ("cancelled", "rejected"):
        events.append({"status": status, "ts": _to_int(item.get("updated_at", 0)), "note": item.get("reject_reason", "")})
    return events


def get_payout_detail(user_id: str, payout_id: str) -> dict:
    """PAY-50 statement/detail for ONE payout (user-scoped; 403 if not owner)."""
    item = T.creator_payouts.get_item(Key={"payout_id": payout_id}).get("Item")
    if not item or not _is_real_payout(item):
        raise LookupError("Payout not found")
    if item.get("user_id") != user_id:
        raise PermissionError("Not your payout")
    d = _payout_to_dict(item)
    d["method_id"] = item.get("method_id", "")
    d["method_last4"] = _resolve_method_last4(item)
    d["fail_reason"] = item.get("fail_reason", "")
    d["manual_hold"] = bool(item.get("manual_hold", False))
    d["hold_reason"] = item.get("hold_reason", "")
    d["debit_reversed"] = bool(item.get("debit_reversed", False))
    d["transfer_provider"] = item.get("transfer_provider", "")
    d["transfer_ref"] = item.get("transfer_ref", "")
    d["transfer_attempts"] = _to_int(item.get("transfer_attempts", 0))
    d["timeline"] = _build_payout_timeline(item)
    return d
'''

patch("app/services/creator_payouts.py", [
    (
        "pay50-read-surface",
        "def get_payout_stats() -> dict:",
        SVC_FUNCS.lstrip("\n") + "\n\ndef get_payout_stats() -> dict:",
        "def get_wallet_summary(",
    ),
    (
        "deeplink-paid",
        'title="Your withdrawal was paid",\n',
        'title="Your withdrawal was paid",\n            action_url=f"/wallet/payouts/{payout_id}",\n',
        'action_url=f"/wallet/payouts/{payout_id}",\n            details={"payout_id": payout_id, "amount_cents": _to_int(item.get("amount_cents", 0)), "transfer_provider"',
    ),
    (
        "deeplink-failed",
        'title=("Your withdrawal was returned" if returned else "Your withdrawal failed"),\n',
        'title=("Your withdrawal was returned" if returned else "Your withdrawal failed"),\n            action_url=f"/wallet/payouts/{payout_id}",\n',
        'action_url=f"/wallet/payouts/{payout_id}",\n            details={"payout_id": payout_id, "amount_cents": _to_int(item.get("amount_cents", 0)), "returned"',
    ),
    (
        "deeplink-initiated",
        'title="Your withdrawal is processing",\n',
        'title="Your withdrawal is processing",\n            action_url=f"/wallet/payouts/{payout_id}",\n',
        'action_url=f"/wallet/payouts/{payout_id}",\n            details={"payout_id": payout_id, "amount_cents": amount',
    ),
])

# ---------------------------------------------------------------- models
MODELS = '''class WalletSummaryOut(BaseModel):
    available_cents: int = 0
    held_cents: int = 0
    held_count: int = 0
    held_release_at: Optional[int] = None
    pending_cents: int = 0
    pending_count: int = 0
    lifetime_paid_cents: int = 0
    total_earned_cents: int = 0
    currency: str = "USD"
    minimum_payout_cents: int = 1000


class PayoutTimelineEvent(BaseModel):
    status: str
    ts: int = 0
    note: str = ""


class PayoutDetailOut(BaseModel):
    payout_id: str
    user_id: str
    amount_cents: int
    method: str = "bank_transfer"
    method_id: str = ""
    method_last4: str = ""
    status: str
    created_at: int
    updated_at: int
    completed_at: Optional[int] = None
    notes: str = ""
    reject_reason: str = ""
    fail_reason: str = ""
    approved_by: str = ""
    manual_hold: bool = False
    hold_reason: str = ""
    debit_reversed: bool = False
    transfer_provider: str = ""
    transfer_ref: str = ""
    transfer_attempts: int = 0
    timeline: List[PayoutTimelineEvent] = []


'''

patch("app/models.py", [
    (
        "wallet+detail-models",
        "class PayoutStatsOut(BaseModel):",
        MODELS + "class PayoutStatsOut(BaseModel):",
        "class WalletSummaryOut(BaseModel):",
    ),
])

# ---------------------------------------------------------------- router
WALLET_ROUTE = (
    '        minimum_payout_cents=S.payout_minimum_cents,\n    )\n'
    '\n\n@router.get("/wallet", response_model=WalletSummaryOut)\n'
    'def wallet_summary(session=Depends(require_ui_session)):\n'
    '    """PAY-50 wallet home: available + held(+release date) + pending + lifetime paid."""\n'
    '    result = get_wallet_summary(session["user_sub"])\n'
    '    return WalletSummaryOut(\n'
    '        available_cents=result["available_cents"],\n'
    '        held_cents=result["held_cents"],\n'
    '        held_count=result["held_count"],\n'
    '        held_release_at=result["held_release_at"],\n'
    '        pending_cents=result["pending_cents"],\n'
    '        pending_count=result["pending_count"],\n'
    '        lifetime_paid_cents=result["lifetime_paid_cents"],\n'
    '        total_earned_cents=result["total_earned_cents"],\n'
    '        currency=result["currency"],\n'
    '        minimum_payout_cents=S.payout_minimum_cents,\n'
    '    )\n'
)

DETAIL_ROUTE = (
    '    result = create_connect_onboarding_link(session["user_sub"])\n'
    '    return ConnectOnboardingOut(**result)\n'
    '\n\n'
    '# ---------------------------------------------------------------------------\n'
    '# PAY-50 (PAY-F): per-payout statement/detail. Registered LAST so the literal\n'
    '# GET routes (/balance, /wallet, /methods, /tax-info, /connect) always win over\n'
    '# this catch-all {payout_id} param route.\n'
    '# ---------------------------------------------------------------------------\n'
    '\n\n'
    '@router.get("/{payout_id}", response_model=PayoutDetailOut)\n'
    'def payout_detail(payout_id: str, session=Depends(require_ui_session)):\n'
    '    """Payout statement/detail: lifecycle timeline + transfer ref + method last-4\n'
    "    + fail/return/hold reason. User-scoped (403 on another creator's payout).\"\"\"\n"
    '    try:\n'
    '        result = get_payout_detail(session["user_sub"], payout_id)\n'
    '    except LookupError:\n'
    '        raise HTTPException(status_code=404, detail="Payout not found")\n'
    '    except PermissionError:\n'
    '        raise HTTPException(status_code=403, detail="Not your payout")\n'
    '    return PayoutDetailOut(**result)\n'
)

patch("app/routers/creator_payouts.py", [
    (
        "import-svc",
        "    get_available_balance,\n",
        "    get_available_balance,\n    get_wallet_summary,\n    get_payout_detail,\n",
        "    get_wallet_summary,\n",
    ),
    (
        "import-models",
        "    PayoutListOut,\n",
        "    PayoutListOut,\n    WalletSummaryOut,\n    PayoutDetailOut,\n",
        "    WalletSummaryOut,\n",
    ),
    (
        "wallet-route",
        "        minimum_payout_cents=S.payout_minimum_cents,\n    )\n",
        WALLET_ROUTE,
        '@router.get("/wallet", response_model=WalletSummaryOut)',
    ),
    (
        "detail-route",
        '    result = create_connect_onboarding_link(session["user_sub"])\n    return ConnectOnboardingOut(**result)\n',
        DETAIL_ROUTE,
        '@router.get("/{payout_id}", response_model=PayoutDetailOut)',
    ),
])

print("DONE")
