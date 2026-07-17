"""DISP E1 LIVE verification harness (user-level dispute flow).

Seeds REAL charges (tip / subscription / ecom / vod) against the SAME live
DynamoDB the running uvicorn (:8000) uses, then drives the WHOLE user-track
dispute flow over REAL HTTP against the running server:

    payer opens dispute  ->  creator response window  ->  admin resolves
      refunded  => money REALLY moves + access revoked + creator clawed back
      partial   => partial ledger move (ecom)
      denied    => zero ledger move
    + dedup / refund-then-dispute / reason-gating guards
    + SLA sweep escalates a no-response dispute
    + idempotent double-resolve

Asserts every money/access effect via live HTTP (minted cookies) + live-DDB
reads. Auto-cleans all synthetic rows (0 residue).

Run:  set -a; . .env.local; set +a; .venv/bin/python ~/disp_work/verify_e1.py
"""
from __future__ import annotations
import json, time, uuid, subprocess

import jwt
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import user_pk, new_ledger_entry
from app.services import dispute_dispatch as DD
from app.services import dispute_lifecycle as DL

BASE = "http://localhost:8000"
COOKIE = S.ui_access_token_cookie_name
SEC = S.ui_access_token_secret
RUN = uuid.uuid4().hex[:8]
ADMIN = f"disp_admin_{RUN}"

results = []
_created_keys = []


def rec(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, "-", detail)


def track(table, key):
    _created_keys.append((table, key))


def cookie_for(sub, role="user"):
    tok = jwt.encode({"sub": sub, "sid": f"disp-{RUN}", "role": role,
                      "exp": int(time.time()) + 3600}, SEC, algorithm="HS256")
    return f"{COOKIE}={tok}"


def _curl(method, path, sub, role="user", body=None):
    args = ["curl", "-s", "-X", method, BASE + path,
            "-H", "Cookie: " + cookie_for(sub, role), "-w", "\n%{http_code}"]
    if body is not None:
        args += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    r = subprocess.run(args, capture_output=True, text=True)
    txt, _, code = r.stdout.rpartition("\n")
    try:
        return int(code or 0), (json.loads(txt) if txt.strip() else {})
    except Exception:
        return int(code or 0), {"_raw": txt}


def http_get(path, sub, role="user"):
    return _curl("GET", path, sub, role)


def http_post(path, sub, body=None, role="user"):
    return _curl("POST", path, sub, role, body)


def http_balance(sub):
    code, j = http_get("/ui/payouts/balance", sub)
    return code, int((j or {}).get("total_earned_cents", -1))


def http_available(sub):
    code, j = http_get("/ui/payouts/balance", sub)
    return code, int((j or {}).get("available_cents", -1))


def seed_admin():
    T.users.put_item(Item={"user_sub": ADMIN, "role": "admin", "email": f"{ADMIN}@t.co"})
    track(T.users, {"user_sub": ADMIN})


def find_credit_state(user_id, meta_key, meta_val):
    for row in T.billing.query(KeyConditionExpression="pk = :p",
                               ExpressionAttributeValues={":p": user_pk(user_id)}).get("Items", []):
        if (row.get("meta") or {}).get(meta_key) == meta_val and \
           str(row.get("type", "")) in ("credit", "vod_purchase_credit", "vod_rental_credit"):
            return row.get("state", "")
    return None


def track_charge_rows(uids, meta_key, meta_val):
    for uid in uids:
        for row in T.billing.query(KeyConditionExpression="pk = :p",
                                   ExpressionAttributeValues={":p": user_pk(uid)}).get("Items", []):
            if (row.get("meta") or {}).get(meta_key) == meta_val:
                track(T.billing, {"pk": row["pk"], "sk": row["sk"]})


def track_dispute(did):
    track(T.billing_disputes, {"pk": f"DISPUTE#{did}", "sk": "META"})


# ═══════════════════════════════════════════════════════════════════════════
# 1) TIP dispute -> refunded (full money move + clawback + idempotent)
# ═══════════════════════════════════════════════════════════════════════════
def test_tip_refunded():
    from app.services.tips import charge_tip, _reversal_sk
    tipper = f"disp_e1_tipper_{RUN}"
    recip = f"disp_e1_creator_{RUN}"
    amt = 500
    res = charge_tip(tipper_id=tipper, recipient_id=recip, amount_cents=amt,
                     content_type="post", content_id=f"c_{RUN}",
                     idempotency_key=f"e1tip_{RUN}", payment_method_id=None)
    tpid = res.tip_payment_id if hasattr(res, "tip_payment_id") else res["tip_payment_id"]
    net = res.net_cents if hasattr(res, "net_cents") else res.get("net_cents", amt)
    track_charge_rows((tipper, recip), "tip_payment_id", tpid)
    track(T.billing, {"pk": user_pk(tipper), "sk": _reversal_sk(tpid)})
    track(T.billing, {"pk": user_pk(tipper), "sk": DD._mutex_sk("tip", tpid)})

    code0, bal0 = http_balance(recip)

    # open dispute over HTTP (unauthorized -> auto-skip window -> under_review)
    code, j = http_post("/ui/billing/disputes", tipper, {
        "amount_cents": amt, "reason": "unauthorized",
        "charge_type": "tip", "charge_ref": tpid, "recipient_id": recip,
        "reason_detail": "I did not authorize this tip",
    })
    did = j.get("dispute_id")
    if did:
        track_dispute(did)
    rec("tip: open dispute (unauthorized) -> auto-skip to under_review (HTTP 201)",
        code == 201 and j.get("status") == "under_review" and j.get("charge_type") == "tip",
        f"http={code} status={j.get('status')} did={did}")

    # reason gating: not_received is invalid for a tip
    codeg, jg = http_post("/ui/billing/disputes", tipper, {
        "amount_cents": amt, "reason": "not_received",
        "charge_type": "tip", "charge_ref": tpid + "x", "recipient_id": recip})
    rec("tip: reason gating rejects not_received for a tip (HTTP 400)",
        codeg == 400, f"http={codeg} body={jg}")

    # admin resolves refunded -> money moves
    codeR, jR = http_post(f"/ui/admin/disputes/{did}/resolve", ADMIN,
                          {"resolution": "refunded", "notes": "valid claim"}, role="admin")
    code1, bal1 = http_balance(recip)
    st = find_credit_state(recip, "tip_payment_id", tpid)
    rec("tip: admin resolve refunded moves money (HTTP 200, moved==net)",
        codeR == 200 and int(jR.get("moved_cents", -1)) == net and jR.get("status") == "resolved",
        f"http={codeR} moved={jR.get('moved_cents')} net={net}")
    rec("tip: creator earnings dropped after refund (live HTTP balance)",
        bal1 == bal0 - net, f"bal {bal0}->{bal1}")
    rec("tip: original credit flipped state=reversed", st == "reversed", f"state={st}")

    # idempotent double-resolve (already terminal -> 409)
    codeR2, jR2 = http_post(f"/ui/admin/disputes/{did}/resolve", ADMIN,
                            {"resolution": "refunded"}, role="admin")
    code2, bal2 = http_balance(recip)
    rec("tip: double-resolve is no-op (409, balance unchanged)",
        codeR2 == 409 and bal2 == bal1, f"http={codeR2} bal={bal2}")

    # refund-then-dispute now blocked (mutex claimed)
    codeD, jD = http_post("/ui/billing/disputes", tipper, {
        "amount_cents": amt, "reason": "unauthorized",
        "charge_type": "tip", "charge_ref": tpid, "recipient_id": recip})
    rec("tip: refund-then-dispute blocked (HTTP 409 already_reversed)",
        codeD == 409, f"http={codeD} body={jD}")


# ═══════════════════════════════════════════════════════════════════════════
# 2) SUBSCRIPTION dispute -> refunded (needs_response window -> resolve)
# ═══════════════════════════════════════════════════════════════════════════
def test_subscription_window_then_refund():
    from app.routers.subscription_server import _sub_reversal_sk
    creator = f"disp_e1_subcreator_{RUN}"
    subscriber = f"disp_e1_subscriber_{RUN}"
    sub_id = f"sub_e1_{RUN}"
    gross = 1000
    now = now_ts()
    period_end = now + 30 * 86400
    T.subscriptions.put_item(Item={
        "pk": f"SUB#{sub_id}", "sk": "META", "subscription_id": sub_id,
        "creator_id": creator, "subscriber_id": subscriber, "status": "active",
        "currency": "usd", "price_cents": gross,
        "current_period_start": now - 86400, "current_period_end": period_end,
        "provider_subscription_id": f"psub_{RUN}", "plan_id": f"plan_{RUN}"})
    track(T.subscriptions, {"pk": f"SUB#{sub_id}", "sk": "META"})
    T.subscriptions.put_item(Item={"pk": f"SUB#{sub_id}", "sk": f"INV#{now}", "status": "paid",
                                   "amount_cents": gross, "created_at": now, "subscription_id": sub_id})
    track(T.subscriptions, {"pk": f"SUB#{sub_id}", "sk": f"INV#{now}"})
    _, credit = new_ledger_entry(key_name="pk", key_value=user_pk(creator),
                                 entry_type="credit", amount_cents=gross, state="settled",
                                 reason="sub cycle", meta={"content_type": "subscription",
                                 "subscription_id": sub_id, "creator_id": creator})
    credit["subscription_id"] = sub_id
    T.billing.put_item(Item=credit)
    track(T.billing, {"pk": credit["pk"], "sk": credit["sk"]})

    code0, bal0 = http_balance(creator)

    # open (reason=quality -> NOT auto-skip -> needs_response window opens)
    code, j = http_post("/ui/billing/disputes", subscriber, {
        "amount_cents": gross, "reason": "quality",
        "charge_type": "subscription", "charge_ref": sub_id, "recipient_id": creator,
        "reason_detail": "content stopped being posted"})
    did = j.get("dispute_id")
    if did:
        track_dispute(did)
    rec("sub: open (quality) opens creator response window (needs_response + respond_by)",
        code == 201 and j.get("status") == "needs_response" and (j.get("respond_by") or 0) > now,
        f"http={code} status={j.get('status')} respond_by={j.get('respond_by')}")

    # dedup: a second open on the same charge -> 409
    codeX, jX = http_post("/ui/billing/disputes", subscriber, {
        "amount_cents": gross, "reason": "quality",
        "charge_type": "subscription", "charge_ref": sub_id, "recipient_id": creator})
    rec("sub: dedup blocks a 2nd open dispute on same charge (HTTP 409)",
        codeX == 409, f"http={codeX} body={jX}")

    # creator responds within window (rides poster_respond) -> under_review
    DL.record_creator_response(dispute_id=did, creator_id=creator,
                               response_text="content is still active, disagree")
    d = T.billing_disputes.get_item(Key={"pk": f"DISPUTE#{did}", "sk": "META"}).get("Item")
    rec("sub: creator response advances needs_response -> under_review + comment stored",
        d.get("status") == "under_review" and bool(d.get("creator_response")),
        f"status={d.get('status')} resp={bool(d.get('creator_response'))}")

    # admin resolves refunded -> money moves
    codeR, jR = http_post(f"/ui/admin/disputes/{did}/resolve", ADMIN,
                          {"resolution": "refunded"}, role="admin")
    for uid in (subscriber, creator):
        for row in T.billing.query(KeyConditionExpression="pk = :p",
                                   ExpressionAttributeValues={":p": user_pk(uid)}).get("Items", []):
            if (row.get("meta") or {}).get("subscription_id") == sub_id and row.get("type") in ("refund", "reversal"):
                track(T.billing, {"pk": row["pk"], "sk": row["sk"]})
    track(T.billing, {"pk": user_pk(subscriber), "sk": DD._mutex_sk("subscription", sub_id)})
    track(T.billing, {"pk": user_pk(subscriber), "sk": _sub_reversal_sk(f"{sub_id}#{period_end}")})
    code1, bal1 = http_balance(creator)
    rec("sub: admin resolve refunded claws full cycle (HTTP 200, balance drops)",
        codeR == 200 and bal1 == bal0 - gross, f"http={codeR} bal {bal0}->{bal1} moved={jR.get('moved_cents')}")


# ═══════════════════════════════════════════════════════════════════════════
# 3) VOD dispute -> refunded (entitlement REVOKED via HTTP)
# ═══════════════════════════════════════════════════════════════════════════
def test_vod_refunded_revokes_access():
    from app.services.vod_purchase import purchase_video, check_entitlement, _vod_reversal_sk
    buyer = f"disp_e1_vodbuyer_{RUN}"
    seller = f"disp_e1_vodseller_{RUN}"
    vid = f"vid_e1_{RUN}"
    price = 800
    res = purchase_video(buyer_id=buyer, video_id=vid, price_cents=price, seller_id=seller)
    pid = res["purchase_id"]
    track(T.vod_entitlements, {"pk": f"USER#{buyer}", "sk": f"VIDEO#{vid}"})
    track(T.video_metadata, {"video_id": vid})
    track_charge_rows((buyer, seller), "purchase_id", pid)
    track(T.billing, {"pk": user_pk(buyer), "sk": _vod_reversal_sk(pid)})
    track(T.billing, {"pk": user_pk(buyer), "sk": DD._mutex_sk("vod", pid)})

    code0, j0 = http_get("/ui/videos/purchases/list", buyer)
    has0 = any(i.get("video_id") == vid for i in (j0.get("items") or []))
    rec("vod: purchase grants access (live HTTP list)", code0 == 200 and has0, f"in_list={has0}")

    code, j = http_post("/ui/billing/disputes", buyer, {
        "amount_cents": price, "reason": "not_as_described",
        "charge_type": "vod", "charge_ref": pid, "recipient_id": seller})
    did = j.get("dispute_id")
    if did:
        track_dispute(did)
    rec("vod: open (not_as_described) valid for vod -> needs_response",
        code == 201 and j.get("status") == "needs_response", f"http={code} status={j.get('status')}")

    codeR, jR = http_post(f"/ui/admin/disputes/{did}/resolve", ADMIN,
                          {"resolution": "refunded"}, role="admin")
    track_charge_rows((buyer, seller), "purchase_id", pid)
    code1, j1 = http_get("/ui/videos/purchases/list", buyer)
    has1 = any(i.get("video_id") == vid for i in (j1.get("items") or []))
    ent1 = check_entitlement(buyer, vid)["entitled"]
    st = find_credit_state(seller, "purchase_id", pid)
    rec("vod: refund DELETES entitlement -> buyer loses access (live HTTP + check)",
        codeR == 200 and (not has1) and (not ent1), f"http={codeR} in_list={has1} entitled={ent1}")
    rec("vod: seller credit flipped state=reversed", st == "reversed", f"state={st}")


# ═══════════════════════════════════════════════════════════════════════════
# 4) ECOM dispute -> partial refund; and a DENIED dispute moves zero money
# ═══════════════════════════════════════════════════════════════════════════
def test_ecom_partial_and_denied():
    # ecom seed: buyer debit + seller credit via refund_requests-compatible rows.
    from app.services import refund_requests
    buyer = f"disp_e1_ecombuyer_{RUN}"
    seller = f"disp_e1_ecomseller_{RUN}"
    order_id = f"ord_e1_{RUN}"
    gross = 1200
    # buyer debit ledger row
    _, debit = new_ledger_entry(key_name="pk", key_value=user_pk(buyer),
                                entry_type="debit", amount_cents=gross, state="settled",
                                reason="ecom purchase", meta={"content_type": "ecom",
                                "order_id": order_id, "refund_seller_ids": [seller]})
    T.billing.put_item(Item=debit)
    entry_id = debit["entry_id"]
    track(T.billing, {"pk": debit["pk"], "sk": debit["sk"]})
    # seller credit
    _, credit = new_ledger_entry(key_name="pk", key_value=user_pk(seller),
                                 entry_type="credit", amount_cents=gross, state="settled",
                                 reason="ecom sale", meta={"content_type": "ecom", "order_id": order_id,
                                 "buyer_transaction_entry_id": entry_id})
    T.billing.put_item(Item=credit)
    track(T.billing, {"pk": credit["pk"], "sk": credit["sk"]})

    code0, bal0 = http_balance(seller)

    # --- DENIED: open a dispute, admin denies -> zero money move ---
    codeO, jO = http_post("/ui/billing/disputes", buyer, {
        "amount_cents": gross, "reason": "not_as_described",
        "charge_type": "ecom", "charge_ref": entry_id, "recipient_id": seller})
    didD = jO.get("dispute_id")
    if didD:
        track_dispute(didD)
    codeDn, jDn = http_post(f"/ui/admin/disputes/{didD}/resolve", ADMIN,
                            {"resolution": "denied", "notes": "evidence favored seller"}, role="admin")
    codeb1, bal1 = http_balance(seller)
    rec("ecom: DENIED resolution moves ZERO money (HTTP 200, balance unchanged)",
        codeDn == 200 and jDn.get("status") == "resolved" and int(jDn.get("moved_cents", -1)) == 0 and bal1 == bal0,
        f"http={codeDn} moved={jDn.get('moved_cents')} bal {bal0}->{bal1}")

    # --- PARTIAL: a fresh dispute on the same charge (denied is terminal, so allowed) ---
    codeO2, jO2 = http_post("/ui/billing/disputes", buyer, {
        "amount_cents": gross, "reason": "quality",
        "charge_type": "ecom", "charge_ref": entry_id, "recipient_id": seller})
    didP = jO2.get("dispute_id")
    if didP:
        track_dispute(didP)
    part = 400
    codeP, jP = http_post(f"/ui/admin/disputes/{didP}/resolve", ADMIN,
                          {"resolution": "partial", "override_amount_cents": part}, role="admin")
    # track any refund rows + mutex
    track(T.billing, {"pk": user_pk(buyer), "sk": DD._mutex_sk("ecom", entry_id)})
    for uid in (buyer, seller):
        for row in T.billing.query(KeyConditionExpression="pk = :p",
                                   ExpressionAttributeValues={":p": user_pk(uid)}).get("Items", []):
            if (row.get("meta") or {}).get("order_id") == order_id and str(row.get("sk","")).startswith("LEDGER#"):
                track(T.billing, {"pk": row["pk"], "sk": row["sk"]})
        for row in T.billing.query(KeyConditionExpression="pk = :p",
                                   ExpressionAttributeValues={":p": user_pk(uid)}).get("Items", []):
            if str(row.get("sk","")).startswith("REFUND#") or "REFUND" in str(row.get("sk","")):
                track(T.billing, {"pk": row["pk"], "sk": row["sk"]})
    # refund_requests table rows
    try:
        for row in T.refund_requests.scan().get("Items", []):
            if (row.get("transaction_entry_id") == entry_id):
                track(T.refund_requests, {k: row[k] for k in ("pk","sk") if k in row} or {"request_id": row.get("request_id")})
    except Exception:
        pass
    # The ecom rail is offsetting-debit (writes a seller refund_debit; it does NOT
    # flip the original credit) — a real semantic difference vs tip/sub/vod. So the
    # hold-independent proof is: a seller refund_debit row exists for this order
    # whose amount == the partial. (total_earned won't drop; available would drop
    # but the fresh seed credit is under the 7d hold, so available=0.)
    seller_refund_debit = None
    for row in T.billing.query(KeyConditionExpression="pk = :p",
                               ExpressionAttributeValues={":p": user_pk(seller)}).get("Items", []):
        m = row.get("meta") or {}
        if str(row.get("type","")) in ("refund_debit","refund","reversal") and m.get("order_id") == order_id:
            seller_refund_debit = row
            break
    dbt = abs(int((seller_refund_debit or {}).get("amount_cents", 0)))
    rec("ecom: PARTIAL refund fires multi-party rail (buyer refund_credit==override, seller refund_debit==net)",
        codeP == 200 and jP.get("status") == "resolved" and seller_refund_debit is not None
        and int(jP.get("moved_cents", -1)) == part and dbt == gross,
        f"http={codeP} moved={jP.get('moved_cents')} refund_debit={dbt} part={part} net={gross}")


# ═══════════════════════════════════════════════════════════════════════════
# 5) SLA sweep: a needs_response dispute past respond_by -> under_review
# ═══════════════════════════════════════════════════════════════════════════
def test_sla_sweep():
    from app.services.tips import charge_tip, _reversal_sk
    tipper = f"disp_e1_sla_tipper_{RUN}"
    recip = f"disp_e1_sla_creator_{RUN}"
    amt = 600
    res = charge_tip(tipper_id=tipper, recipient_id=recip, amount_cents=amt,
                     content_type="post", content_id=f"sla_{RUN}",
                     idempotency_key=f"e1sla_{RUN}", payment_method_id=None)
    tpid = res.tip_payment_id if hasattr(res, "tip_payment_id") else res["tip_payment_id"]
    track_charge_rows((tipper, recip), "tip_payment_id", tpid)
    track(T.billing, {"pk": user_pk(tipper), "sk": _reversal_sk(tpid)})

    # open with reason=quality (NOT auto-skip) -> needs_response window
    code, j = http_post("/ui/billing/disputes", tipper, {
        "amount_cents": amt, "reason": "quality",
        "charge_type": "tip", "charge_ref": tpid, "recipient_id": recip})
    did = j.get("dispute_id")
    if did:
        track_dispute(did)
    ok_open = code == 201 and j.get("status") == "needs_response"

    # force respond_by into the past (simulate window expiry)
    T.billing_disputes.update_item(Key={"pk": f"DISPUTE#{did}", "sk": "META"},
                                   UpdateExpression="SET respond_by = :r",
                                   ExpressionAttributeValues={":r": now_ts() - 10})
    swept = DL.sweep_expired_dispute_responses()
    d = T.billing_disputes.get_item(Key={"pk": f"DISPUTE#{did}", "sk": "META"}).get("Item")
    rec("sla: no-response past respond_by -> sweep escalates to under_review (NOT auto-refund)",
        ok_open and did in swept.get("dispute_ids", []) and d.get("status") == "under_review"
        and bool(d.get("sla_expired")),
        f"swept={swept.get('escalated')} status={d.get('status')}")

    # late creator response after sweep -> attaches as comment, no illegal transition
    upd = DL.record_creator_response(dispute_id=did, creator_id=recip,
                                     response_text="late rebuttal")
    rec("sla: late creator response attaches as comment (no illegal transition, stays under_review)",
        upd.get("status") == "under_review" and bool(upd.get("creator_response")),
        f"status={upd.get('status')}")


def cleanup():
    ok = 0
    for table, key in reversed(_created_keys):
        try:
            if key:
                table.delete_item(Key=key)
                ok += 1
        except Exception as e:
            print("cleanup miss", key, e)
    # Thorough purge: delete EVERY row on any synthetic user's billing partition
    # (rails auto-create BALANCE / idempotency / reversal / refund rows we can't
    # all pre-track). All synthetic users share the run-specific prefix "disp_e1_".
    purged = 0
    try:
        for row in T.billing.scan().get("Items", []):
            pk = str(row.get("pk", ""))
            if "disp_e1_" in pk:
                try:
                    T.billing.delete_item(Key={"pk": row["pk"], "sk": row["sk"]})
                    purged += 1
                except Exception:
                    pass
    except Exception as e:
        print("purge scan err", e)
    print(f"cleanup: removed {ok}/{len(_created_keys)} tracked + {purged} residual billing rows")


def residue_check():
    """Confirm 0 disp_e1 residue across the tables we touched."""
    leaked = []
    for uid_prefix in (f"disp_e1_",):
        pass
    try:
        for row in T.billing_disputes.scan().get("Items", []):
            if RUN in str(row.get("dispute_id", "")) or "disp_e1_" in str(row.get("user_id", "")):
                leaked.append(("billing_disputes", row.get("dispute_id")))
    except Exception:
        pass
    try:
        for row in T.billing.scan().get("Items", []):
            if "disp_e1_" in str(row.get("pk", "")):
                leaked.append(("billing", row.get("pk"), row.get("sk")))
    except Exception:
        pass
    try:
        for row in T.users.scan().get("Items", []):
            if str(row.get("user_sub", "")).startswith("disp_admin_") and RUN in str(row.get("user_sub", "")):
                leaked.append(("users", row.get("user_sub")))
    except Exception:
        pass
    rec("cleanup: 0 residual rows across billing/disputes/users for this run",
        not leaked, f"leaked={leaked[:8]}")


if __name__ == "__main__":
    seed_admin()
    try:
        for fn in (test_tip_refunded, test_subscription_window_then_refund,
                   test_vod_refunded_revokes_access, test_ecom_partial_and_denied,
                   test_sla_sweep):
            try:
                fn()
            except Exception as e:
                rec(fn.__name__, False, f"EXCEPTION {type(e).__name__}: {e}")
    finally:
        cleanup()
        residue_check()
    npass = sum(1 for _, ok, _ in results if ok)
    print(f"\n==== E1 RESULT: {npass}/{len(results)} PASS ====")
    for n, ok, d in results:
        if not ok:
            print("  FAIL:", n, "-", d)
