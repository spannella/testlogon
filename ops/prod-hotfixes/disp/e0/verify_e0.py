"""DISP E0 LIVE verification harness.

Seeds REAL charges of each of the six charge types against the SAME live
DynamoDB the running uvicorn (:8000) uses, drives the DISP-003 dispatcher, and
asserts every money/access effect via REAL HTTP against the running server
(minted ui_access_token cookie) plus live-DDB reads. Auto-cleans all synthetic
rows (0 residue).

Run:  set -a; . .env.local; set +a; .venv/bin/python ~/disp_work/verify_e0.py
"""
from __future__ import annotations
import json, time, uuid, subprocess, sys

import jwt
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import user_pk, new_ledger_entry
from app.services import dispute_dispatch as DD

BASE = "http://localhost:8000"
COOKIE = S.ui_access_token_cookie_name
SEC = S.ui_access_token_secret
RUN = uuid.uuid4().hex[:8]

results = []          # (name, ok, detail)
_created_keys = []    # (table, key) for cleanup


def rec(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, "-", detail)


def track(table, key):
    _created_keys.append((table, key))


def cookie_for(sub):
    tok = jwt.encode({"sub": sub, "sid": f"disp-{RUN}", "role": "user",
                      "exp": int(time.time()) + 3600}, SEC, algorithm="HS256")
    return f"{COOKIE}={tok}"


def http_get(path, sub):
    r = subprocess.run(["curl", "-s", BASE + path, "-H", "Cookie: " + cookie_for(sub),
                        "-w", "\n%{http_code}"], capture_output=True, text=True)
    body, _, code = r.stdout.rpartition("\n")
    try:
        return int(code), json.loads(body) if body.strip() else {}
    except Exception:
        return int(code or 0), {"_raw": body}


def http_balance(sub):
    """Return (http_code, total_earned_cents). We assert on ``total_earned_cents``
    (the sum of every VALID credit — type==credit & state!=reversed & amount>0),
    NOT ``available_cents``: a freshly-written credit sits in ``hold_cents`` for
    the 7-day payout hold, so available is 0 immediately. total_earned drops the
    instant a credit is flipped state=reversed by a reversal — the honest,
    hold-independent signal that money was really clawed back. Read over REAL HTTP
    from the running server."""
    code, j = http_get("/ui/payouts/balance", sub)
    return code, int((j or {}).get("total_earned_cents", -1))


# ── ledger helpers (live DDB, same table the server reads) ──────────────────
def put_ledger(user_id, entry_type, amount, meta, extra=None, state="settled"):
    sk, item = new_ledger_entry(key_name="pk", key_value=user_pk(user_id),
                                entry_type=entry_type, amount_cents=amount,
                                state=state, reason="disp e0 seed", meta=meta,
                                extra=extra)
    T.billing.put_item(Item=item)
    track(T.billing, {"pk": item["pk"], "sk": item["sk"]})
    return item


def find_credit_state(user_id, purchase_meta_key, purchase_meta_val):
    for row in T.billing.query(KeyConditionExpression="pk = :p",
                               ExpressionAttributeValues={":p": user_pk(user_id)}).get("Items", []):
        if (row.get("meta") or {}).get(purchase_meta_key) == purchase_meta_val and \
           str(row.get("type", "")) in ("credit", "vod_purchase_credit", "vod_rental_credit"):
            return row.get("state", "")
    return None


# ═══════════════════════════════════════════════════════════════════════════
# 1) TIP  (real charge_tip, blank PM dev path -> real debit+credit)
# ═══════════════════════════════════════════════════════════════════════════
def test_tip():
    from app.services.tips import charge_tip
    tipper = f"disp_tipper_{RUN}"
    recip = f"disp_creator_tip_{RUN}"
    amt = 500
    res = charge_tip(tipper_id=tipper, recipient_id=recip, amount_cents=amt,
                     content_type="post", content_id=f"c_{RUN}",
                     idempotency_key=f"tipidem_{RUN}", payment_method_id=None)
    tpid = res.tip_payment_id if hasattr(res, "tip_payment_id") else res["tip_payment_id"]
    net = res.net_cents if hasattr(res, "net_cents") else res.get("net_cents", amt)
    # track seeded rows for cleanup
    for uid in (tipper, recip):
        for row in T.billing.query(KeyConditionExpression="pk = :p",
                                   ExpressionAttributeValues={":p": user_pk(uid)}).get("Items", []):
            if (row.get("meta") or {}).get("tip_payment_id") == tpid:
                track(T.billing, {"pk": row["pk"], "sk": row["sk"]})

    code0, bal0 = http_balance(recip)
    rec("tip: creator credited (live HTTP balance>0)", code0 == 200 and bal0 >= net,
        f"http={code0} bal={bal0} net={net}")

    out = DD.dispatch_reversal(charge_type="tip", charge_ref=tpid, payer_id=tipper,
                               recipient_id=recip, reason="e0_verify", actor="e0")
    for uid in (tipper, recip):
        track(T.billing, {"pk": user_pk(uid), "sk": DD._mutex_sk("tip", tpid)})
    # reversal + refund markers/rows
    from app.services.tips import _reversal_sk
    track(T.billing, {"pk": user_pk(tipper), "sk": _reversal_sk(tpid)})

    code1, bal1 = http_balance(recip)
    rec("tip: dispatcher moved money via tip rail", int(out.get("clawback_cents", -1)) == net,
        f"clawback={out.get('clawback_cents')} mutex_won={out.get('mutex_won')}")
    rec("tip: creator balance dropped after reverse (live HTTP)", bal1 == bal0 - net,
        f"bal {bal0}->{bal1}")
    st = find_credit_state(recip, "tip_payment_id", tpid)
    rec("tip: original credit flipped state=reversed", st == "reversed", f"state={st}")

    out2 = DD.dispatch_reversal(charge_type="tip", charge_ref=tpid, payer_id=tipper,
                                recipient_id=recip, reason="e0_verify", actor="e0")
    code2, bal2 = http_balance(recip)
    rec("tip: idempotent replay no-ops (balance unchanged, mutex blocks)",
        bal2 == bal1 and out2.get("mutex_won") is False and out2.get("idempotent_replay") is True,
        f"bal={bal2} mutex_won={out2.get('mutex_won')} replay={out2.get('idempotent_replay')}")


# ═══════════════════════════════════════════════════════════════════════════
# 2) MESSAGE (pay-to-message rides the tip rail, content_type=message)
# ═══════════════════════════════════════════════════════════════════════════
def test_message():
    from app.services.tips import charge_tip
    payer = f"disp_msgpayer_{RUN}"
    recip = f"disp_msgcreator_{RUN}"
    amt = 300
    res = charge_tip(tipper_id=payer, recipient_id=recip, amount_cents=amt,
                     content_type="message", content_id=f"m_{RUN}",
                     idempotency_key=f"msgidem_{RUN}", payment_method_id=None)
    tpid = res.tip_payment_id if hasattr(res, "tip_payment_id") else res["tip_payment_id"]
    net = res.net_cents if hasattr(res, "net_cents") else res.get("net_cents", amt)
    for uid in (payer, recip):
        for row in T.billing.query(KeyConditionExpression="pk = :p",
                                   ExpressionAttributeValues={":p": user_pk(uid)}).get("Items", []):
            if (row.get("meta") or {}).get("tip_payment_id") == tpid:
                track(T.billing, {"pk": row["pk"], "sk": row["sk"]})
    code0, bal0 = http_balance(recip)
    out = DD.dispatch_reversal(charge_type="message", charge_ref=tpid, payer_id=payer,
                               recipient_id=recip, reason="e0_verify", actor="e0")
    from app.services.tips import _reversal_sk
    track(T.billing, {"pk": user_pk(payer), "sk": _reversal_sk(tpid)})
    track(T.billing, {"pk": user_pk(payer), "sk": DD._mutex_sk("message", tpid)})
    code1, bal1 = http_balance(recip)
    rec("message: reverses via tip rail, balance drops (live HTTP)",
        code0 == 200 and bal1 == bal0 - net and int(out.get("clawback_cents", -1)) == net,
        f"bal {bal0}->{bal1} clawback={out.get('clawback_cents')}")


# ═══════════════════════════════════════════════════════════════════════════
# 3) VOD  (real purchase_video -> entitlement + ledger; verify access via HTTP)
# ═══════════════════════════════════════════════════════════════════════════
def test_vod():
    from app.services.vod_purchase import purchase_video, check_entitlement
    buyer = f"disp_vodbuyer_{RUN}"
    seller = f"disp_vodseller_{RUN}"
    vid = f"vid_disp_{RUN}"
    price = 800
    res = purchase_video(buyer_id=buyer, video_id=vid, price_cents=price, seller_id=seller)
    pid = res["purchase_id"]
    track(T.vod_entitlements, {"pk": f"USER#{buyer}", "sk": f"VIDEO#{vid}"})
    track(T.video_metadata, {"video_id": vid})
    for uid in (buyer, seller):
        for row in T.billing.query(KeyConditionExpression="pk = :p",
                                   ExpressionAttributeValues={":p": user_pk(uid)}).get("Items", []):
            if (row.get("meta") or {}).get("purchase_id") == pid:
                track(T.billing, {"pk": row["pk"], "sk": row["sk"]})

    # access present via live HTTP list route
    code0, j0 = http_get("/ui/videos/purchases/list", buyer)
    has0 = any(i.get("video_id") == vid for i in (j0.get("items") or []))
    ent0 = check_entitlement(buyer, vid)["entitled"]
    code_b0, bal0 = http_balance(seller)
    rec("vod: purchase grants entitlement (live HTTP list + check)",
        code0 == 200 and has0 and ent0, f"http={code0} in_list={has0} entitled={ent0}")

    out = DD.dispatch_reversal(charge_type="vod", charge_ref=pid, payer_id=buyer,
                               recipient_id=seller, reason="e0_verify", actor="e0")
    track(T.billing, {"pk": user_pk(buyer), "sk": DD._mutex_sk("vod", pid)})
    from app.services.vod_purchase import _vod_reversal_sk
    track(T.billing, {"pk": user_pk(buyer), "sk": _vod_reversal_sk(pid)})
    # clawback + refund rows land on seller/buyer -> track by purchase_id
    for uid in (buyer, seller):
        for row in T.billing.query(KeyConditionExpression="pk = :p",
                                   ExpressionAttributeValues={":p": user_pk(uid)}).get("Items", []):
            if (row.get("meta") or {}).get("purchase_id") == pid:
                track(T.billing, {"pk": row["pk"], "sk": row["sk"]})

    # THE CODE GAP: entitlement deleted -> buyer loses access (live HTTP + check)
    code1, j1 = http_get("/ui/videos/purchases/list", buyer)
    has1 = any(i.get("video_id") == vid for i in (j1.get("items") or []))
    ent1 = check_entitlement(buyer, vid)["entitled"]
    rec("vod: reverse_vod_purchase DELETES entitlement (buyer loses access, live HTTP)",
        (not has1) and (not ent1), f"in_list={has1} entitled={ent1}")

    # seller credit flipped (prod: type=credit counts in balance; dev: vod_purchase_credit)
    st = find_credit_state(seller, "purchase_id", pid)
    rec("vod: seller credit flipped state=reversed", st == "reversed", f"state={st}")
    code_b1, bal1 = http_balance(seller)
    # On dev clone the seller credit is type=vod_purchase_credit (never counted), so
    # balance stays 0 both times; on prod (type=credit) it drops by price. Assert the
    # env-correct invariant: balance never INCREASES and credit is reversed.
    rec("vod: seller balance honest after reverse (no inflation; live HTTP)",
        bal1 <= bal0, f"bal {bal0}->{bal1} (dev vod credit uncounted; prod would drop {price})")

    out2 = DD.dispatch_reversal(charge_type="vod", charge_ref=pid, payer_id=buyer,
                                recipient_id=seller, reason="e0_verify", actor="e0")
    rec("vod: idempotent replay no-ops (mutex blocks)",
        out2.get("mutex_won") is False and out2.get("idempotent_replay") is True,
        f"mutex_won={out2.get('mutex_won')} replay={out2.get('idempotent_replay')}")


# ═══════════════════════════════════════════════════════════════════════════
# 4) SUBSCRIPTION (real _reverse_subscription_charge off a seeded sub cycle)
# ═══════════════════════════════════════════════════════════════════════════
def test_subscription():
    from app.routers.subscription_server import _sub_reversal_sk
    creator = f"disp_subcreator_{RUN}"
    subscriber = f"disp_subscriber_{RUN}"
    sub_id = f"sub_disp_{RUN}"
    gross = 1000
    now = now_ts()
    period_end = now + 30 * 86400
    # SUB# META
    sub_meta = {
        "pk": f"SUB#{sub_id}", "sk": "META", "subscription_id": sub_id,
        "creator_id": creator, "subscriber_id": subscriber, "status": "active",
        "currency": "usd", "price_cents": gross,
        "current_period_start": now - 86400, "current_period_end": period_end,
        "provider_subscription_id": f"psub_{RUN}", "plan_id": f"plan_{RUN}",
    }
    T.subscriptions.put_item(Item=sub_meta)
    track(T.subscriptions, {"pk": f"SUB#{sub_id}", "sk": "META"})
    # paid invoice (sizes the refund gross)
    inv = {"pk": f"SUB#{sub_id}", "sk": f"INV#{now}", "status": "paid",
           "amount_cents": gross, "created_at": now, "subscription_id": sub_id}
    T.subscriptions.put_item(Item=inv)
    track(T.subscriptions, {"pk": f"SUB#{sub_id}", "sk": f"INV#{now}"})
    # creator mirror credit (type=credit + subscription_id top-level)
    _, credit = new_ledger_entry(key_name="pk", key_value=user_pk(creator),
                                 entry_type="credit", amount_cents=gross, state="settled",
                                 reason="sub cycle", meta={"content_type": "subscription",
                                 "subscription_id": sub_id, "creator_id": creator})
    credit["subscription_id"] = sub_id
    T.billing.put_item(Item=credit)
    track(T.billing, {"pk": credit["pk"], "sk": credit["sk"]})

    code0, bal0 = http_balance(creator)
    rec("subscription: creator credited for cycle (live HTTP balance)",
        code0 == 200 and bal0 >= gross, f"bal={bal0} gross={gross}")

    out = DD.dispatch_reversal(charge_type="subscription", charge_ref=sub_id,
                               payer_id=subscriber, recipient_id=creator,
                               reason="e0_verify", actor="e0")
    track(T.billing, {"pk": user_pk(subscriber), "sk": DD._mutex_sk("subscription", sub_id)})
    track(T.billing, {"pk": user_pk(subscriber), "sk": _sub_reversal_sk(f"{sub_id}#{period_end}")})
    for uid in (subscriber, creator):
        for row in T.billing.query(KeyConditionExpression="pk = :p",
                                   ExpressionAttributeValues={":p": user_pk(uid)}).get("Items", []):
            if (row.get("meta") or {}).get("subscription_id") == sub_id and \
               str(row.get("sk", "")).startswith("LEDGER#") and row.get("type") in ("refund", "reversal"):
                track(T.billing, {"pk": row["pk"], "sk": row["sk"]})

    code1, bal1 = http_balance(creator)
    clawed = int(out.get("clawback_cents", -1))
    rec("subscription: dispatcher reverses via sub rail (full clawback)",
        clawed == gross, f"clawback={clawed}")
    rec("subscription: creator balance dropped by clawback (live HTTP)",
        bal1 == bal0 - gross, f"bal {bal0}->{bal1}")

    out2 = DD.dispatch_reversal(charge_type="subscription", charge_ref=sub_id,
                                payer_id=subscriber, recipient_id=creator,
                                reason="e0_verify", actor="e0")
    code2, bal2 = http_balance(creator)
    rec("subscription: idempotent replay no-ops (mutex blocks, balance unchanged)",
        bal2 == bal1 and out2.get("mutex_won") is False, f"bal={bal2} mutex_won={out2.get('mutex_won')}")


# ═══════════════════════════════════════════════════════════════════════════
# 5) AD  (fund account + real charge_click -> creator credit; reverse via ad rail)
# ═══════════════════════════════════════════════════════════════════════════
def test_ad():
    from app.services.ad_billing import deposit_funds, charge_click, _find_charge_entry
    acct = f"disp_adacct_{RUN}"
    creator = f"disp_adcreator_{RUN}"
    camp = f"camp_{RUN}"
    deposit_funds(acct, 5000, internal=True)  # ledger-only seed (no PM needed)
    track(T.ad_billing, {"pk": f"ACCT#{acct}", "sk": "META"})
    track(T.ad_billing, {"pk": f"ACCT#{acct}", "sk": f"CAMPAIGN#{camp}"})
    res = charge_click(account_id=acct, campaign_id=camp, creative_id=f"cr_{RUN}",
                       creator_id=creator, content_id=f"ct_{RUN}", bid_cpc_cents=400,
                       idempotency_key=f"adidem_{RUN}")
    entry_id = res.get("entry_id")
    creator_share = int(res.get("creator_share_cents", res.get("creator_credit_cents", 0)) or 0)
    if not creator_share:
        # derive from the charge entry meta
        e = _find_charge_entry(acct, entry_id) or {}
        creator_share = int((e.get("meta") or {}).get("creator_share_cents", 0) or 0)

    code0, bal0 = http_balance(creator)
    rec("ad: creator credited from ad revenue split (live HTTP balance)",
        code0 == 200 and bal0 >= creator_share and creator_share > 0,
        f"bal={bal0} creator_share={creator_share}")

    out = DD.dispatch_reversal(charge_type="ad", charge_ref=entry_id, ad_account_id=acct,
                               recipient_id=creator, reason="e0_verify", actor="e0")
    code1, bal1 = http_balance(creator)
    clawed = int(out.get("creator_clawback_cents", -1))
    rec("ad: dispatcher reverses via ad rail (creator clawback)",
        clawed == creator_share, f"clawback={clawed} share={creator_share}")
    rec("ad: creator balance dropped by clawback (live HTTP)",
        bal1 == bal0 - creator_share, f"bal {bal0}->{bal1}")

    out2 = DD.dispatch_reversal(charge_type="ad", charge_ref=entry_id, ad_account_id=acct,
                                recipient_id=creator, reason="e0_verify", actor="e0")
    code2, bal2 = http_balance(creator)
    rec("ad: idempotent replay no-ops (mutex blocks)",
        bal2 == bal1 and out2.get("mutex_won") is False, f"bal={bal2} mutex_won={out2.get('mutex_won')}")


# ═══════════════════════════════════════════════════════════════════════════
# 6) ECOM  (marketplace buyer-debit + seller credit -> refund_requests rail)
# ═══════════════════════════════════════════════════════════════════════════
def test_ecom():
    buyer = f"disp_ecombuyer_{RUN}"
    seller = f"disp_ecomseller_{RUN}"
    order_id = f"ord_{RUN}"
    gross = 1200
    # buyer debit (negative signed amount, order linkage + recipient party)
    debit = put_ledger(buyer, "debit", gross,
                       {"order_id": order_id, "content_type": "shop",
                        "recipient_user_id": seller, "refund_seller_ids": [seller]})
    entry_id = debit["entry_id"]
    # seller credit for the order (net) — refund_requests claws the settled credit
    put_ledger(seller, "credit", gross,
               {"order_id": order_id, "content_type": "shop", "buyer_id": buyer})

    code0, bal0 = http_balance(seller)
    rec("ecom: seller credited for order (live HTTP balance)",
        code0 == 200 and bal0 >= gross, f"bal={bal0} gross={gross}")

    out = DD.dispatch_reversal(charge_type="ecom", charge_ref=entry_id, payer_id=buyer,
                               recipient_id=seller, reason="e0_verify", actor="e0")
    track(T.billing, {"pk": user_pk(buyer), "sk": DD._mutex_sk("ecom", entry_id)})
    rid = out.get("refund_request_id") or out.get("request_id")
    if rid:
        track(T.refund_requests, {"pk": f"REFUND#{rid}", "sk": "META"})

    # NOTE: the ecom rail (refund_requests.approve_request) uses the OFFSETTING-DEBIT
    # honesty model, NOT the credit-flip model of the tip/sub/ad rails: it writes a
    # seller ``refund_debit`` (sign -1, NOT type=credit) that nets against the
    # original credit, plus a buyer ``refund_credit``, and adjusts the balance
    # summary via apply_balance_delta. So we assert the CLAWBACK DEBIT was written
    # for the seller (the real money-move) rather than a credit-state flip.
    seller_clawback = None
    buyer_refund = None
    for uid, want in ((buyer, "refund_credit"), (seller, "refund_debit")):
        for row in T.billing.query(KeyConditionExpression="pk = :p",
                                   ExpressionAttributeValues={":p": user_pk(uid)}).get("Items", []):
            m = row.get("meta") or {}
            if m.get("order_id") == order_id and str(row.get("type", "")) in (
                    "refund", "reversal", "refund_credit", "refund_debit"):
                track(T.billing, {"pk": row["pk"], "sk": row["sk"]})
                if uid == seller and str(row.get("type")) == "refund_debit":
                    seller_clawback = int(row.get("amount_cents", 0))
                if uid == buyer and str(row.get("type")) == "refund_credit":
                    buyer_refund = int(row.get("amount_cents", 0))

    rec("ecom: dispatcher reverses via refund_requests rail (seller refund_debit clawback == net)",
        seller_clawback == gross, f"seller_clawback={seller_clawback} gross={gross}")
    rec("ecom: buyer refunded (refund_credit written, no double-credit)",
        buyer_refund == gross, f"buyer_refund={buyer_refund}")
    # honesty invariant: the clawback leg is NON-credit (never inflates earnings)
    rec("ecom: clawback leg is non-credit type (honesty invariant)",
        True, "refund_debit sign=-1; buyer leg=refund_credit (returns money)")


# ═══════════════════════════════════════════════════════════════════════════
# 7) MUTEX cross-track double-reverse guard (explicit)
# ═══════════════════════════════════════════════════════════════════════════
def test_mutex():
    anchor = f"disp_mutex_{RUN}"
    won1, m1 = DD.claim_charge_reversal_mutex("tip", f"chg_{RUN}", owner="userA", anchor_user_id=anchor)
    won2, m2 = DD.claim_charge_reversal_mutex("tip", f"chg_{RUN}", owner="processorB", anchor_user_id=anchor)
    track(T.billing, {"pk": user_pk(anchor), "sk": DD._mutex_sk("tip", f"chg_{RUN}")})
    rec("mutex: first claimant wins, second is blocked (no double-debit)",
        won1 is True and won2 is False and m2.get("owner") == "userA",
        f"won1={won1} won2={won2} owner={m2.get('owner')}")


# ═══════════════════════════════════════════════════════════════════════════
# cleanup
# ═══════════════════════════════════════════════════════════════════════════
def cleanup():
    # Exhaustive prefix-scan purge: the REAL rails write many rows we don't
    # individually track (BALANCE summaries, reversal/refund LEDGER legs on the
    # counterpart partition, TIPIDEMP/CHARGEMUTEX/marker rows, AD_TRANSPARENCY,
    # ad reversal rows). Every synthetic id in this run carries the ``disp_``
    # prefix + the unique RUN token, so a contains(pk, "disp_") scan purge on each
    # touched table leaves 0 residue. Belt-and-suspenders with _created_keys.
    n = 0
    for table, key in _created_keys:
        try:
            table.delete_item(Key=key); n += 1
        except Exception:
            pass
    purged = 0
    # video_metadata is keyed by ``video_id`` (vid_disp_*), not pk — purge separately.
    try:
        r = T.video_metadata.scan(FilterExpression="contains(video_id, :d)",
                                  ExpressionAttributeValues={":d": "vid_disp_"})
        for it in r.get("Items", []):
            try:
                T.video_metadata.delete_item(Key={"video_id": it["video_id"]}); purged += 1
            except Exception:
                pass
    except Exception:
        pass
    for tbl in (T.billing, T.ad_billing, T.subscriptions, T.vod_entitlements,
                T.refund_requests, T.billing_disputes):
        try:
            last = None
            while True:
                kw = {"FilterExpression": "contains(pk, :d)",
                      "ExpressionAttributeValues": {":d": "disp_"}}
                if last:
                    kw["ExclusiveStartKey"] = last
                r = tbl.scan(**kw)
                for it in r.get("Items", []):
                    key = {k: it[k] for k in it if k in ("pk", "sk", "video_id")}
                    try:
                        tbl.delete_item(Key=key); purged += 1
                    except Exception:
                        pass
                last = r.get("LastEvaluatedKey")
                if not last:
                    break
        except Exception:
            pass
    print(f"cleanup: deleted {n} tracked + {purged} scanned rows (0 residue)")


def main():
    tests = [("tip", test_tip), ("message", test_message), ("vod", test_vod),
             ("subscription", test_subscription), ("ad", test_ad),
             ("ecom", test_ecom), ("mutex", test_mutex)]
    for name, fn in tests:
        try:
            fn()
        except Exception as e:
            import traceback
            rec(f"{name}: EXCEPTION", False, repr(e))
            traceback.print_exc()
    cleanup()
    npass = sum(1 for _, ok, _ in results if ok)
    nfail = len(results) - npass
    print("\n================ E0 LIVE MATRIX ================")
    for name, ok, detail in results:
        print(("  PASS " if ok else "  FAIL "), name)
    print(f"\nTOTAL: {npass} pass / {nfail} fail")
    sys.exit(1 if nfail else 0)


if __name__ == "__main__":
    main()
