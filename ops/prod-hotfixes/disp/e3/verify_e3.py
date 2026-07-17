"""DISP E3 LIVE verification harness (processor chargeback track).

Seeds REAL charges (tip / vod / subscription / ecom) against the SAME live
DynamoDB the running uvicorn (:8000) uses, then drives the PROCESSOR chargeback
flow over REAL HTTP by POSTing a *signed* mock Stripe webhook to
``/api/billing/webhooks/stripe`` (HMAC-signed with the local whsec so real
signature verification passes):

    charge.dispute.created         -> funds HELD (drop out of available balance)
    charge.dispute.funds_withdrawn -> maps to opened (idempotent hold)
    charge.dispute.funds_reinstated-> maps to opened
    charge.dispute.closed [lost]   -> creator clawed + chargeback_fee + earnings
                                      drop + NO buyer double-refund
    charge.dispute.closed [won]    -> hold released, credit restored, no ledger move
    + evidence assembler (mock submit records)
    + idempotent redelivery per provider event

Asserts every money/access effect via live HTTP + live-DDB reads. Auto-cleans
all synthetic rows (0 residue).

Run:  set -a; . .env.local; set +a; .venv/bin/python ~/disp_work/verify_e3.py
"""
from __future__ import annotations
import hashlib
import hmac
import json
import subprocess
import time
import uuid

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import user_pk, new_ledger_entry
from app.services import dispute_dispatch as DD
from app.services import dispute_chargeback as CB

BASE = "http://localhost:8000"
COOKIE = S.ui_access_token_cookie_name
SEC = S.ui_access_token_secret
WHSEC = S.stripe_webhook_secret
RUN = uuid.uuid4().hex[:8]

results = []
_created_keys = []


def rec(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, "-", detail)


def track(table, key):
    _created_keys.append((table, key))


def track_charge_rows(uids, meta_key, meta_val):
    for uid in uids:
        for row in T.billing.query(KeyConditionExpression="pk = :p",
                                   ExpressionAttributeValues={":p": user_pk(uid)}).get("Items", []):
            if (row.get("meta") or {}).get(meta_key) == meta_val:
                track(T.billing, {"pk": row["pk"], "sk": row["sk"]})


def http_available(sub):
    args = ["curl", "-s", BASE + "/ui/payouts/balance",
            "-H", "Cookie: " + _cookie(sub), "-w", "\n%{http_code}"]
    r = subprocess.run(args, capture_output=True, text=True)
    txt, _, code = r.stdout.rpartition("\n")
    try:
        j = json.loads(txt) if txt.strip() else {}
    except Exception:
        j = {}
    return int(code or 0), int(j.get("available_cents", -1)), int(j.get("total_earned_cents", -1))


def _cookie(sub, role="user"):
    import jwt
    tok = jwt.encode({"sub": sub, "sid": f"disp3-{RUN}", "role": role,
                      "exp": int(time.time()) + 3600}, SEC, algorithm="HS256")
    return f"{COOKIE}={tok}"


def credit_state(user_id, meta_key, meta_val):
    for row in T.billing.query(KeyConditionExpression="pk = :p",
                               ExpressionAttributeValues={":p": user_pk(user_id)}).get("Items", []):
        m = row.get("meta") or {}
        if m.get(meta_key) == meta_val and str(row.get("type", "")) in (
                "credit", "vod_purchase_credit", "vod_rental_credit"):
            return row.get("state", "")
    return None


def has_ledger_type(user_id, typ, *, meta_key=None, meta_val=None):
    for row in T.billing.query(KeyConditionExpression="pk = :p",
                               ExpressionAttributeValues={":p": user_pk(user_id)}).get("Items", []):
        if str(row.get("type", "")) != typ:
            continue
        if meta_key is not None and (row.get("meta") or {}).get(meta_key) != meta_val:
            continue
        return row
    return None


# --- Stripe-signed webhook POST -------------------------------------------

def stripe_event(event_type, dispute_id, charge_id, status, amount_cents, *, metadata=None,
                 currency="usd", due_by=None, evt_id=None):
    obj = {
        "id": dispute_id, "object": "dispute", "charge": charge_id,
        "amount": amount_cents, "currency": currency, "status": status,
        "metadata": metadata or {},
    }
    if due_by is not None:
        obj["evidence_details"] = {"due_by": due_by}
    return {"id": evt_id or f"evt_{uuid.uuid4().hex[:16]}", "type": event_type,
            "data": {"object": obj}}


def post_webhook(event):
    body = json.dumps(event).encode("utf-8")
    ts = int(time.time())
    signed = f"{ts}.".encode() + body
    sig = hmac.new(WHSEC.encode(), signed, hashlib.sha256).hexdigest()
    header = f"t={ts},v1={sig}"
    args = ["curl", "-s", "-X", "POST", BASE + "/api/billing/webhooks/stripe",
            "-H", "Content-Type: application/json",
            "-H", f"Stripe-Signature: {header}",
            "--data-binary", "@-", "-w", "\n%{http_code}"]
    r = subprocess.run(args, input=body.decode("utf-8"), capture_output=True, text=True)
    txt, _, code = r.stdout.rpartition("\n")
    try:
        return int(code or 0), (json.loads(txt) if txt.strip() else {})
    except Exception:
        return int(code or 0), {"_raw": txt}


def incident_for(dispute_id):
    """The incident row Stripe dispute_id maps to (provider_incident_id)."""
    from app.services.payment_incidents_store import DynamoPaymentIncidentRepository
    repo = DynamoPaymentIncidentRepository()
    got = repo.list_incidents_by_case(provider="stripe", case_id=dispute_id, limit=1)
    return got[0] if got else None


def track_incident(dispute_id, payer_anchor):
    inc = incident_for(dispute_id)
    if inc:
        track(T.payment_incidents, {"incident_id": inc["incident_id"]})
        iid = inc["incident_id"]
        for sk in (f"CHARGEBACK_HOLD#{iid}", f"CHARGEBACK_LOST#{iid}", f"CHARGEBACK_RELEASE#{iid}"):
            track(T.billing, {"pk": user_pk(payer_anchor), "sk": sk})
    return inc


# ═══════════════════════════════════════════════════════════════════════════
# 1) TIP chargeback -> LOST: hold on open, clawback + fee, no buyer double-refund
# ═══════════════════════════════════════════════════════════════════════════
def test_tip_chargeback_lost():
    from app.services.tips import charge_tip, _reversal_sk
    tipper = f"disp_e3_tipper_{RUN}"
    recip = f"disp_e3_creator_{RUN}"
    amt = 500
    res = charge_tip(tipper_id=tipper, recipient_id=recip, amount_cents=amt,
                     content_type="post", content_id=f"c_{RUN}",
                     idempotency_key=f"e3tip_{RUN}", payment_method_id=None)
    tpid = res.tip_payment_id if hasattr(res, "tip_payment_id") else res["tip_payment_id"]
    net = res.net_cents if hasattr(res, "net_cents") else res.get("net_cents", amt)
    track_charge_rows((tipper, recip), "tip_payment_id", tpid)
    track(T.billing, {"pk": user_pk(tipper), "sk": _reversal_sk(tpid)})
    track(T.billing, {"pk": user_pk(tipper), "sk": DD._mutex_sk("tip", tpid)})

    _, avail0, earned0 = http_available(recip)
    charge_id = f"ch_{RUN}_tip"
    disp_id = f"dp_{RUN}_tip"
    meta = {"charge_type": "tip", "charge_ref": tpid, "payer_id": tipper, "recipient_id": recip}

    # created -> HOLD
    c, j = post_webhook(stripe_event("charge.dispute.created", disp_id, charge_id,
                                     "needs_response", amt, metadata=meta, due_by=now_ts() + 5 * 86400))
    track_incident(disp_id, tipper)
    _, avail1, earned1 = http_available(recip)
    st_held = credit_state(recip, "tip_payment_id", tpid)
    rec("tip: dispute.created accepted + processed (HTTP 200)", c == 200 and j.get("processed", 0) >= 1,
        f"http={c} body={j}")
    rec("tip: funds HELD on open -> credit state=held", st_held == "held", f"state={st_held}")
    rec("tip: held credit drops out of earned balance (honest)", earned1 == earned0 - net,
        f"earned {earned0}->{earned1} net={net}")

    # funds_withdrawn -> maps opened, idempotent hold (no double-hold)
    c2, j2 = post_webhook(stripe_event("charge.dispute.funds_withdrawn", disp_id, charge_id,
                                       "needs_response", amt, metadata=meta))
    _, avail2, earned2 = http_available(recip)
    rec("tip: funds_withdrawn maps->opened, hold idempotent (earned unchanged)",
        c2 == 200 and earned2 == earned1, f"http={c2} earned={earned2}")

    # evidence assembler
    inc = incident_for(disp_id)
    ev = CB.build_dispute_evidence(inc, creator_rebuttal="content delivered as described")
    due = CB.response_due_at(inc)
    rec("tip: evidence assembled from charge meta + rebuttal + due_by deadline",
        ev.get("product_description") and ev.get("uncategorized_text").startswith("content delivered")
        and (due or 0) > now_ts(), f"ev_keys={sorted(ev)[:4]} due={due}")

    # closed LOST -> clawback (already held -> reversed) + chargeback_fee + NO buyer refund
    c3, j3 = post_webhook(stripe_event("charge.dispute.closed", disp_id, charge_id,
                                       "lost", amt, metadata=meta))
    track(T.billing, {"pk": user_pk(recip), "sk": DD._mutex_sk("tip", tpid)})
    _, avail3, earned3 = http_available(recip)
    st_rev = credit_state(recip, "tip_payment_id", tpid)
    clawback = has_ledger_type(recip, "reversal", meta_key="tip_payment_id", meta_val=tpid)
    fee = has_ledger_type(recip, "chargeback_fee")
    buyer_refund = has_ledger_type(tipper, "refund", meta_key="tip_payment_id", meta_val=tpid)
    rec("tip: LOST closed processed (HTTP 200)", c3 == 200, f"http={c3} body={j3}")
    rec("tip: LOST flips held credit -> reversed", st_rev == "reversed", f"state={st_rev}")
    rec("tip: LOST claws creator (type=reversal, net)", bool(clawback)
        and int((clawback or {}).get("amount_cents", 0)) == net,
        f"clawback={(clawback or {}).get('amount_cents')}")
    rec("tip: chargeback_fee ledger row recorded (creator_eats)", bool(fee)
        and int((fee or {}).get("amount_cents", 0)) == S.dispute_chargeback_fee_cents,
        f"fee={(fee or {}).get('amount_cents')}")
    rec("tip: NO buyer refund on chargeback (processor already refunded)", buyer_refund is None,
        f"buyer_refund_present={bool(buyer_refund)}")
    rec("tip: creator earned stays dropped after LOST (net clawed for good)",
        earned3 == earned0 - net, f"earned {earned0}->{earned3}")

    # idempotent redelivery of closed[lost]
    c4, j4 = post_webhook(stripe_event("charge.dispute.closed", disp_id, charge_id,
                                       "lost", amt, metadata=meta))
    _, avail4, earned4 = http_available(recip)
    fee_rows = [r for r in T.billing.query(KeyConditionExpression="pk = :p",
                ExpressionAttributeValues={":p": user_pk(recip)}).get("Items", [])
                if str(r.get("type")) == "chargeback_fee"]
    claw_rows = [r for r in T.billing.query(KeyConditionExpression="pk = :p",
                 ExpressionAttributeValues={":p": user_pk(recip)}).get("Items", [])
                 if str(r.get("type")) == "reversal" and (r.get("meta") or {}).get("tip_payment_id") == tpid]
    rec("tip: LOST redelivery idempotent (deduped, no 2nd clawback/fee)",
        earned4 == earned3 and len(fee_rows) == 1 and len(claw_rows) == 1,
        f"earned={earned4} fee_rows={len(fee_rows)} claw_rows={len(claw_rows)}")


# ═══════════════════════════════════════════════════════════════════════════
# 2) VOD chargeback -> WON: hold then release, no ledger move
# ═══════════════════════════════════════════════════════════════════════════
def test_vod_chargeback_won():
    from app.services.vod_purchase import purchase_video, _vod_reversal_sk
    buyer = f"disp_e3_vodbuyer_{RUN}"
    seller = f"disp_e3_vodseller_{RUN}"
    vid = f"vid_e3_{RUN}"
    price = 800
    res = purchase_video(buyer_id=buyer, video_id=vid, price_cents=price, seller_id=seller)
    pid = res["purchase_id"]
    track(T.vod_entitlements, {"pk": f"USER#{buyer}", "sk": f"VIDEO#{vid}"})
    track(T.video_metadata, {"video_id": vid})
    track_charge_rows((buyer, seller), "purchase_id", pid)
    track(T.billing, {"pk": user_pk(buyer), "sk": _vod_reversal_sk(pid)})
    track(T.billing, {"pk": user_pk(buyer), "sk": DD._mutex_sk("vod", pid)})

    charge_id = f"ch_{RUN}_vod"
    disp_id = f"dp_{RUN}_vod"
    meta = {"charge_type": "vod", "charge_ref": pid, "payer_id": buyer, "recipient_id": seller,
            "video_id": vid}

    st_pre = credit_state(seller, "purchase_id", pid)
    c, j = post_webhook(stripe_event("charge.dispute.created", disp_id, charge_id,
                                     "warning_needs_response", price, metadata=meta))
    track_incident(disp_id, buyer)
    st_held = credit_state(seller, "purchase_id", pid)
    rec("vod: dispute.created -> seller vod credit flips settled->HELD",
        c == 200 and st_pre == "settled" and st_held == "held",
        f"pre={st_pre} held={st_held}")

    # closed WON -> release hold, restore credit (to settled), NO ledger money move
    c2, j2 = post_webhook(stripe_event("charge.dispute.closed", disp_id, charge_id,
                                       "won", price, metadata=meta))
    st_restored = credit_state(seller, "purchase_id", pid)
    clawback = has_ledger_type(seller, "reversal", meta_key="purchase_id", meta_val=pid)
    fee = has_ledger_type(seller, "chargeback_fee")
    buyer_refund = has_ledger_type(buyer, "refund", meta_key="purchase_id", meta_val=pid)
    rec("vod: WON restores held credit -> state=settled (live again)",
        c2 == 200 and st_restored == "settled", f"http={c2} state={st_restored}")
    rec("vod: WON writes NO clawback / NO fee / NO buyer refund",
        clawback is None and fee is None and buyer_refund is None,
        f"claw={bool(clawback)} fee={bool(fee)} refund={bool(buyer_refund)}")

    # idempotent WON redelivery (state stays settled, no new rows)
    c3, _ = post_webhook(stripe_event("charge.dispute.closed", disp_id, charge_id,
                                      "won", price, metadata=meta))
    st_after = credit_state(seller, "purchase_id", pid)
    rec("vod: WON redelivery idempotent (state stays settled)", st_after == "settled",
        f"state={st_after}")


# ═══════════════════════════════════════════════════════════════════════════
# 2b) VOD chargeback -> LOST: clawback-only rail (vod credit reversed, no buyer refund)
# ═══════════════════════════════════════════════════════════════════════════
def test_vod_chargeback_lost():
    from app.services.vod_purchase import purchase_video, _vod_reversal_sk, check_entitlement
    buyer = f"disp_e3_vodlbuyer_{RUN}"
    seller = f"disp_e3_vodlseller_{RUN}"
    vid = f"vidl_e3_{RUN}"
    price = 800
    res = purchase_video(buyer_id=buyer, video_id=vid, price_cents=price, seller_id=seller)
    pid = res["purchase_id"]
    track(T.vod_entitlements, {"pk": f"USER#{buyer}", "sk": f"VIDEO#{vid}"})
    track(T.video_metadata, {"video_id": vid})
    track_charge_rows((buyer, seller), "purchase_id", pid)
    track(T.billing, {"pk": user_pk(buyer), "sk": _vod_reversal_sk(pid)})
    track(T.billing, {"pk": user_pk(buyer), "sk": DD._mutex_sk("vod", pid)})

    charge_id = f"ch_{RUN}_vodl"
    disp_id = f"dp_{RUN}_vodl"
    meta = {"charge_type": "vod", "charge_ref": pid, "payer_id": buyer, "recipient_id": seller,
            "video_id": vid}
    post_webhook(stripe_event("charge.dispute.created", disp_id, charge_id, "needs_response", price, metadata=meta))
    track_incident(disp_id, buyer)
    c2, j2 = post_webhook(stripe_event("charge.dispute.closed", disp_id, charge_id, "lost", price, metadata=meta))
    st_rev = credit_state(seller, "purchase_id", pid)
    clawback = has_ledger_type(seller, "reversal", meta_key="purchase_id", meta_val=pid)
    fee = has_ledger_type(seller, "chargeback_fee")
    buyer_refund = has_ledger_type(buyer, "refund", meta_key="purchase_id", meta_val=pid)
    ent = check_entitlement(buyer, vid) if callable(check_entitlement) else None
    has_access = bool(ent.get("entitled")) if isinstance(ent, dict) else None
    rec("vod: LOST claws seller (vod credit reversed) + fee, NO buyer refund",
        c2 == 200 and st_rev == "reversed" and bool(clawback) and bool(fee) and buyer_refund is None,
        f"http={c2} state={st_rev} claw={bool(clawback)} fee={bool(fee)} refund={bool(buyer_refund)}")
    rec("vod: LOST clawback-only revokes buyer entitlement (access lost)",
        has_access is False, f"has_access={has_access}")


# ═══════════════════════════════════════════════════════════════════════════
# 3) SUBSCRIPTION chargeback -> ACCEPTED (== lost): clawback + fee, no double refund
# ═══════════════════════════════════════════════════════════════════════════
def test_subscription_chargeback_accepted():
    from app.routers.subscription_server import _sub_reversal_sk
    creator = f"disp_e3_subcreator_{RUN}"
    subscriber = f"disp_e3_subscriber_{RUN}"
    sub_id = f"sub_e3_{RUN}"
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
    track(T.billing, {"pk": user_pk(subscriber), "sk": DD._mutex_sk("subscription", sub_id)})
    track(T.billing, {"pk": user_pk(subscriber), "sk": _sub_reversal_sk(f"{sub_id}#{period_end}")})

    _, _, earned0 = http_available(creator)
    charge_id = f"ch_{RUN}_sub"
    disp_id = f"dp_{RUN}_sub"
    meta = {"charge_type": "subscription", "charge_ref": sub_id, "payer_id": subscriber,
            "recipient_id": creator}

    c, j = post_webhook(stripe_event("charge.dispute.created", disp_id, charge_id,
                                     "needs_response", gross, metadata=meta))
    track_incident(disp_id, subscriber)
    _, _, earned1 = http_available(creator)
    st_held = credit_state(creator, "subscription_id", sub_id)
    rec("sub: dispute.created -> creator credit HELD, drops from earned",
        c == 200 and st_held == "held" and earned1 == earned0 - gross,
        f"state={st_held} earned {earned0}->{earned1}")

    # ACCEPTED == lost (stripe maps 'warning_closed'-in-closed to 'accepted')
    c2, j2 = post_webhook(stripe_event("charge.dispute.closed", disp_id, charge_id,
                                       "warning_closed", gross, metadata=meta, evt_id=f"evt_{RUN}_subacc"))
    _, _, earned2 = http_available(creator)
    st_rev = credit_state(creator, "subscription_id", sub_id)
    clawback = has_ledger_type(creator, "reversal", meta_key="subscription_id", meta_val=sub_id)
    fee = has_ledger_type(creator, "chargeback_fee")
    payer_refund = has_ledger_type(subscriber, "refund", meta_key="subscription_id", meta_val=sub_id)
    rec("sub: ACCEPTED(closed) claws creator + fee, held->reversed",
        st_rev == "reversed" and bool(clawback) and bool(fee),
        f"state={st_rev} claw={bool(clawback)} fee={bool(fee)}")
    rec("sub: ACCEPTED writes NO payer refund (processor already refunded)", payer_refund is None,
        f"payer_refund_present={bool(payer_refund)}")


# ═══════════════════════════════════════════════════════════════════════════
# 4) UNMAPPED external charge -> safe no-op (records audit, no crash, no ledger)
# ═══════════════════════════════════════════════════════════════════════════
def test_unmapped_charge_noop():
    charge_id = f"ch_{RUN}_ext"
    disp_id = f"dp_{RUN}_ext"
    c, j = post_webhook(stripe_event("charge.dispute.created", disp_id, charge_id,
                                     "needs_response", 999))  # no metadata
    track_incident(disp_id, "unknown")
    inc = incident_for(disp_id)
    hold_marker = T.billing.get_item(Key={"pk": user_pk("unknown"),
                                          "sk": f"CHARGEBACK_HOLD#{(inc or {}).get('incident_id')}"}).get("Item")
    rec("unmapped: external charge webhook still 200 + records a non-resolvable hold marker",
        c == 200 and bool(hold_marker) and hold_marker.get("resolvable") is False,
        f"http={c} marker={bool(hold_marker)} resolvable={(hold_marker or {}).get('resolvable')}")
    c2, j2 = post_webhook(stripe_event("charge.dispute.closed", disp_id, charge_id, "lost", 999))
    rec("unmapped: LOST on unmapped charge is a safe no-op (200, no crash)", c2 == 200, f"http={c2}")


# --- cleanup ---------------------------------------------------------------

def cleanup():
    ok = 0
    for table, key in _created_keys:
        try:
            if key and key.get("sk") is not None and all(v is not None for v in key.values()):
                table.delete_item(Key=key)
                ok += 1
        except Exception as e:
            print("cleanup miss", key, e)
    purged = 0
    for tbl in (T.billing,):
        try:
            for row in tbl.scan().get("Items", []):
                pk = str(row.get("pk", ""))
                if "disp_e3_" in pk or ("unknown" in pk and RUN in str(row.get("sk", ""))):
                    try:
                        tbl.delete_item(Key={"pk": row["pk"], "sk": row["sk"]})
                        purged += 1
                    except Exception:
                        pass
        except Exception as e:
            print("purge err", e)
    # incidents by run id
    inc_purged = 0
    try:
        for row in T.payment_incidents.scan().get("Items", []):
            if RUN in str(row.get("provider_incident_id", "")):
                try:
                    T.payment_incidents.delete_item(Key={"incident_id": row["incident_id"]})
                    inc_purged += 1
                except Exception:
                    pass
    except Exception as e:
        print("incident purge err", e)
    print(f"cleanup: removed {ok}/{len(_created_keys)} tracked + {purged} billing + {inc_purged} incidents")


def residue_check():
    leaked = []
    try:
        for row in T.billing.scan().get("Items", []):
            if "disp_e3_" in str(row.get("pk", "")):
                leaked.append(("billing", row.get("pk"), row.get("sk")))
    except Exception:
        pass
    try:
        for row in T.payment_incidents.scan().get("Items", []):
            if RUN in str(row.get("provider_incident_id", "")):
                leaked.append(("payment_incidents", row.get("incident_id")))
    except Exception:
        pass
    rec("cleanup: 0 residual rows across billing/payment_incidents for this run",
        not leaked, f"leaked={leaked[:8]}")


if __name__ == "__main__":
    rec("config: local stripe webhook secret present (real signature verify path)",
        bool(WHSEC), f"whsec_set={bool(WHSEC)}")
    try:
        for fn in (test_tip_chargeback_lost, test_vod_chargeback_won, test_vod_chargeback_lost,
                   test_subscription_chargeback_accepted, test_unmapped_charge_noop):
            try:
                fn()
            except Exception as e:
                import traceback
                rec(fn.__name__, False, f"EXCEPTION {type(e).__name__}: {e}")
                traceback.print_exc()
    finally:
        cleanup()
        residue_check()
    npass = sum(1 for _, ok, _ in results if ok)
    print(f"\n==== E3 RESULT: {npass}/{len(results)} PASS ====")
    for n, ok, d in results:
        if not ok:
            print("  FAIL:", n, "-", d)
