"""DISP E4 LIVE verification harness (fraud/abuse + cross-track link/dedupe).

Runs against the SAME live DDB the running uvicorn (:8000) uses. Drives:
  * USER track over REAL HTTP: POST /ui/billing/disputes (file) +
    POST /ui/admin/disputes/{id}/resolve (admin, refunded).
  * PROCESSOR track over REAL HTTP: signed mock Stripe webhook to
    /api/billing/webhooks/stripe (HMAC-signed with the local whsec).

Proves (all against live HTTP + live-DDB reads):
  DISP-042  no-double-debit BOTH orderings on the SAME charge:
            (A) user-refund FIRST then processor LOST  -> LOST is a mutex no-op
            (B) processor chargeback FIRST then user    -> user dispute auto-mooted
                + linked; user resolve blocked (terminal); one debit only.
  DISP-041  serial disputer flagged + auto-refund fast-path suppressed;
            over-cap dispute -> HTTP 429.
  DISP-040  fraud chargeback_count increments on LOST + on user_refund;
            idempotent on webhook redelivery (no double count).

Auto-cleans all synthetic rows (0 residue).
Run: set -a; . .env.local; set +a; .venv/bin/python ~/disp_work/verify_e4.py
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
from app.services.billing_shared import user_pk
from app.services import dispute_dispatch as DD
from app.services import dispute_chargeback as CB
from app.services import dispute_fraud as DF

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


def _cookie(sub, role="user"):
    import jwt
    tok = jwt.encode({"sub": sub, "sid": f"disp4-{RUN}", "role": role,
                      "exp": int(time.time()) + 3600}, SEC, algorithm="HS256")
    return f"{COOKIE}={tok}"


def http_post(path, sub, body, role="user"):
    args = ["curl", "-s", "-X", "POST", BASE + path,
            "-H", "Content-Type: application/json",
            "-H", "Cookie: " + _cookie(sub, role),
            "--data-binary", "@-", "-w", "\n%{http_code}"]
    r = subprocess.run(args, input=json.dumps(body), capture_output=True, text=True)
    txt, _, code = r.stdout.rpartition("\n")
    try:
        return int(code or 0), (json.loads(txt) if txt.strip() else {})
    except Exception:
        return int(code or 0), {"_raw": txt}


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


def stripe_event(event_type, dispute_id, charge_id, status, amount_cents, *, metadata=None,
                 currency="usd", due_by=None, evt_id=None):
    obj = {"id": dispute_id, "object": "dispute", "charge": charge_id,
           "amount": amount_cents, "currency": currency, "status": status,
           "metadata": metadata or {}}
    if due_by is not None:
        obj["evidence_details"] = {"due_by": due_by}
    return {"id": evt_id or f"evt_{uuid.uuid4().hex[:16]}", "type": event_type,
            "data": {"object": obj}}


def seed_tip(tipper, recip, amt, tag):
    from app.services.tips import charge_tip, _reversal_sk
    res = charge_tip(tipper_id=tipper, recipient_id=recip, amount_cents=amt,
                     content_type="post", content_id=f"c_{tag}",
                     idempotency_key=f"e4tip_{tag}", payment_method_id=None)
    tpid = res.tip_payment_id if hasattr(res, "tip_payment_id") else res["tip_payment_id"]
    net = res.net_cents if hasattr(res, "net_cents") else res.get("net_cents", amt)
    for uid in (tipper, recip):
        for row in T.billing.query(KeyConditionExpression="pk = :p",
                                   ExpressionAttributeValues={":p": user_pk(uid)}).get("Items", []):
            if (row.get("meta") or {}).get("tip_payment_id") == tpid:
                track(T.billing, {"pk": row["pk"], "sk": row["sk"]})
    track(T.billing, {"pk": user_pk(tipper), "sk": _reversal_sk(tpid)})
    track(T.billing, {"pk": user_pk(tipper), "sk": DD._mutex_sk("tip", tpid)})
    track(T.billing, {"pk": user_pk(recip), "sk": DD._mutex_sk("tip", tpid)})
    track(T.billing, {"pk": user_pk(tipper), "sk": f"DISPUTE_LINK#tip#{tpid}"})
    track(T.billing, {"pk": user_pk(tipper), "sk": DF._fraud_marker_sk("chargeback", f"cb:dp_{tag}")})
    track(T.billing, {"pk": user_pk(tipper), "sk": DF._fraud_marker_sk("user_refund", f"userref:tip:{tpid}")})
    return tpid, net


def credit_state(user_id, tpid):
    for row in T.billing.query(KeyConditionExpression="pk = :p",
                               ExpressionAttributeValues={":p": user_pk(user_id)}).get("Items", []):
        m = row.get("meta") or {}
        if m.get("tip_payment_id") == tpid and str(row.get("type", "")) == "credit":
            return row.get("state", "")
    return None


def count_ledger_type(user_id, typ, tpid=None):
    n = 0
    for row in T.billing.query(KeyConditionExpression="pk = :p",
                               ExpressionAttributeValues={":p": user_pk(user_id)}).get("Items", []):
        if str(row.get("type", "")) != typ:
            continue
        if tpid is not None and (row.get("meta") or {}).get("tip_payment_id") != tpid:
            continue
        n += 1
    return n


def cb_count(user_id):
    row = T.fraud_cases.get_item(Key={"pk": f"RISK#USER#{user_id}", "sk": "SCORE"}).get("Item") or {}
    return int(row.get("chargeback_count", 0) or 0)


def track_incident(dispute_id, payer):
    from app.services.payment_incidents_store import DynamoPaymentIncidentRepository
    repo = DynamoPaymentIncidentRepository()
    got = repo.list_incidents_by_case(provider="stripe", case_id=dispute_id, limit=1)
    if got:
        iid = got[0]["incident_id"]
        track(T.payment_incidents, {"incident_id": iid})
        for sk in (f"CHARGEBACK_HOLD#{iid}", f"CHARGEBACK_LOST#{iid}", f"CHARGEBACK_RELEASE#{iid}"):
            track(T.billing, {"pk": user_pk(payer), "sk": sk})
    return got[0] if got else None


def get_dispute(did):
    return T.billing_disputes.get_item(Key={"pk": f"DISPUTE#{did}", "sk": "META"}).get("Item")


# ═══════════════════════════════════════════════════════════════════════════
# DISP-042 (A) USER refund FIRST, then processor LOST -> LOST is a mutex no-op
# ═══════════════════════════════════════════════════════════════════════════
def test_order_A_user_then_processor():
    tipper = f"disp_e4_A_payer_{RUN}"
    recip = f"disp_e4_A_creator_{RUN}"
    amt = 800
    tpid, net = seed_tip(tipper, recip, amt, f"A_{RUN}")

    _, _, earned0 = http_available(recip)
    cb0 = cb_count(tipper)

    # 1) file a USER dispute over HTTP (quality reason applies to tips)
    c, j = http_post("/ui/billing/disputes", tipper, {
        "amount_cents": amt, "reason": "quality", "charge_type": "tip",
        "charge_ref": tpid, "recipient_id": recip})
    did = j.get("dispute_id")
    if did:
        track(T.billing_disputes, {"pk": f"DISPUTE#{did}", "sk": "META"})
    rec("A: user dispute filed over HTTP", c == 201 and bool(did), f"http={c} id={did}")

    # 2) admin resolves REFUNDED over HTTP -> real rail fires, claims mutex
    c2, j2 = http_post(f"/ui/admin/disputes/{did}/resolve", "admin_e4", {
        "resolution": "refunded"}, role="admin")
    _, _, earned1 = http_available(recip)
    st1 = credit_state(recip, tpid)
    reversals1 = count_ledger_type(recip, "reversal", tpid)
    rec("A: user refund resolved over HTTP (200)", c2 == 200, f"http={c2} body={j2}")
    rec("A: user refund flips credit -> reversed + drops earned", st1 == "reversed" and earned1 == earned0 - net,
        f"state={st1} earned {earned0}->{earned1} net={net}")
    rec("A: exactly ONE clawback reversal after user refund", reversals1 == 1, f"reversals={reversals1}")
    cb1 = cb_count(tipper)
    rec("A/DISP-040: user_refund incremented fraud chargeback_count (+1)", cb1 == cb0 + 1, f"cb {cb0}->{cb1}")

    # 3) NOW a processor chargeback LANDS on the SAME tip -> LOST must be a no-op
    disp_id = f"dp_{RUN}_A"
    charge_id = f"ch_{RUN}_A"
    meta = {"charge_type": "tip", "charge_ref": tpid, "payer_id": tipper, "recipient_id": recip}
    post_webhook(stripe_event("charge.dispute.created", disp_id, charge_id, "needs_response",
                              amt, metadata=meta, due_by=now_ts() + 5 * 86400))
    inc = track_incident(disp_id, tipper)
    c4, j4 = post_webhook(stripe_event("charge.dispute.closed", disp_id, charge_id, "lost",
                                       amt, metadata=meta))
    _, _, earned2 = http_available(recip)
    st2 = credit_state(recip, tpid)
    reversals2 = count_ledger_type(recip, "reversal", tpid)
    rec("A: processor LOST after user refund processed (200)", c4 == 200, f"http={c4}")
    rec("A/NO-DOUBLE-DEBIT: still exactly ONE clawback reversal (LOST was a mutex no-op)",
        reversals2 == 1, f"reversals after LOST={reversals2}")
    rec("A/NO-DOUBLE-DEBIT: earned did NOT drop a second time",
        earned2 == earned0 - net, f"earned {earned0}->{earned2}")
    rec("A: credit stays reversed (not double-flipped)", st2 == "reversed", f"state={st2}")


# ═══════════════════════════════════════════════════════════════════════════
# DISP-042 (B) processor chargeback FIRST -> user dispute auto-mooted + linked
# ═══════════════════════════════════════════════════════════════════════════
def test_order_B_processor_then_user():
    tipper = f"disp_e4_B_payer_{RUN}"
    recip = f"disp_e4_B_creator_{RUN}"
    amt = 900
    tpid, net = seed_tip(tipper, recip, amt, f"B_{RUN}")

    _, _, earned0 = http_available(recip)
    cb0 = cb_count(tipper)

    # 1) file a USER dispute over HTTP (kept OPEN, not resolved)
    c, j = http_post("/ui/billing/disputes", tipper, {
        "amount_cents": amt, "reason": "quality", "charge_type": "tip",
        "charge_ref": tpid, "recipient_id": recip})
    did = j.get("dispute_id")
    if did:
        track(T.billing_disputes, {"pk": f"DISPUTE#{did}", "sk": "META"})
    rec("B: user dispute filed + OPEN over HTTP", c == 201 and bool(did), f"http={c} id={did}")

    # 2) processor chargeback CREATED lands -> DISP-042 auto-moot + link
    disp_id = f"dp_{RUN}_B"
    charge_id = f"ch_{RUN}_B"
    meta = {"charge_type": "tip", "charge_ref": tpid, "payer_id": tipper, "recipient_id": recip}
    cW, jW = post_webhook(stripe_event("charge.dispute.created", disp_id, charge_id, "needs_response",
                                       amt, metadata=meta, due_by=now_ts() + 5 * 86400))
    inc = track_incident(disp_id, tipper)
    d_after = get_dispute(did) or {}
    rec("B: dispute.created processed over HTTP (200)", cW == 200, f"http={cW}")
    rec("B/DISP-042: open user dispute AUTO-MOOTED (-> withdrawn)",
        str(d_after.get("status")) == "withdrawn" and bool(d_after.get("mooted_by_chargeback")),
        f"status={d_after.get('status')} mooted={d_after.get('mooted_by_chargeback')}")
    rec("B/DISP-042: user dispute cross-linked to the incident",
        str(d_after.get("linked_dispute_id") or "").endswith(inc["incident_id"]) if inc else False,
        f"linked={d_after.get('linked_dispute_id')}")
    link_marker = T.billing.get_item(Key={"pk": user_pk(tipper), "sk": f"DISPUTE_LINK#tip#{tpid}"}).get("Item")
    rec("B/DISP-042: DISPUTE_LINK marker written both-ways (incident<->user disputes)",
        bool(link_marker) and did in (link_marker.get("linked_user_disputes") or []),
        f"marker={bool(link_marker)}")

    # 3) trying to resolve the (now withdrawn) user dispute must be a terminal no-op
    cR, jR = http_post(f"/ui/admin/disputes/{did}/resolve", "admin_e4", {"resolution": "refunded"}, role="admin")
    rec("B: resolving the mooted user dispute is blocked (terminal 409, no money move)",
        cR == 409, f"http={cR} body={jR}")

    # 4) processor closes LOST -> ONE clawback via the processor track only
    cL, jL = post_webhook(stripe_event("charge.dispute.closed", disp_id, charge_id, "lost", amt, metadata=meta))
    track(T.billing, {"pk": user_pk(recip), "sk": DD._mutex_sk("tip", tpid)})
    _, _, earned1 = http_available(recip)
    reversals = count_ledger_type(recip, "reversal", tpid)
    st = credit_state(recip, tpid)
    rec("B: processor LOST processed (200)", cL == 200, f"http={cL}")
    rec("B/NO-DOUBLE-DEBIT: exactly ONE clawback (processor track only)", reversals == 1, f"reversals={reversals}")
    rec("B/NO-DOUBLE-DEBIT: earned dropped exactly once", earned1 == earned0 - net,
        f"earned {earned0}->{earned1} net={net}")
    rec("B: credit reversed (held->reversed by LOST)", st == "reversed", f"state={st}")
    cb1 = cb_count(tipper)
    rec("B/DISP-040: chargeback LOST incremented fraud count (+1)", cb1 == cb0 + 1, f"cb {cb0}->{cb1}")

    # 5) idempotent redelivery of LOST -> NO extra debit, NO extra fraud count
    post_webhook(stripe_event("charge.dispute.closed", disp_id, charge_id, "lost", amt, metadata=meta))
    reversals2 = count_ledger_type(recip, "reversal", tpid)
    cb2 = cb_count(tipper)
    rec("B/DISP-040: redelivered LOST does NOT double-count fraud (idempotent)", cb2 == cb1, f"cb={cb2}")
    rec("B: redelivered LOST does NOT add a second reversal", reversals2 == 1, f"reversals={reversals2}")


# ═══════════════════════════════════════════════════════════════════════════
# DISP-041 serial disputer: flagged + fast-path suppressed + over-cap 429
# ═══════════════════════════════════════════════════════════════════════════
def test_serial_disputer():
    payer = f"disp_e4_serial_{RUN}"
    recip = f"disp_e4_serialcreator_{RUN}"
    thr = S.dispute_serial_disputer_threshold
    cap = S.dispute_max_disputes_per_month
    # We use reason="unauthorized" which ALWAYS auto-skips the response window
    # (_skip_window) -> under_review, for a NON-serial payer. Once the payer is
    # serial (>= threshold disputes in 30d), DISP-041 forces force_manual_review
    # so even an "unauthorized" dispute lands in needs_response (no fast-path).
    statuses = []
    for i in range(thr + 1):
        tpid, _ = seed_tip(payer, recip, 500, f"serial{i}_{RUN}")
        c, j = http_post("/ui/billing/disputes", payer, {
            "amount_cents": 500, "reason": "unauthorized", "charge_type": "tip",
            "charge_ref": tpid, "recipient_id": recip})
        did = j.get("dispute_id")
        if did:
            track(T.billing_disputes, {"pk": f"DISPUTE#{did}", "sk": "META"})
            statuses.append((did, str(j.get("status") or "")))

    # The FIRST dispute (payer not yet serial) auto-skips -> under_review.
    first_did, first_status = statuses[0]
    rec("DISP-041: pre-serial 'unauthorized' dispute auto-skips window -> under_review",
        first_status == "under_review", f"status={first_status}")
    # The dispute filed once the payer is serial (index == thr, 0-based) is forced
    # to needs_response instead of the fast-path.
    serial_did, serial_status = statuses[thr] if len(statuses) > thr else (None, "")
    d = get_dispute(serial_did) if serial_did else None
    rec("DISP-041: serial disputer's dispute flagged serial_disputer=True",
        bool(d) and bool(d.get("serial_disputer")), f"serial_flag={(d or {}).get('serial_disputer')}")
    rec("DISP-041: serial disputer fast-path SUPPRESSED (needs_response, not auto-skipped)",
        serial_status == "needs_response", f"status={serial_status}")
    stats = DF.dispute_stats(payer)
    rec("DISP-041: dispute_stats classifies payer as serial", stats.get("serial_disputer") is True,
        f"disputes_30d={stats.get('disputes_30d')} thr={stats.get('serial_threshold')}")

    # Push OVER the monthly cap -> HTTP 429.
    over = None
    for i in range(cap + 2):
        tpid, _ = seed_tip(payer, recip, 500, f"cap{i}_{RUN}")
        c, j = http_post("/ui/billing/disputes", payer, {
            "amount_cents": 500, "reason": "unauthorized", "charge_type": "tip",
            "charge_ref": tpid, "recipient_id": recip})
        did = j.get("dispute_id")
        if did:
            track(T.billing_disputes, {"pk": f"DISPUTE#{did}", "sk": "META"})
        if c == 429:
            over = (c, j)
            break
    rec("DISP-041: over-cap dispute rejected with HTTP 429 (rate-limited)",
        bool(over) and over[0] == 429, f"resp={over[1] if over else None}")


# ═══════════════════════════════════════════════════════════════════════════
# DISP-040 fraud counter increments + idempotent (direct signal, standalone)
# ═══════════════════════════════════════════════════════════════════════════
def test_fraud_signal_idempotent():
    payer = f"disp_e4_fraud_{RUN}"
    track(T.billing, {"pk": user_pk(payer), "sk": DF._fraud_marker_sk("chargeback", "cbref1")})
    cb0 = cb_count(payer)
    r1 = DF.record_dispute_fraud_signal(payer_id=payer, amount_cents=500, tx_id="t1",
                                        kind="chargeback", signal_ref="cbref1", actor="test")
    cb1 = cb_count(payer)
    r2 = DF.record_dispute_fraud_signal(payer_id=payer, amount_cents=500, tx_id="t1",
                                        kind="chargeback", signal_ref="cbref1", actor="test")
    cb2 = cb_count(payer)
    rec("DISP-040: first signal increments chargeback_count", r1.get("recorded") and cb1 == cb0 + 1,
        f"cb {cb0}->{cb1}")
    rec("DISP-040: duplicate signal is an idempotent no-op (no double count)",
        r2.get("idempotent_replay") is True and cb2 == cb1, f"cb2={cb2} r2={r2.get('idempotent_replay')}")


# ═══════════════════════════════════════════════════════════════════════════
def cleanup():
    ok = 0
    for table, key in _created_keys:
        try:
            table.delete_item(Key=key)
            ok += 1
        except Exception:
            pass
    # purge fraud SCORE rows + any stray disp_e4 billing rows + incidents
    purged = 0
    for uid_tag in ("A_payer", "B_payer", "serial", "fraud", "A_creator", "B_creator", "serialcreator"):
        pass
    try:
        for row in T.billing.scan().get("Items", []):
            if "disp_e4_" in str(row.get("pk", "")):
                try:
                    T.billing.delete_item(Key={"pk": row["pk"], "sk": row["sk"]}); purged += 1
                except Exception:
                    pass
    except Exception:
        pass
    fr = 0
    try:
        for row in T.fraud_cases.scan().get("Items", []):
            if "disp_e4_" in str(row.get("pk", "")):
                try:
                    T.fraud_cases.delete_item(Key={"pk": row["pk"], "sk": row["sk"]}); fr += 1
                except Exception:
                    pass
    except Exception:
        pass
    inc = 0
    try:
        for row in T.payment_incidents.scan().get("Items", []):
            if RUN in str(row.get("provider_incident_id", "")):
                try:
                    T.payment_incidents.delete_item(Key={"incident_id": row["incident_id"]}); inc += 1
                except Exception:
                    pass
    except Exception:
        pass
    try:
        for row in T.billing_disputes.scan().get("Items", []):
            if f"_{RUN}" in str(row.get("dispute_id", "")) or (row.get("user_id") or "").startswith("disp_e4_"):
                try:
                    T.billing_disputes.delete_item(Key={"pk": row["pk"], "sk": row["sk"]})
                except Exception:
                    pass
    except Exception:
        pass
    print(f"cleanup: {ok}/{len(_created_keys)} tracked + {purged} billing + {fr} fraud + {inc} incidents")


def residue_check():
    leaked = []
    for tbl, tag in ((T.billing, "billing"), (T.fraud_cases, "fraud")):
        try:
            for row in tbl.scan().get("Items", []):
                if "disp_e4_" in str(row.get("pk", "")):
                    leaked.append((tag, row.get("pk"), row.get("sk")))
        except Exception:
            pass
    try:
        for row in T.payment_incidents.scan().get("Items", []):
            if RUN in str(row.get("provider_incident_id", "")):
                leaked.append(("payment_incidents", row.get("incident_id")))
    except Exception:
        pass
    rec("cleanup: 0 residual rows for this run", not leaked, f"leaked={leaked[:8]}")


if __name__ == "__main__":
    rec("config: local stripe webhook secret present (real signature verify)", bool(WHSEC), f"whsec={bool(WHSEC)}")
    try:
        for fn in (test_order_A_user_then_processor, test_order_B_processor_then_user,
                   test_serial_disputer, test_fraud_signal_idempotent):
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
    print(f"\n==== E4 RESULT: {npass}/{len(results)} PASS ====")
    for n, ok, d in results:
        if not ok:
            print("  FAIL:", n, "-", d)
