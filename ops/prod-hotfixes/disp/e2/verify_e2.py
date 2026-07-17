"""DISP E2 LIVE verification harness (app+web SURFACES: creator respond + admin queue).

Drives the NEW E2 endpoints over REAL HTTP against the running uvicorn (:8000):

  DISP-021  GET  /ui/creator/disputes          (inbound queue)
            GET  /ui/creator/disputes/{id}
            POST /ui/creator/disputes/{id}/respond   (rebut in-window)
  DISP-022  GET  /ui/admin/disputes             (queue + rail_preview + linked_incident)
            GET  /ui/admin/disputes/{id}         (full admin view)
            POST /ui/admin/disputes/{id}/resolve (dual-approval > threshold)
            + AdminScope.PAYMENT_DISPUTES gate

  Full path: buyer opens (not_as_described -> needs_response) -> creator responds
             (-> under_review) -> admin resolves refunded -> buyer sees resolved+refunded.

Auto-cleans all synthetic rows (0 residue). Run:
  set -a; . .env.local; set +a; .venv/bin/python ~/disp_work/verify_e2.py
"""
from __future__ import annotations
import json, time, uuid, subprocess

import jwt
from app.core.settings import S
from app.core.tables import T
from app.services.billing_shared import user_pk

BASE = "http://localhost:8000"
COOKIE = S.ui_access_token_cookie_name
SEC = S.ui_access_token_secret
RUN = uuid.uuid4().hex[:8]
PFX = f"disp_e2_"
ADMIN = f"disp_admin_{RUN}"           # GENERAL admin (has PAYMENT_DISPUTES via GENERAL)
ADMIN2 = f"disp_admin2_{RUN}"         # second GENERAL admin (valid dual approver)
SCOPED_NOSCOPE = f"disp_admin_ns_{RUN}"  # SCOPED admin lacking payment_disputes

results = []
_created_keys = []


def rec(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, "-", detail)


def track(table, key):
    _created_keys.append((table, key))


def cookie_for(sub, role="user", admin_profile=None):
    claims = {"sub": sub, "sid": f"disp-{RUN}", "role": role,
              "exp": int(time.time()) + 3600}
    if admin_profile is not None:
        claims["admin_profile"] = admin_profile
    tok = jwt.encode(claims, SEC, algorithm="HS256")
    return f"{COOKIE}={tok}"


def _curl(method, path, sub, role="user", body=None, admin_profile=None):
    args = ["curl", "-s", "-X", method, BASE + path,
            "-H", "Cookie: " + cookie_for(sub, role, admin_profile), "-w", "\n%{http_code}"]
    if body is not None:
        args += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    r = subprocess.run(args, capture_output=True, text=True)
    txt, _, code = r.stdout.rpartition("\n")
    try:
        return int(code or 0), (json.loads(txt) if txt.strip() else {})
    except Exception:
        return int(code or 0), {"_raw": txt}


def http_get(path, sub, role="user", admin_profile=None):
    return _curl("GET", path, sub, role, admin_profile=admin_profile)


def http_post(path, sub, body=None, role="user", admin_profile=None):
    return _curl("POST", path, sub, role, body, admin_profile=admin_profile)


def http_balance(sub):
    code, j = http_get("/ui/payouts/balance", sub)
    return code, int((j or {}).get("total_earned_cents", -1))


def seed_admins():
    T.users.put_item(Item={"user_sub": ADMIN, "role": "admin", "email": f"{ADMIN}@t.co"})
    track(T.users, {"user_sub": ADMIN})
    T.users.put_item(Item={"user_sub": ADMIN2, "role": "admin", "email": f"{ADMIN2}@t.co"})
    track(T.users, {"user_sub": ADMIN2})
    # a SCOPED admin whose only scope is content_moderation -> must be denied the
    # payment-disputes queue.
    T.users.put_item(Item={"user_sub": SCOPED_NOSCOPE, "role": "admin",
                           "email": f"{SCOPED_NOSCOPE}@t.co",
                           "admin_profile": {"type": "scoped", "scopes": ["content_moderation"]}})
    track(T.users, {"user_sub": SCOPED_NOSCOPE})


def track_dispute(did):
    if did:
        track(T.billing_disputes, {"pk": f"DISPUTE#{did}", "sk": "META"})


def track_charge_rows(uids, meta_key, meta_val):
    for uid in uids:
        for row in T.billing.query(KeyConditionExpression="pk = :p",
                                   ExpressionAttributeValues={":p": user_pk(uid)}).get("Items", []):
            if (row.get("meta") or {}).get(meta_key) == meta_val:
                track(T.billing, {"pk": row["pk"], "sk": row["sk"]})


def seed_tip(tipper, recip, amt):
    from app.services.tips import charge_tip
    from app.services import dispute_dispatch as DD
    res = charge_tip(tipper_id=tipper, recipient_id=recip, amount_cents=amt,
                     content_type="post", content_id=f"c_{RUN}_{uuid.uuid4().hex[:4]}",
                     idempotency_key=f"e2tip_{uuid.uuid4().hex[:8]}", payment_method_id=None)
    tpid = res.tip_payment_id if hasattr(res, "tip_payment_id") else res["tip_payment_id"]
    net = res.net_cents if hasattr(res, "net_cents") else res.get("net_cents", amt)
    track_charge_rows((tipper, recip), "tip_payment_id", tpid)
    track(T.billing, {"pk": user_pk(tipper), "sk": DD._mutex_sk("tip", tpid)})
    return tpid, net


# ═══════════════════════════════════════════════════════════════════════════
# DISP-021 — creator inbound queue + respond
# ═══════════════════════════════════════════════════════════════════════════
def test_creator_respond_flow():
    tipper = f"{PFX}buyer_{RUN}"
    creator = f"{PFX}creator_{RUN}"
    other = f"{PFX}other_{RUN}"
    tpid, net = seed_tip(tipper, creator, 800)

    # open dispute w/ 'quality' (valid for a tip; NOT unauthorized) -> opens a
    # creator RESPONSE window (needs_response). unauthorized would auto-skip.
    code, j = http_post("/ui/billing/disputes", tipper, {
        "amount_cents": 800, "reason": "quality",
        "charge_type": "tip", "charge_ref": tpid, "recipient_id": creator,
        "reason_detail": "content was not what was promised"})
    did = j.get("dispute_id")
    track_dispute(did)
    rec("DISP-021 open (quality) -> needs_response window (HTTP 201)",
        code == 201 and j.get("status") == "needs_response" and (j.get("respond_by") or 0) > 0,
        f"http={code} status={j.get('status')} respond_by={j.get('respond_by')}")

    # creator inbound queue lists it
    codeQ, jQ = http_get("/ui/creator/disputes", creator)
    ids = [d.get("dispute_id") for d in (jQ.get("items") or [])]
    rec("DISP-021 creator inbound queue lists the dispute (HTTP 200)",
        codeQ == 200 and did in ids, f"http={codeQ} ids={ids}")

    # a DIFFERENT user's queue does NOT show it
    codeO, jO = http_get("/ui/creator/disputes", other)
    oids = [d.get("dispute_id") for d in (jO.get("items") or [])]
    rec("DISP-021 non-counterparty queue excludes the dispute",
        codeO == 200 and did not in oids, f"http={codeO} ids={oids}")

    # creator detail visible to the creator, 404 to a stranger
    codeD, jD = http_get(f"/ui/creator/disputes/{did}", creator)
    codeX, _ = http_get(f"/ui/creator/disputes/{did}", other)
    rec("DISP-021 creator detail: counterparty 200, stranger 404",
        codeD == 200 and jD.get("dispute_id") == did and codeX == 404,
        f"creator={codeD} stranger={codeX}")

    # non-counterparty CANNOT respond (404, no enumeration)
    codeNR, _ = http_post(f"/ui/creator/disputes/{did}/respond", other,
                          {"response_text": "not mine"})
    rec("DISP-021 non-counterparty respond -> 404",
        codeNR == 404, f"http={codeNR}")

    # creator responds in-window -> advances to under_review + rebuttal recorded
    codeR, jR = http_post(f"/ui/creator/disputes/{did}/respond", creator,
                          {"response_text": "Here is my delivery proof and receipt."})
    rec("DISP-021 creator respond in-window -> under_review + rebuttal recorded (HTTP 200)",
        codeR == 200 and jR.get("status") == "under_review"
        and "delivery proof" in str(jR.get("creator_response") or ""),
        f"http={codeR} status={jR.get('status')} resp={str(jR.get('creator_response'))[:40]!r}")

    return did, creator, tipper


# ═══════════════════════════════════════════════════════════════════════════
# DISP-022 — admin queue: scope gate + rail preview + admin detail + full path
# ═══════════════════════════════════════════════════════════════════════════
def test_admin_queue_and_scope(did, creator, tipper):
    # scope gate: a SCOPED admin lacking payment_disputes is denied. admin_profile
    # is read from the JWT claims (deps._extract_admin_profile_from_claims), so we
    # mint a scoped profile carrying only content_moderation.
    scoped_profile = {"type": "scoped", "scopes": ["content_moderation"]}
    codeNS, _ = http_get("/ui/admin/disputes?status=under_review", SCOPED_NOSCOPE,
                         role="admin", admin_profile=scoped_profile)
    rec("DISP-022 scoped admin WITHOUT payment_disputes -> 403",
        codeNS == 403, f"http={codeNS}")

    # and a SCOPED admin that DOES hold payment_disputes passes
    pd_profile = {"type": "scoped", "scopes": ["payment_disputes"]}
    codePD, _ = http_get("/ui/admin/disputes?status=under_review", ADMIN,
                         role="admin", admin_profile=pd_profile)
    rec("DISP-022 scoped admin WITH payment_disputes -> 200",
        codePD == 200, f"http={codePD}")

    # general admin sees the queue w/ rail preview
    codeQ, jQ = http_get("/ui/admin/disputes?status=under_review", ADMIN, role="admin")
    row = next((d for d in (jQ.get("items") or []) if d.get("dispute_id") == did), None)
    rp = (row or {}).get("rail_preview") or {}
    rec("DISP-022 admin queue includes rail_preview (rail=tip, available)",
        codeQ == 200 and row is not None and rp.get("charge_type") == "tip"
        and rp.get("rail_available") is True and "reverse_tip" in str(rp.get("rail")),
        f"http={codeQ} rail={rp.get('rail')} avail={rp.get('rail_available')} clawback={rp.get('clawback_cents')}")

    # admin detail: rail preview + creator rebuttal thread + linked_incident key present
    codeD, jD = http_get(f"/ui/admin/disputes/{did}", ADMIN, role="admin")
    resp_thread = jD.get("responses") or []
    rec("DISP-022 admin detail: rail_preview + creator rebuttal thread present",
        codeD == 200 and (jD.get("rail_preview") or {}).get("charge_type") == "tip"
        and any("delivery proof" in str(r.get("text", "")) for r in resp_thread)
        and "linked_incident" in jD,
        f"http={codeD} responses={len(resp_thread)} linked_incident={jD.get('linked_incident')}")


def test_full_happy_path(did, creator, tipper):
    code0, earned0 = http_balance(creator)
    # admin resolves refunded (tip=800 < 5000 threshold -> no dual-approval needed)
    codeR, jR = http_post(f"/ui/admin/disputes/{did}/resolve", ADMIN,
                          {"resolution": "refunded", "notes": "buyer rebuttal accepted"}, role="admin")
    rec("DISP-022 admin resolve refunded moves money (HTTP 200, resolved)",
        codeR == 200 and jR.get("status") == "resolved" and int(jR.get("moved_cents", 0)) > 0,
        f"http={codeR} status={jR.get('status')} moved={jR.get('moved_cents')}")

    code1, earned1 = http_balance(creator)
    rec("DISP-022 creator earnings dropped after refund (live balance)",
        earned1 < earned0, f"earned {earned0} -> {earned1}")

    # buyer sees resolved + refunded via their own detail endpoint
    codeB, jB = http_get(f"/ui/billing/disputes/{did}", tipper)
    rec("DISP-023/full: buyer sees resolved + refunded (HTTP 200)",
        codeB == 200 and jB.get("status") == "resolved" and jB.get("resolution") == "refunded"
        and int(jB.get("moved_cents") or 0) > 0,
        f"http={codeB} status={jB.get('status')} resolution={jB.get('resolution')} moved={jB.get('moved_cents')}")


# ═══════════════════════════════════════════════════════════════════════════
# DISP-022 — dual-approval on a HIGH-VALUE refund (>= threshold)
# ═══════════════════════════════════════════════════════════════════════════
def test_dual_approval():
    thr = int(getattr(S, "dispute_dual_approval_threshold_cents", 5000) or 5000)
    amt = thr + 2500                      # above the dual-approval threshold
    tipper = f"{PFX}hvbuyer_{RUN}"
    creator = f"{PFX}hvcreator_{RUN}"
    tpid, net = seed_tip(tipper, creator, amt)

    # open (unauthorized -> straight to under_review; skips creator window)
    code, j = http_post("/ui/billing/disputes", tipper, {
        "amount_cents": amt, "reason": "unauthorized",
        "charge_type": "tip", "charge_ref": tpid, "recipient_id": creator,
        "reason_detail": "did not authorize"})
    did = j.get("dispute_id")
    track_dispute(did)
    rec("DISP-022 high-value dispute opened (under_review)",
        code == 201 and j.get("status") == "under_review", f"http={code} status={j.get('status')}")

    # (a) refund WITHOUT a second approver -> 403 dual_approval_required
    codeA, jA = http_post(f"/ui/admin/disputes/{did}/resolve", ADMIN,
                          {"resolution": "refunded"}, role="admin")
    rec("DISP-022 high-value refund w/o second approver -> 403 dual_approval_required",
        codeA == 403 and "dual_approval_required" in json.dumps(jA), f"http={codeA} body={jA}")

    # (b) second approver == acting admin (self) -> 403 dual_approval_self
    codeS, jS = http_post(f"/ui/admin/disputes/{did}/resolve", ADMIN,
                          {"resolution": "refunded", "second_approver_admin_user_id": ADMIN}, role="admin")
    rec("DISP-022 high-value refund w/ SELF approver -> 403 dual_approval_self",
        codeS == 403 and "dual_approval_self" in json.dumps(jS), f"http={codeS} body={jS}")

    # (c) second approver is a non-admin / fabricated id -> 403 invalid_approver
    codeF, jF = http_post(f"/ui/admin/disputes/{did}/resolve", ADMIN,
                          {"resolution": "refunded",
                           "second_approver_admin_user_id": f"ghost_{RUN}"}, role="admin")
    rec("DISP-022 high-value refund w/ fabricated approver -> 403 invalid_approver",
        codeF == 403 and "dual_approval_invalid_approver" in json.dumps(jF), f"http={codeF} body={jF}")

    # dispute still NOT resolved (no money moved on any 403)
    codeG, jG = http_get(f"/ui/admin/disputes/{did}", ADMIN, role="admin")
    rec("DISP-022 dispute NOT resolved after the 403s (no premature money move)",
        codeG == 200 and jG.get("status") != "resolved", f"status={jG.get('status')}")

    # (d) VALID second approver (real, distinct payment-disputes admin) -> 200, money moves
    code0, earned0 = http_balance(creator)
    codeV, jV = http_post(f"/ui/admin/disputes/{did}/resolve", ADMIN,
                          {"resolution": "refunded",
                           "second_approver_admin_user_id": ADMIN2}, role="admin")
    code1, earned1 = http_balance(creator)
    rec("DISP-022 high-value refund w/ VALID second approver -> 200 + money moves",
        codeV == 200 and jV.get("status") == "resolved" and int(jV.get("moved_cents", 0)) > 0
        and earned1 < earned0,
        f"http={codeV} moved={jV.get('moved_cents')} earned {earned0}->{earned1}")

    # (e) idempotent: a re-resolve does not double-move (already resolved -> no new move)
    codeI, jI = http_post(f"/ui/admin/disputes/{did}/resolve", ADMIN,
                          {"resolution": "refunded", "second_approver_admin_user_id": ADMIN2}, role="admin")
    code2, earned2 = http_balance(creator)
    rec("DISP-022 re-resolve is idempotent (no double-debit)",
        earned2 == earned1, f"earned {earned1} -> {earned2} http={codeI}")


def cleanup():
    ok = 0
    for table, key in reversed(_created_keys):
        try:
            if key:
                table.delete_item(Key=key)
                ok += 1
        except Exception as e:
            print("cleanup miss", key, e)
    purged = 0
    try:
        for row in T.billing.scan().get("Items", []):
            if PFX in str(row.get("pk", "")):
                try:
                    T.billing.delete_item(Key={"pk": row["pk"], "sk": row["sk"]})
                    purged += 1
                except Exception:
                    pass
    except Exception as e:
        print("purge scan err", e)
    print(f"cleanup: removed {ok}/{len(_created_keys)} tracked + {purged} residual billing rows")


def residue_check():
    leaked = []
    try:
        for row in T.billing_disputes.scan().get("Items", []):
            if PFX in str(row.get("user_id", "")):
                leaked.append(("billing_disputes", row.get("dispute_id")))
    except Exception:
        pass
    try:
        for row in T.billing.scan().get("Items", []):
            if PFX in str(row.get("pk", "")):
                leaked.append(("billing", row.get("pk"), row.get("sk")))
    except Exception:
        pass
    try:
        for row in T.users.scan().get("Items", []):
            us = str(row.get("user_sub", ""))
            if RUN in us and ("disp_admin" in us):
                leaked.append(("users", us))
    except Exception:
        pass
    rec("cleanup: 0 residual rows across billing/disputes/users for this run",
        not leaked, f"leaked={leaked[:8]}")


if __name__ == "__main__":
    seed_admins()
    try:
        did, creator, tipper = test_creator_respond_flow()
        test_admin_queue_and_scope(did, creator, tipper)
        test_full_happy_path(did, creator, tipper)
        test_dual_approval()
    except Exception as e:
        import traceback
        rec("verify_e2 harness", False, f"EXCEPTION {type(e).__name__}: {e}")
        traceback.print_exc()
    finally:
        cleanup()
        residue_check()
    npass = sum(1 for _, ok, _ in results if ok)
    print(f"\n==== E2 RESULT: {npass}/{len(results)} PASS ====")
    for n, ok, d in results:
        if not ok:
            print("  FAIL:", n, "-", d)
