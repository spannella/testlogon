#!/usr/bin/env python3
"""TIPX-B live-DDB-direct verifier (runs on the prod host against DDB-Local).

Epic B is app/web-first; the ONE money-path assertion B adds is that the tip
charge HONORS an explicit payment_method_id (F9: the web comment tip now sends
one) — resolve_tip_payment_method must (a) use the explicit PM when it belongs to
the tipper, (b) reject a foreign PM with 400, (c) fall back to the tip-default
when none is given — and the tip CORE (charge/credit/receipt/net-fee/idempotency/
402-before-ledger) still holds through the `comment` + `video_comment` surfaces.

Pattern-tags every synthetic row with TAG and DELETES all tagged rows at the end
(0 residue). No moto/self-boot. Mirrors ops/prod-hotfixes/tipx/epic-a/verify_tipx_a.py.
"""
import os, sys, time, uuid, traceback

TAG = f"tipxB_{int(time.time())}_{uuid.uuid4().hex[:6]}"
RESULTS = []
CREATED = []


def rec(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" :: {detail}" if detail else ""))


def uid(role):
    return f"{TAG}_{role}"


def main():
    import boto3
    from app.core.tables import T
    from app.services import tips as tips_mod
    from app.services.tips import charge_tip
    from app.services.billing_shared import ddb_query_pk, user_pk
    from botocore.exceptions import ClientError
    from fastapi import HTTPException

    _ep = os.environ.get("DDB_ENDPOINT_URL", "http://localhost:8001")
    _plain = boto3.client("dynamodb", endpoint_url=_ep, region_name="us-east-1",
                          aws_access_key_id="test", aws_secret_access_key="test")
    _orig_client = T.billing._t.meta.client

    class _ClientProxy:
        def transact_write_items(self, **kw):
            return _plain.transact_write_items(**kw)
        def __getattr__(self, n):
            return getattr(_orig_client, n)

    T.billing._t.meta.client = _ClientProxy()
    billing = T.billing

    def track(user):
        for r in ddb_query_pk(billing, user_pk(user)):
            CREATED.append((r["pk"], r["sk"]))

    def ledger_rows(user, typ=None):
        rows = [r for r in ddb_query_pk(billing, user_pk(user)) if r.get("sk", "").startswith("LEDGER#")]
        if typ:
            rows = [r for r in rows if r.get("type") == typ]
        return rows

    def give_pm(user, suffix=""):
        pm_id = f"pm_{TAG}_{user[-6:]}{suffix}"
        billing.put_item(Item={"pk": user_pk(user), "sk": f"PM#{pm_id}", "payment_method_id": pm_id})
        return pm_id

    def set_tip_default(user, pm_id):
        billing.put_item(Item={"pk": user_pk(user), "sk": "BILLING", "tip_default_payment_method_id": pm_id})

    # =====================================================================
    # B-F9 (a): comment tip with an EXPLICIT payment_method_id -> the charge
    # HONORS it (recorded on the debit row), net 800 / fee 200, one charge.
    # =====================================================================
    tipper = uid("f9_explicit"); recipient = uid("f9_explicit_r")
    give_pm(tipper, "_A")  # a default-ish PM
    explicit = give_pm(tipper, "_B")  # the one the tipper explicitly chose
    try:
        r = charge_tip(tipper_id=tipper, recipient_id=recipient, amount_cents=1000,
                       payment_method_id=explicit, content_type="comment",
                       content_id=f"cmt_{TAG}", meta={"tag": TAG},
                       idempotency_key=f"cmttip:{TAG}:explicit")
        debit = ledger_rows(tipper, "debit")
        credit = ledger_rows(recipient, "credit")
        pm_on_debit = debit[0].get("meta", {}).get("payment_method_id") if debit else None
        honored = pm_on_debit == explicit
        net_ok = (r.net_cents == 800 and r.fee_cents == 200 and r.charged_cents == 1000)
        rec("B-F9 explicit PM honored (comment)", bool(honored) and len(debit) == 1 and len(credit) == 1 and net_ok,
            f"pm_on_debit={pm_on_debit} want={explicit} net={r.net_cents}/fee={r.fee_cents}")
    except Exception as e:
        rec("B-F9 explicit PM honored (comment)", False, f"exc={e!r}")
    finally:
        track(tipper); track(recipient)

    # =====================================================================
    # B-F9 (a'): idempotent — the SAME stable comment key double-fires -> ONE
    # debit/credit + a replayed receipt (no double charge on retry/double-tap).
    # =====================================================================
    tipper = uid("f9_idem"); recipient = uid("f9_idem_r"); pm = give_pm(tipper)
    try:
        k = f"cmttip:{TAG}:idem"
        a = charge_tip(tipper_id=tipper, recipient_id=recipient, amount_cents=500,
                       payment_method_id=pm, content_type="comment",
                       content_id=f"cmt2_{TAG}", meta={"tag": TAG}, idempotency_key=k)
        b = charge_tip(tipper_id=tipper, recipient_id=recipient, amount_cents=500,
                       payment_method_id=pm, content_type="comment",
                       content_id=f"cmt2_{TAG}", meta={"tag": TAG}, idempotency_key=k)
        d = ledger_rows(tipper, "debit"); c = ledger_rows(recipient, "credit")
        rec("B-F9 comment idempotent (1 charge)",
            len(d) == 1 and len(c) == 1 and a.tip_payment_id == b.tip_payment_id and b.idempotent_replay,
            f"debits={len(d)} credits={len(c)} same_id={a.tip_payment_id == b.tip_payment_id} replay={b.idempotent_replay}")
    except Exception as e:
        rec("B-F9 comment idempotent (1 charge)", False, f"exc={e!r}")
    finally:
        track(tipper); track(recipient)

    # =====================================================================
    # B-F9 (b): a FOREIGN payment_method_id (not the tipper's) -> 400, no ledger.
    # =====================================================================
    tipper = uid("f9_foreign"); recipient = uid("f9_foreign_r"); give_pm(tipper)
    try:
        try:
            charge_tip(tipper_id=tipper, recipient_id=recipient, amount_cents=1000,
                       payment_method_id="pm_someone_else", content_type="comment",
                       content_id=f"cmt3_{TAG}", meta={"tag": TAG},
                       idempotency_key=f"cmttip:{TAG}:foreign")
            rec("B-F9 foreign PM rejected 400", False, "no exception raised")
        except HTTPException as e:
            no_ledger = len(ledger_rows(tipper, "debit")) == 0 and len(ledger_rows(recipient, "credit")) == 0
            rec("B-F9 foreign PM rejected 400 (no ledger)", e.status_code == 400 and no_ledger,
                f"status={e.status_code} no_ledger={no_ledger}")
    finally:
        track(tipper); track(recipient)

    # =====================================================================
    # B-F9 (c): NO explicit PM -> falls back to the tipper's tip-default and
    # HONORS it (the resolve chain the app/web rely on).
    # =====================================================================
    tipper = uid("f9_default"); recipient = uid("f9_default_r")
    tipdef = give_pm(tipper, "_TD"); set_tip_default(tipper, tipdef)
    try:
        r = charge_tip(tipper_id=tipper, recipient_id=recipient, amount_cents=1000,
                       payment_method_id=None, content_type="comment",
                       content_id=f"cmt4_{TAG}", meta={"tag": TAG},
                       idempotency_key=f"cmttip:{TAG}:default")
        debit = ledger_rows(tipper, "debit")
        pm_on_debit = debit[0].get("meta", {}).get("payment_method_id") if debit else None
        honored = pm_on_debit == tipdef
        rec("B-F9 tip-default fallback honored", bool(honored),
            f"pm_on_debit={pm_on_debit} want={tipdef}")
    except Exception as e:
        rec("B-F9 tip-default fallback honored", False, f"exc={e!r}")
    finally:
        track(tipper); track(recipient)

    # =====================================================================
    # CORE regression: video_comment surface still charges NET + credits once.
    # =====================================================================
    tipper = uid("vc_core"); recipient = uid("vc_core_r"); pm = give_pm(tipper)
    try:
        r = charge_tip(tipper_id=tipper, recipient_id=recipient, amount_cents=2000,
                       payment_method_id=pm, content_type="video_comment",
                       content_id=f"vc_{TAG}", meta={"tag": TAG},
                       idempotency_key=f"vidcmttip:{TAG}:core")
        d = ledger_rows(tipper, "debit"); c = ledger_rows(recipient, "credit")
        rec("CORE video_comment net/credit", len(d) == 1 and len(c) == 1 and r.net_cents == 1600 and r.fee_cents == 400,
            f"debits={len(d)} credits={len(c)} net={r.net_cents}/fee={r.fee_cents}")
    except Exception as e:
        rec("CORE video_comment net/credit", False, f"exc={e!r}")
    finally:
        track(tipper); track(recipient)

    # =====================================================================
    # CORE: 402-before-ledger — a forced decline leaves NO debit/credit (the
    # charge-before-bump guarantee the comment endpoints rely on).
    # =====================================================================
    tipper = uid("core_402"); recipient = uid("core_402_r"); pm = give_pm(tipper)
    orig = tips_mod._charge_tip_payment_intent
    def boom(**kw):
        raise HTTPException(402, {"code": "payment_failed", "message": "declined (verify)"})
    tips_mod._charge_tip_payment_intent = boom
    try:
        raised = False
        try:
            charge_tip(tipper_id=tipper, recipient_id=recipient, amount_cents=1000,
                       payment_method_id=pm, content_type="comment",
                       content_id=f"cmt402_{TAG}", meta={"tag": TAG},
                       idempotency_key=f"cmttip:{TAG}:402")
        except HTTPException as e:
            raised = (e.status_code == 402)
        d = ledger_rows(tipper, "debit"); c = ledger_rows(recipient, "credit")
        rec("CORE 402 before ledger (comment)", raised and len(d) == 0 and len(c) == 0,
            f"raised402={raised} debits={len(d)} credits={len(c)}")
    finally:
        tips_mod._charge_tip_payment_intent = orig
        track(tipper); track(recipient)

    # ---- cleanup ----
    deleted = 0
    for pk, sk in set(CREATED):
        try:
            billing.delete_item(Key={"pk": pk, "sk": sk}); deleted += 1
        except Exception:
            pass
    residue = 0
    for pk, sk in set(CREATED):
        try:
            g = billing.get_item(Key={"pk": pk, "sk": sk}).get("Item")
            if g:
                residue += 1
        except Exception:
            pass
    rec("cleanup 0 residue", residue == 0, f"deleted={deleted} residue={residue}")

    npass = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\n==== {npass}/{len(RESULTS)} PASS ====")
    return 0 if npass == len(RESULTS) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(2)
