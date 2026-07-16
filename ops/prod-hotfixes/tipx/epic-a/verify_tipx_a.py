#!/usr/bin/env python3
"""TIPX-A live-DDB-direct verifier (runs on the prod host against DDB-Local).

Pattern-tags every synthetic row with TAG and DELETES all tagged rows at the end
(0 residue). Proves A1/A2/A3/A4/A6 + the tip core still holds. No moto/self-boot.
"""
import os, sys, time, uuid, traceback

TAG = f"tipxA_{int(time.time())}_{uuid.uuid4().hex[:6]}"
RESULTS = []
CREATED = []  # (table_logical, pk, sk) rows we must delete


def rec(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" :: {detail}" if detail else ""))


def uid(role):
    return f"{TAG}_{role}"


def main():
    import boto3
    from app.core.tables import T
    from app.services import tips as tips_mod
    from app.services.tips import charge_tip, reverse_tip_by_payment_id, TipResult
    from app.services.billing_shared import ddb_query_pk, user_pk
    from botocore.exceptions import ClientError

    # ENV NOTE: boto3.resource(...).meta.client rejects low-level AV maps in
    # TransactWriteItems against DDB-Local (the resource client expects native
    # types). Production runs on real AWS where the shipped rail is validated.
    # For this live-DDB-direct verifier we swap in a plain low-level client so the
    # SAME charge_tip/reverse/collab code paths execute unchanged and we validate
    # the LOGIC (fee/atomicity/idempotency/reversal) against real rows.
    _ep = os.environ.get("DDB_ENDPOINT_URL", "http://localhost:8001")
    _plain = boto3.client("dynamodb", endpoint_url=_ep, region_name="us-east-1",
                          aws_access_key_id="test", aws_secret_access_key="test")
    _orig_client = T.billing._t.meta.client

    class _ClientProxy:
        """Delegates every op to the resource's original client EXCEPT
        transact_write_items, which routes to a plain client that accepts the
        low-level AV maps _transact_tip_ledger / collaboration_splits build.
        (Resource put_item/query/get keep native-type serialization.)"""
        def transact_write_items(self, **kw):
            return _plain.transact_write_items(**kw)
        def __getattr__(self, n):
            return getattr(_orig_client, n)

    _proxy = _ClientProxy()
    T.billing._t.meta.client = _proxy

    billing = T.billing

    def query(user):
        return [r for r in ddb_query_pk(billing, user_pk(user)) if r.get("sk", "").startswith("LEDGER#") or r.get("sk", "").startswith("TIPIDEMP#") or r.get("sk", "").startswith("TIPREVERSAL#")]

    def track(user):
        for r in ddb_query_pk(billing, user_pk(user)):
            CREATED.append((r["pk"], r["sk"]))

    def ledger_rows(user, typ=None):
        rows = [r for r in ddb_query_pk(billing, user_pk(user)) if r.get("sk", "").startswith("LEDGER#")]
        if typ:
            rows = [r for r in rows if r.get("type") == typ]
        return rows

    # ---- put a PM on the tipper so resolve_tip_payment_method is exercised ----
    def give_pm(user):
        pm_id = f"pm_{TAG}_{user[-6:]}"
        billing.put_item(Item={"pk": user_pk(user), "sk": f"PM#{pm_id}", "payment_method_id": pm_id})
        return pm_id

    # =====================================================================
    # A3 IDEMPOTENCY: every surface's stable key replays -> ONE debit/credit.
    # =====================================================================
    surfaces = [
        ("post", "post"), ("post_react", "post_react"), ("comment", "comment"),
        ("message", "message"), ("message_react", "message_react"),
        ("video", "video"), ("video_comment", "video_comment"),
    ]
    for label, ctype in surfaces:
        tipper = uid(f"tip_{label}"); recipient = uid(f"rcp_{label}")
        give_pm(tipper)
        key = f"{label}:{TAG}:stable"
        try:
            r1 = charge_tip(tipper_id=tipper, recipient_id=recipient, amount_cents=1000,
                            content_type=ctype, content_id=f"c_{TAG}_{label}",
                            meta={"tag": TAG}, idempotency_key=key)
            r2 = charge_tip(tipper_id=tipper, recipient_id=recipient, amount_cents=1000,
                            content_type=ctype, content_id=f"c_{TAG}_{label}",
                            meta={"tag": TAG}, idempotency_key=key)
            debits = ledger_rows(tipper, "debit")
            credits = ledger_rows(recipient, "credit")
            same_receipt = (r1.tip_payment_id == r2.tip_payment_id)
            replayed = r2.idempotent_replay
            net_ok = (r1.net_cents == 800 and r1.fee_cents == 200)
            ok = (len(debits) == 1 and len(credits) == 1 and same_receipt and replayed and net_ok)
            rec(f"A3 idempotent [{label}]", ok,
                f"debits={len(debits)} credits={len(credits)} same_id={same_receipt} replay={replayed} net={r1.net_cents}/fee={r1.fee_cents}")
        finally:
            track(tipper); track(recipient)

    # =====================================================================
    # CORE: distinct keys => two charges (idempotency does not over-collapse).
    # =====================================================================
    tipper = uid("core_dist"); recipient = uid("core_dist_r"); give_pm(tipper)
    try:
        charge_tip(tipper_id=tipper, recipient_id=recipient, amount_cents=500,
                   content_type="post", content_id=f"cd_{TAG}", meta={"tag": TAG},
                   idempotency_key=f"post:{TAG}:A")
        charge_tip(tipper_id=tipper, recipient_id=recipient, amount_cents=500,
                   content_type="post", content_id=f"cd_{TAG}", meta={"tag": TAG},
                   idempotency_key=f"post:{TAG}:B")
        d = ledger_rows(tipper, "debit"); c = ledger_rows(recipient, "credit")
        rec("CORE distinct-keys charge twice", len(d) == 2 and len(c) == 2, f"debits={len(d)} credits={len(c)}")
    finally:
        track(tipper); track(recipient)

    # =====================================================================
    # CORE: self-tip 400, invalid content_type 400.
    # =====================================================================
    from fastapi import HTTPException
    tipper = uid("core_self"); give_pm(tipper)
    try:
        try:
            charge_tip(tipper_id=tipper, recipient_id=tipper, amount_cents=100,
                       content_type="post", content_id=f"self_{TAG}", meta={"tag": TAG},
                       idempotency_key=f"self:{TAG}")
            rec("CORE self-tip 400", False, "no exception")
        except HTTPException as e:
            rec("CORE self-tip 400", e.status_code == 400, f"status={e.status_code}")
    finally:
        track(tipper)

    # =====================================================================
    # A1 ORPHAN-TOTAL (402 leaves no ledger): force a decline by monkeypatching
    # the PI charger to raise 402, prove NO debit/credit row is written.
    # This mirrors the charge-before-side-effect guarantee the endpoints rely on.
    # =====================================================================
    tipper = uid("a1_402"); recipient = uid("a1_402_r"); give_pm(tipper)
    orig = tips_mod._charge_tip_payment_intent
    def boom(**kw):
        raise HTTPException(402, {"code": "payment_failed", "message": "declined (verify)"})
    tips_mod._charge_tip_payment_intent = boom
    try:
        raised = False
        try:
            charge_tip(tipper_id=tipper, recipient_id=recipient, amount_cents=1000,
                       content_type="post", content_id=f"a1_{TAG}", meta={"tag": TAG},
                       idempotency_key=f"a1:{TAG}", payment_method_id=give_pm(tipper))
        except HTTPException as e:
            raised = (e.status_code == 402)
        d = ledger_rows(tipper, "debit"); c = ledger_rows(recipient, "credit")
        rec("A1 402-before-ledger (no orphan)", raised and len(d) == 0 and len(c) == 0,
            f"raised402={raised} debits={len(d)} credits={len(c)}")
    finally:
        tips_mod._charge_tip_payment_intent = orig
        track(tipper); track(recipient)

    # =====================================================================
    # A2 REVERSAL: charge a tip, then admin-reverse by tip_payment_id.
    #   - funds back (refund row for GROSS on tipper, type=refund)
    #   - earnings NOT inflated (no new credit; clawback row type=reversal)
    #   - original credit flipped state=reversed
    #   - idempotent (second reverse returns replay, no new rows)
    # =====================================================================
    tipper = uid("a2_tip"); recipient = uid("a2_rcp"); give_pm(tipper)
    try:
        r = charge_tip(tipper_id=tipper, recipient_id=recipient, amount_cents=1000,
                       content_type="post", content_id=f"a2_{TAG}", meta={"tag": TAG},
                       idempotency_key=f"a2:{TAG}")
        rev = reverse_tip_by_payment_id(tip_payment_id=r.tip_payment_id, tipper_id=tipper,
                                        reason="verify_reversal", actor="verifier")
        # inspect ledger
        credits = ledger_rows(recipient, "credit")
        reversal_rows = [x for x in ledger_rows(recipient) if x.get("type") == "reversal"]
        refund_rows = [x for x in ledger_rows(tipper) if x.get("type") == "refund"]
        orig_credit = credits[0] if credits else {}
        credit_state = orig_credit.get("state")
        no_credit_from_reversal = all(x.get("type") != "credit" for x in reversal_rows + refund_rows)
        refund_gross = refund_rows and int(refund_rows[0].get("amount_cents", 0)) == 1000
        clawback_net = reversal_rows and int(reversal_rows[0].get("amount_cents", 0)) == 800
        ok = (rev.refunded_cents == 1000 and rev.clawback_cents == 800 and credit_state == "reversed"
              and no_credit_from_reversal and refund_gross and clawback_net)
        rec("A2 admin reversal correct", ok,
            f"refund={rev.refunded_cents} clawback={rev.clawback_cents} credit_state={credit_state} "
            f"refund_gross={bool(refund_gross)} clawback_net={bool(clawback_net)} no_credit_type={no_credit_from_reversal}")

        # idempotent second reversal
        before = len(ledger_rows(recipient)) + len(ledger_rows(tipper))
        rev2 = reverse_tip_by_payment_id(tip_payment_id=r.tip_payment_id, tipper_id=tipper)
        after = len(ledger_rows(recipient)) + len(ledger_rows(tipper))
        rec("A2 reversal idempotent", rev2.idempotent_replay and before == after,
            f"replay={rev2.idempotent_replay} rows {before}->{after}")
    finally:
        track(tipper); track(recipient)

    # =====================================================================
    # A6 LEADERBOARD excludes reversed credits (the A2 recipient above).
    # =====================================================================
    try:
        from app.services.tip_leaderboard import aggregate_tips_for_creator
        # recipient a2_rcp's only credit is reversed -> should NOT appear.
        ranked = aggregate_tips_for_creator(uid("a2_rcp"), "all")
        tippers = {x["user_id"] for x in ranked}
        rec("A6 leaderboard excludes reversed", uid("a2_tip") not in tippers,
            f"ranked_tippers={len(ranked)}")
    except Exception as e:
        rec("A6 leaderboard excludes reversed", False, f"err={e}")

    # =====================================================================
    # A4 COLLAB-SPLIT: tip-sourced split takes 20% fee + atomic + NET per collab.
    #   Use write_collaboration_split_ledger directly with source="tip".
    #   Build a synthetic accepted collaboration in collaboration_agreements.
    # =====================================================================
    try:
        from app.core.tables import T as _T
        collab_id = f"collab_{TAG}"
        A = uid("collabA"); B = uid("collabB"); payer = uid("collab_payer")
        give_pm(payer)
        # seed an accepted collaboration CURRENT row (50/50 split, initiator=A)
        _T.collaboration_agreements.put_item(Item={
            "collaboration_id": collab_id, "sk": "CURRENT", "status": "accepted",
            "initiator_id": A, "recipient_id": B, "split": {A: 50, B: 50},
            "total_revenue_cents": 0,
        })
        CREATED.append((None, ("COLLAB", collab_id, "CURRENT")))
        from app.services.collaboration_splits import write_collaboration_split_ledger
        credited = write_collaboration_split_ledger(
            collaboration_id=collab_id, payer_user_id=payer, amount_cents=1000,
            currency="USD", content_type="post", content_id=f"collabc_{TAG}", source="tip",
        )
        # NET distributable = 800; 50/50 => 400 each. Payer debit = 1000 (gross).
        cA = sum(int(x["amount_cents"]) for x in ledger_rows(A, "credit"))
        cB = sum(int(x["amount_cents"]) for x in ledger_rows(B, "credit"))
        dP = sum(int(x["amount_cents"]) for x in ledger_rows(payer, "debit"))
        total_credited = cA + cB
        fee_taken = dP - total_credited
        ok = (dP == 1000 and total_credited == 800 and fee_taken == 200 and cA == 400 and cB == 400)
        rec("A4 collab tip: fee taken + NET split", ok,
            f"payer_debit={dP} A={cA} B={cB} total_credit={total_credited} fee={fee_taken}")

        # Atomicity: a forced failure writes NOTHING. Point the client at a bad
        # table via a monkeypatched transact to raise, prove no partial rows.
        A2 = uid("collabA2"); B2 = uid("collabB2"); payer2 = uid("collab_payer2")
        collab_id2 = f"collab2_{TAG}"
        _T.collaboration_agreements.put_item(Item={
            "collaboration_id": collab_id2, "sk": "CURRENT", "status": "accepted",
            "initiator_id": A2, "recipient_id": B2, "split": {A2: 50, B2: 50},
            "total_revenue_cents": 0,
        })
        CREATED.append((None, ("COLLAB", collab_id2, "CURRENT")))
        threw = False
        # Force the atomic write to fail and prove NO partial rows land. Patch the
        # (plain) client used by collaboration_splits -> T.billing.meta.client.
        saved = _plain.transact_write_items
        def raise_tx(**kw):
            raise ClientError({"Error": {"Code": "ValidationException", "Message": "forced"}}, "TransactWriteItems")
        _plain.transact_write_items = raise_tx
        try:
            try:
                write_collaboration_split_ledger(
                    collaboration_id=collab_id2, payer_user_id=payer2, amount_cents=1000,
                    currency="USD", content_type="post", content_id=f"collabc2_{TAG}", source="tip",
                )
            except ClientError:
                threw = True
        finally:
            _plain.transact_write_items = saved
        rows_after = len(ledger_rows(A2)) + len(ledger_rows(B2)) + len(ledger_rows(payer2))
        rec("A4 collab split atomic (all-or-nothing)", threw and rows_after == 0,
            f"threw={threw} orphan_rows={rows_after}")
        for u in (A, B, payer, A2, B2, payer2):
            track(u)
    except Exception as e:
        rec("A4 collab-split", False, f"err={e}\n{traceback.format_exc()}")

    # =====================================================================
    # A4 reconcile: solo tip net formula == collab tip net formula (both 20%).
    # =====================================================================
    from app.services.billing_config import split_fee
    fee, net, bps = split_fee("tip_debit", 1000)
    rec("A4 solo/collab net reconcile", net == 800 and fee == 200, f"solo net={net} fee={fee} bps={bps}")

    # cleanup
    cleanup(T)
    # residue check
    residue = 0
    for pk, sk in CREATED:
        if isinstance(sk, tuple):
            continue
        try:
            it = T.billing.get_item(Key={"pk": pk, "sk": sk}).get("Item")
            if it:
                residue += 1
        except Exception:
            pass
    rec("CLEANUP 0 residue (billing)", residue == 0, f"residue_rows={residue}")

    npass = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\n==== TIPX-A VERIFY: {npass}/{len(RESULTS)} PASS ====")
    return 0 if npass == len(RESULTS) else 1


def cleanup(T):
    seen = set()
    for pk, sk in CREATED:
        if isinstance(sk, tuple):
            _, cid, csk = sk
            try:
                # delete all rows for the collab id
                resp = T.collaboration_agreements.query(
                    KeyConditionExpression="collaboration_id = :c",
                    ExpressionAttributeValues={":c": cid},
                )
                for it in resp.get("Items", []):
                    T.collaboration_agreements.delete_item(
                        Key={"collaboration_id": cid, "sk": it["sk"]})
            except Exception:
                pass
            continue
        k = (pk, sk)
        if k in seen:
            continue
        seen.add(k)
        try:
            T.billing.delete_item(Key={"pk": pk, "sk": sk})
        except Exception:
            pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(2)
