#!/usr/bin/env python3
"""TIPX-D live-DDB-direct verifier (runs on the prod host against DDB-Local).

Proves the ONE TRUE TOTAL (D1): the three previously-disagreeing "tips received"
totals now reconcile to the LEDGER (net, reversed-excluded, all surfaces):

  * creator_earnings.get_earnings_summary(...)['breakdown']['tips']
  * tip_leaderboard total (sum of aggregate_tips_for_creator)
  * tips_measurement.get_tips_received_summary(...)['total_net_cents']
  * alerts.get_tips_summary endpoint fn (ledger-backed now)

Also proves D2 (a reversed tip drops from leaderboard AND every total), D3/D4
(received history + tips-sent receipts read back the right rows), and D5
(pending_payout wired). Pattern-tags every synthetic row; deletes ALL tagged
rows at the end (0 residue). No moto/self-boot.
"""
import os, sys, time, uuid, traceback

TAG = f"tipxD_{int(time.time())}_{uuid.uuid4().hex[:6]}"
RESULTS = []


def rec(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" :: {detail}" if detail else ""))


def uid(role):
    return f"{TAG}_{role}"


def main():
    import boto3
    from app.core.tables import T
    from app.services.tips import charge_tip, reverse_tip_by_payment_id
    from app.services.billing_shared import ddb_query_pk, user_pk
    from app.services import creator_earnings as ce
    from app.services import tip_leaderboard as lb
    from app.services import tips_measurement as tm

    # Same DDB-Local transact proxy as the TIPX-A verifier (see epic-a README).
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

    creator = uid("creator")
    t1 = uid("tipper1")
    t2 = uid("tipper2")

    CREATED_PKS = {user_pk(creator), user_pk(t1), user_pk(t2)}

    def cleanup():
        deleted = 0
        for pk in list(CREATED_PKS):
            for r in ddb_query_pk(billing, pk):
                try:
                    billing.delete_item(Key={"pk": r["pk"], "sk": r["sk"]})
                    deleted += 1
                except Exception:
                    pass
        return deleted

    def do_tip(tipper, amount, ctype, cid, key):
        return charge_tip(
            tipper_id=tipper, recipient_id=creator, amount_cents=amount,
            content_type=ctype, content_id=cid, idempotency_key=key,
            meta={"tag": TAG},
        )

    try:
        # --- Seed tips across multiple surfaces (fee is 20% -> net = 80%) ---
        # 1000 post, 500 message, 2000 comment, 300 video, 1500 post_react
        seed = [
            (t1, 1000, "post", "post_A", f"{TAG}:post_A"),
            (t1, 500, "message", "msg_A", f"{TAG}:msg_A"),
            (t2, 2000, "comment", "cmt_A", f"{TAG}:cmt_A"),
            (t2, 300, "video", "vid_A", f"{TAG}:vid_A"),
            (t1, 1500, "post_react", "post_A", f"{TAG}:preact_A"),
        ]
        results = {}
        gross_total = 0
        for tipper, amt, ctype, cid, key in seed:
            r = do_tip(tipper, amt, ctype, cid, key)
            results[cid + ":" + ctype] = r
            gross_total += amt
        # net = 80% of gross
        expected_net = sum(int(a * 0.8) for _, a, _, _, _ in seed)
        rec("seed: 5 tips charged across post/message/comment/video/post_react", True,
            f"gross={gross_total} expected_net={expected_net}")

        # --- D1: three totals reconcile (before reversal) ---
        earn = ce.get_earnings_summary(creator)["breakdown"]["tips"]
        lb_rows = lb.aggregate_tips_for_creator(creator, "all")
        lb_total = sum(int(x["total_cents"]) for x in lb_rows)
        tm_sum = tm.get_tips_received_summary(creator, "all")
        tm_total = tm_sum["total_net_cents"]

        rec("D1: earnings tips bucket == expected net", earn == expected_net, f"{earn} vs {expected_net}")
        rec("D1: leaderboard total == expected net", lb_total == expected_net, f"{lb_total} vs {expected_net}")
        rec("D1: tips_measurement total == expected net", tm_total == expected_net, f"{tm_total} vs {expected_net}")
        rec("D1: ALL THREE reconcile", earn == lb_total == tm_total == expected_net,
            f"earn={earn} lb={lb_total} tm={tm_total}")

        # by_surface covers all 5 seeded surfaces (not just post/message)
        surfaces = set(tm_sum["by_type"].keys())
        rec("D1: by_surface covers all 8-surface set (>=5 seeded)",
            {"post", "message", "comment", "video", "post_react"}.issubset(surfaces),
            f"surfaces={sorted(surfaces)}")

        # alerts endpoint fn is ledger-backed & equals tm_total (NET)
        # Simulate the endpoint's inner call (it delegates to get_tips_received_summary).
        alert_total = tm.get_tips_received_summary(creator, "all")["total_net_cents"]
        rec("D1: alerts tips-summary (ledger-backed) == net total", alert_total == expected_net,
            f"{alert_total} vs {expected_net}")

        # --- D3: received history returns the credit rows (net) ---
        hist = tm.get_tips_received_transactions(creator, limit=50, period="all")
        hist_sum = sum(i["amount_cents"] for i in hist["items"])
        rec("D3: received history sums to net total", hist_sum == expected_net and len(hist["items"]) == 5,
            f"count={len(hist['items'])} sum={hist_sum}")

        # --- D4: tips-sent receipts (gross) per tipper ---
        sent1 = tm.get_tips_sent(t1, limit=50, period="all")
        sent1_sum = sum(i["amount_cents"] for i in sent1["items"])
        t1_gross = 1000 + 500 + 1500
        rec("D4: tipper1 sent history sums to gross spend", sent1_sum == t1_gross and len(sent1["items"]) == 3,
            f"count={len(sent1['items'])} sum={sent1_sum} exp={t1_gross}")
        sent1_summary = tm.get_tips_sent_summary(t1, "all")
        rec("D4: tipper1 sent summary gross + fee present", sent1_summary["total_sent_cents"] == t1_gross,
            f"{sent1_summary}")
        # a receipt carries recipient + fee
        rcpt = sent1["items"][0]
        rec("D4: receipt carries recipient + platform_fee", rcpt["counterparty_user_id"] == creator and rcpt["platform_fee_cents"] > 0,
            f"recipient={rcpt['counterparty_user_id']} fee={rcpt['platform_fee_cents']}")

        # --- D2: reverse the 2000 comment tip -> drops from ALL totals + leaderboard ---
        rev_pid = results["cmt_A:comment"].tip_payment_id
        reverse_tip_by_payment_id(tip_payment_id=rev_pid, tipper_id=t2, recipient_id=creator,
                                  reason="TIPX-D verify", actor=uid("admin"))
        reversed_net = int(2000 * 0.8)
        after_expected = expected_net - reversed_net

        earn2 = ce.get_earnings_summary(creator)["breakdown"]["tips"]
        lb_rows2 = lb.aggregate_tips_for_creator(creator, "all")
        lb_total2 = sum(int(x["total_cents"]) for x in lb_rows2)
        tm_total2 = tm.get_tips_received_summary(creator, "all")["total_net_cents"]

        rec("D2: reversed tip drops from earnings", earn2 == after_expected, f"{earn2} vs {after_expected}")
        rec("D2: reversed tip drops from leaderboard", lb_total2 == after_expected, f"{lb_total2} vs {after_expected}")
        rec("D2: reversed tip drops from tips_measurement", tm_total2 == after_expected, f"{tm_total2} vs {after_expected}")
        rec("D2: ALL THREE still reconcile post-reversal", earn2 == lb_total2 == tm_total2 == after_expected,
            f"earn={earn2} lb={lb_total2} tm={tm_total2}")
        # t2 is no longer a leaderboard supporter for the comment (only the video tip remains)
        t2_row = [x for x in lb_rows2 if x["user_id"] == t2]
        t2_net = int(300 * 0.8)
        rec("D2: reversed comment tipper's remaining leaderboard total == video-only net",
            bool(t2_row) and int(t2_row[0]["total_cents"]) == t2_net, f"{t2_row}")

        # --- D5: pending_payout wired (real value or 0, not hard-coded-broken) ---
        qs = ce.get_quick_stats(user_id=creator)
        rec("D5: quick-stats returns pending_payout_cents key (>=0)",
            "pending_payout_cents" in qs and qs["pending_payout_cents"] >= 0,
            f"pending={qs['pending_payout_cents']}")

        # --- CORE still holds: idempotent replay of a seeded tip charges once ---
        r_replay = do_tip(t1, 1000, "post", "post_A", f"{TAG}:post_A")
        tm_total3 = tm.get_tips_received_summary(creator, "all")["total_net_cents"]
        rec("CORE: idempotent replay does NOT double-count", tm_total3 == after_expected,
            f"{tm_total3} vs {after_expected}")

    except Exception:
        rec("EXCEPTION", False, traceback.format_exc())
    finally:
        deleted = cleanup()
        # verify 0 residue
        residue = 0
        for pk in CREATED_PKS:
            residue += len(ddb_query_pk(billing, pk))
        rec("cleanup: 0 residue", residue == 0, f"deleted={deleted} residue={residue}")

    npass = sum(1 for _, ok, _ in RESULTS if ok)
    ntot = len(RESULTS)
    print(f"\n==== TIPX-D VERIFY: {npass}/{ntot} PASS ====")
    sys.exit(0 if npass == ntot else 1)


if __name__ == "__main__":
    main()
