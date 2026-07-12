"""MOD close-out: the two lifecycle lanes not covered by verify_mode1_e2e.py —
GUARDED auto-hide (lower-severity spam: 1 report NOT hidden, 3 reports hidden)
and LICENSING/IP report -> DMCA pipeline (routes away from the general ticket,
files a DMCA claim, hides the content in its store, records a strike).

In-process on prod as ubuntu (venv + .env.local, DEV_MODE=1). Real prod DDB,
the exact _create_report service the /v1/moderation/reports route runs.
"""
import time
from app.routers.moderation import CreateModerationReportIn, _create_report
from app.routers.admin_moderation import ddb, APP_TABLE, T
from app.services import moderation_case as mcase

TS = int(time.time())
PG = "e2e_guardposter_%d" % TS
PD = "e2e_dmcaposter_%d" % TS
R1 = "e2e_rep1_%d" % TS; R2 = "e2e_rep2_%d" % TS; R3 = "e2e_rep3_%d" % TS; RD = "e2e_repd_%d" % TS

results = []
seeded = []
def rec(name, ok, detail=""):
    results.append(bool(ok))
    tag = "PASS" if ok else "FAIL"
    print("[%s] %s :: %s" % (tag, name, detail))

def seed_feed_post(pid, author, text):
    ddb.Table(APP_TABLE).put_item(Item={
        "pk": "POST#%s" % pid, "sk": "META", "post_id": pid,
        "user_id": author, "user_sub": author, "text": text, "created_at": TS,
        "visibility": "public", "type": "post", "image_urls": [],
        "comment_count": 0, "reaction_counts": {},
    })
    seeded.append(pid)

def feed_post_row(pid):
    return ddb.Table(APP_TABLE).get_item(Key={"pk": "POST#%s" % pid, "sk": "META"}).get("Item") or {}

def is_hidden(row):
    return bool(row.get("moderation_hidden") or row.get("moderation_removed") or row.get("moderation_removed_at"))

def report(sub, ct, cid, topics, reason="close-lane report"):
    inp = CreateModerationReportIn(content_type=ct, content_id=cid, topics=topics, reason_text=reason)
    return _create_report(inp, {"user_sub": sub, "role": "user", "ip": ""}, request=None)

# ===== LANE A: GUARDED AUTO-HIDE (lower-severity spam) =====
pidg = "e2e_guard_%d" % TS
seed_feed_post(pidg, PG, "GUARD lane - spammy but lower severity")
report(R1, "feed_post", pidg, ["spam"])
rec("guard.1report_not_hidden", not is_hidden(feed_post_row(pidg)), "after 1 spam report hidden=%s" % is_hidden(feed_post_row(pidg)))
report(R2, "feed_post", pidg, ["spam"])
rec("guard.2report_not_hidden", not is_hidden(feed_post_row(pidg)), "after 2 spam reports hidden=%s" % is_hidden(feed_post_row(pidg)))
report(R3, "feed_post", pidg, ["spam"])
row3 = feed_post_row(pidg)
rec("guard.3report_hidden", is_hidden(row3), "after 3 spam reports hidden=%s flags=%s" % (is_hidden(row3), {k: row3.get(k) for k in ("moderation_hidden", "moderation_removed")}))
case = mcase.get_case_for_content("feed_post", pidg)
rec("guard.reason_threshold", bool(case) and int((case or {}).get("report_count") or 0) >= 3, "case_report_count=%s" % ((case or {}).get("report_count") if case else "n/a"))

# ===== LANE B: LICENSING/IP -> DMCA =====
pidd = "e2e_dmca_%d" % TS
seed_feed_post(pidd, PD, "DMCA lane - copyrighted work")
outd = report(RD, "feed_post", pidd, ["licensing_ip"], reason="This is my copyrighted song")
claim_id = getattr(outd, "report_id", "") or ""
rec("dmca.routed_submitted", getattr(outd, "status", "") == "submitted" and claim_id.startswith("dmca_"), "status=%s report_id=%s" % (getattr(outd, "status", None), claim_id))
rowd = feed_post_row(pidd)
rec("dmca.content_hidden_in_store", bool(rowd.get("dmca_hidden")) and rowd.get("dmca_claim_id") == claim_id, "dmca_hidden=%s claim=%s" % (rowd.get("dmca_hidden"), rowd.get("dmca_claim_id")))
try:
    from app.services.dmca_claims import get_claim
    cl = get_claim(claim_id)
except Exception as e:
    cl = None
rec("dmca.claim_recorded_with_strike", bool(cl) and int((cl or {}).get("strike_number") or 0) >= 1, "claim_status=%s strike=%s" % ((cl or {}).get("status"), (cl or {}).get("strike_number")))
gcase = mcase.get_case_for_content("feed_post", pidd)
rec("dmca.no_general_ticket", not gcase, "general_case_present=%s" % bool(gcase))

# ===== CLEANUP =====
for pid in seeded:
    try:
        ddb.Table(APP_TABLE).delete_item(Key={"pk": "POST#%s" % pid, "sk": "META"})
    except Exception:
        pass

n_pass = sum(1 for r in results if r)
print("")
print("==== CLOSE-LANES MATRIX: %d/%d PASS ====" % (n_pass, len(results)))
