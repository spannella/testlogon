"""MOD-A1..A3 in-process verify on PROD DDB. Exercises the REAL report path."""
import time, traceback
from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.aws import ddb
from app.core.tables import T
from app.core.settings import S
import app.routers.moderation as M
import app.routers.newsfeed as NF
from app.services import moderation_case as MC
from app.services import moderation_hide as MH

APP_TABLE = "app_single_table"
import os
APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")

TS = int(time.time())
results = []
def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))
    print(("PASS" if cond else "FAIL"), name, "--", detail)

def seed_post(pid, owner, body):
    ddb.Table(APP_TABLE).put_item(Item={
        "pk": f"POST#{pid}", "sk": "META", "post_id": pid, "user_id": owner,
        "body": body, "content": body, "text": body,
        "status": "published", "visibility": "public", "privacy": "public",
        "created_at": int(time.time()), "updated_at": int(time.time()),
        "image_urls": [],
    })

def report(reporter, pid, topics, reason="This content violates the rules and should be reviewed."):
    inp = M.CreateModerationReportIn(content_type="feed_post", content_id=pid, topics=topics, reason_text=reason)
    return M._create_report(inp, {"user_sub": reporter, "ip": f"10.0.0.{reporter[-1] if reporter[-1].isdigit() else '9'}"}, request=None)

def get_case(pid):
    return MC.get_case(MC.case_id_for("feed_post", pid))

def meta(pid):
    return ddb.Table(APP_TABLE).get_item(Key={"pk": f"POST#{pid}", "sk": "META"}).get("Item") or {}

def poster_alerts(owner):
    try:
        r = T.alerts.query(KeyConditionExpression=Key("user_sub").eq(owner), ScanIndexForward=False, Limit=25)
        return r.get("Items", [])
    except Exception as e:
        print("  (alerts query err:", e, ")")
        return []

print("=== MOD-A VERIFY ts=%d cases_table=%s ===" % (TS, getattr(S, "moderation_cases_table_name", "?")))

# ---- T1: SEVERE (sexual) -> auto-hide on 1st report ----
owner1 = f"modowner1_{TS}"
p1 = f"modp1_{TS}"
seed_post(p1, owner1, "ORIGINAL_SEVERE_BODY_%d" % TS)
before = meta(p1)
report(f"modrep1_{TS}", p1, ["sexual"])
c1 = get_case(p1)
m1 = meta(p1)
check("T1 case exists", c1 is not None)
check("T1 state=under_review", c1 and c1.get("state") == "under_review", str(c1 and c1.get("state")))
check("T1 hidden flag on case", c1 and bool(c1.get("hidden")))
check("T1 meta moderation_hidden set", bool(m1.get("moderation_hidden")))
check("T1 meta moderation_case_id linked", m1.get("moderation_case_id") == MC.case_id_for("feed_post", p1))
check("T1 NON-DESTRUCTIVE body intact", m1.get("body") == before.get("body") and m1.get("body") == "ORIGINAL_SEVERE_BODY_%d" % TS, repr(m1.get("body")))
# owner-aware read: non-owner 404, owner 200
try:
    NF.get_post(p1, f"stranger_{TS}"); nonowner="VISIBLE"
except HTTPException as e: nonowner = e.status_code
check("T1 non-owner get_post hidden (404)", nonowner == 404, str(nonowner))
try:
    d = NF.get_post(p1, owner1); owner_ok = isinstance(d, dict)
except HTTPException as e: owner_ok = False; print("  owner get_post raised", e.status_code)
check("T1 OWNER get_post can still see it", owner_ok)
check("T1 is_hidden_for_viewer(non-owner)=True", MH.is_hidden_for_viewer(m1, f"stranger_{TS}") is True)
check("T1 is_hidden_for_viewer(owner)=False", MH.is_hidden_for_viewer(m1, owner1) is False)
al = [a for a in poster_alerts(owner1) if a.get("event") == "moderation_content_hidden"]
check("T1 poster notified (moderation_content_hidden alert)", len(al) >= 1, "alerts=%d" % len(al))

# ---- T2: SPAM once -> NOT hidden ----
owner2 = f"modowner2_{TS}"
p2 = f"modp2_{TS}"
seed_post(p2, owner2, "ORIGINAL_SPAM_BODY")
report(f"modrep2_{TS}", p2, ["spam"])
c2 = get_case(p2); m2 = meta(p2)
check("T2 case exists visible", c2 and c2.get("state") == "visible", str(c2 and c2.get("state")))
check("T2 report_count=1", c2 and int(c2.get("report_count", 0)) == 1, str(c2 and c2.get("report_count")))
check("T2 NOT hidden (meta)", not m2.get("moderation_hidden"))
check("T2 non-owner CAN still see it", isinstance(NF.get_post(p2, f"stranger_{TS}"), dict))

# ---- T3: 3 distinct spam reports -> hidden at >=3 ----
owner3 = f"modowner3_{TS}"
p3 = f"modp3_{TS}"
seed_post(p3, owner3, "ORIGINAL_SPAM3_BODY")
report(f"modrA_{TS}", p3, ["spam"])
after1 = get_case(p3)
report(f"modrB_{TS}", p3, ["spam"])
after2 = get_case(p3)
report(f"modrC_{TS}", p3, ["spam"])
c3 = get_case(p3); m3 = meta(p3)
check("T3 after 1 report NOT hidden", after1 and not after1.get("hidden"), str(after1 and after1.get("hidden")))
check("T3 after 2 reports NOT hidden", after2 and not after2.get("hidden"), str(after2 and after2.get("hidden")))
check("T3 report_count=3", c3 and int(c3.get("report_count", 0)) == 3, str(c3 and c3.get("report_count")))
check("T3 hidden at 3rd report (under_review)", c3 and c3.get("state") == "under_review", str(c3 and c3.get("state")))
check("T3 meta hidden + body intact", m3.get("moderation_hidden") and m3.get("body") == "ORIGINAL_SPAM3_BODY")

# ---- T4: TRUSTED reporter, spam once -> hidden ----
trusted = f"modtrust_{TS}"
T.account_state.put_item(Item={"user_sub": trusted, "trusted_reporter": True, "updated_at": TS})
owner4 = f"modowner4_{TS}"
p4 = f"modp4_{TS}"
seed_post(p4, owner4, "ORIGINAL_TRUSTED_BODY")
check("T4 is_trusted_reporter=True", MC.is_trusted_reporter(trusted))
report(trusted, p4, ["spam"])
c4 = get_case(p4); m4 = meta(p4)
check("T4 hidden by trusted reporter (1 spam report)", c4 and c4.get("state") == "under_review", str(c4 and c4.get("state")))
check("T4 report_count=1 (single report)", c4 and int(c4.get("report_count", 0)) == 1, str(c4 and c4.get("report_count")))
check("T4 body intact (non-destructive)", m4.get("body") == "ORIGINAL_TRUSTED_BODY")

# ---- T5: legacy category back-compat (racist -> hate severe -> hidden) ----
owner5 = f"modowner5_{TS}"; p5 = f"modp5_{TS}"
seed_post(p5, owner5, "ORIGINAL_LEGACY_BODY")
report(f"modrep5_{TS}", p5, ["racist"])
c5 = get_case(p5)
check("T5 legacy 'racist' maps to 'hate' + severe auto-hide", c5 and c5.get("state") == "under_review", str(c5 and c5.get("state")))
check("T5 categories normalized to 'hate'", c5 and "hate" in set(c5.get("categories") or []), str(c5 and c5.get("categories")))

# ---- T6: state machine guards ----
try:
    MC.transition(MC.case_id_for("feed_post", p1), "deleted")
    guard = False
except ValueError:
    guard = True
check("T6 illegal transition rejected (under_review->deleted skips hold)", guard)
# idempotent re-report on already-hidden severe post does not double-hide/regress
r_again = MC.on_report_filed(content_type="feed_post", content_id=p1, topics=["sexual"], reporter_user_id=f"modrepX_{TS}", metadata={}, ticket_id=None)
check("T6 re-report idempotent (no new auto-hide)", r_again.get("auto_hidden_now") is False, str(r_again.get("auto_hidden_now")))

npass = sum(1 for ok, _, _ in results if ok)
ntot = len(results)
print("\n=== RESULT %d/%d ===" % (npass, ntot))
print("OVERALL", "ALL_PASS" if npass == ntot else "SOME_FAIL")
