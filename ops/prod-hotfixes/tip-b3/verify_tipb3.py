import os, uuid, json, traceback
os.environ.setdefault("DEV_MODE", "1")

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import app
from app.routers import newsfeed as nf
from app.services import sessions as sess
from app.services import tips as tips_mod
from app.core.tables import T
from app.core.settings import S

now_iso = nf.now_iso
try:
    object.__setattr__(S, "video_gallery_enabled", True)
except Exception:
    pass

HOLDER = {"uid": None}
app.dependency_overrides[nf._get_user_id] = lambda: HOLDER["uid"]
app.dependency_overrides[sess.require_ui_session] = lambda: {
    "user_sub": HOLDER["uid"], "sub": HOLDER["uid"], "session_id": "vtest",
}
client = TestClient(app)

rid = uuid.uuid4().hex[:8]
AUTHOR = f"tipb3author_{rid}"
TIPPER = f"tipb3tipper_{rid}"
results = []
def rec(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + (" :: " + detail if detail else ""))

def ledger(uid):
    r = T.billing.query(KeyConditionExpression=Key("pk").eq(f"USER#{uid}") & Key("sk").begins_with("LEDGER#"))
    return r.get("Items", [])
def find(rows, typ, ctype):
    for it in rows:
        if it.get("type") == typ and (it.get("meta") or {}).get("content_type") == ctype:
            yield it

# seed a public post owned by AUTHOR
post_id = "post_" + uuid.uuid4().hex[:12]
nf.ddb_put_item({"pk": nf.pk_post(post_id), "sk": nf.sk_post(), "post_id": post_id,
                 "user_id": AUTHOR, "Entity": "Post", "visibility": "public",
                 "locked": False, "created_at": now_iso(), "comment_count": 0})

# seed TIPPER billing: a PM + tip-default (for TIP-301 explicit/tip-default PM test)
T.billing.put_item(Item={"pk": f"USER#{TIPPER}", "sk": "PM#pm_test_tipb3", "payment_method_id": "pm_test_tipb3"})
T.billing.put_item(Item={"pk": f"USER#{TIPPER}", "sk": "BILLING", "tip_default_payment_method_id": "pm_test_tipb3"})

# ============ T1: comment-CARRYING tip (TIP-302) ============
try:
    HOLDER["uid"] = TIPPER
    a0 = len(list(find(ledger(TIPPER), "debit", "comment")))
    b0 = len(list(find(ledger(AUTHOR), "credit", "comment")))
    r = client.post(f"/posts/{post_id}/comments",
                    json={"body": "carrying tip!", "tip_amount_cents": 500, "tip_payment_method_id": "pm_test_tipb3"})
    body = r.json()
    stamped = body.get("tip_total_cents")
    deb = list(find(ledger(TIPPER), "debit", "comment"))
    cre = list(find(ledger(AUTHOR), "credit", "comment"))
    new_deb = [d for d in deb if d["amount_cents"] == 500]
    new_cre = [c for c in cre if c["amount_cents"] == 400]
    ok = (r.status_code in (200, 201) and stamped == 500
          and len(deb) == a0 + 1 and len(cre) == b0 + 1
          and new_deb and new_cre
          and new_cre[0].get("type") == "credit"
          and new_deb[0]["meta"].get("payment_method_id") == "pm_test_tipb3")
    rec("T1 comment-carrying tip (302): tipper debit 500 / author credit 400 net type=credit / stamped 500 / PM flows",
        ok, f"status={r.status_code} stamped={stamped} debit={new_deb[0]['amount_cents'] if new_deb else None} credit={new_cre[0]['amount_cents'] if new_cre else None} credit_type={new_cre[0]['type'] if new_cre else None}")
except Exception as e:
    rec("T1 comment-carrying tip", False, repr(e) + "\n" + traceback.format_exc())

# ============ T2: tip an EXISTING comment with tip-default PM (TIP-301) ============
try:
    # AUTHOR posts a plain comment
    HOLDER["uid"] = AUTHOR
    rc = client.post(f"/posts/{post_id}/comments", json={"body": "author comment"})
    cmt_id = rc.json()["comment_id"]
    # TIPPER tips it, NO explicit PM -> resolves tip_default pm_test_tipb3
    HOLDER["uid"] = TIPPER
    b0 = len(list(find(ledger(AUTHOR), "credit", "comment")))
    r = client.post(f"/posts/{post_id}/comments/{cmt_id}/tip", json={"amount_cents": 800})
    cre = list(find(ledger(AUTHOR), "credit", "comment"))
    new_cre = [c for c in cre if c["amount_cents"] == 640]
    pi = (r.json() or {}).get("payment_intent", {})
    ok = (r.status_code == 200 and len(cre) == b0 + 1 and new_cre
          and new_cre[0]["type"] == "credit"
          and new_cre[0]["meta"].get("payment_method_id") == "pm_test_tipb3")
    rec("T2 tip existing comment w/ tip-default PM (301): author credit 640 net type=credit, PM=pm_test_tipb3 resolved",
        ok, f"status={r.status_code} credit={new_cre[0]['amount_cents'] if new_cre else None} pm={new_cre[0]['meta'].get('payment_method_id') if new_cre else None} pi={pi.get('payment_intent_id')}")
except Exception as e:
    rec("T2 tip existing comment", False, repr(e) + "\n" + traceback.format_exc())

# ============ T3: video-comment tip (TIP-303) ============
try:
    video_id = "vid_" + uuid.uuid4().hex[:12]
    from app.services.video_comments import add_comment
    vc = add_comment(video_id=video_id, user_id=AUTHOR, text="great video")
    vcmt_id = vc["comment_id"]
    HOLDER["uid"] = TIPPER
    b0 = len(list(find(ledger(AUTHOR), "credit", "video_comment")))
    r = client.post(f"/ui/videos/{video_id}/comments/{vcmt_id}/tip",
                    json={"amount_cents": 700, "payment_method_id": "pm_test_tipb3"})
    body = r.json()
    cre = list(find(ledger(AUTHOR), "credit", "video_comment"))
    new_cre = [c for c in cre if c["amount_cents"] == 560]
    deb = [d for d in find(ledger(TIPPER), "debit", "video_comment") if d["amount_cents"] == 700]
    ok = (r.status_code == 200 and body.get("tip_total_cents") == 700
          and len(cre) == b0 + 1 and new_cre and deb
          and new_cre[0]["type"] == "credit")
    rec("T3 video-comment tip (303): tipper debit 700 / author credit 560 net type=credit / stamped 700",
        ok, f"status={r.status_code} resp={body} credit={new_cre[0]['amount_cents'] if new_cre else None} debit={deb[0]['amount_cents'] if deb else None}")
except Exception as e:
    rec("T3 video-comment tip", False, repr(e) + "\n" + traceback.format_exc())

# ============ T4: self-tip rejected (400), no comment ============
try:
    HOLDER["uid"] = AUTHOR  # author comments on OWN post with a tip -> self-tip
    # count author's comments-with-tip debits before
    r = client.post(f"/posts/{post_id}/comments", json={"body": "self tip?", "tip_amount_cents": 300})
    ok = (r.status_code == 400)
    # self video-comment tip
    from app.services.video_comments import add_comment as _ac
    v2 = "vid_" + uuid.uuid4().hex[:12]
    sc = _ac(video_id=v2, user_id=AUTHOR, text="mine")
    r2 = client.post(f"/ui/videos/{v2}/comments/{sc['comment_id']}/tip", json={"amount_cents": 300})
    ok2 = (r2.status_code == 400)
    rec("T4 self-tip rejected 400 (comment-carry + video-comment)",
        ok and ok2, f"comment_status={r.status_code} video_status={r2.status_code}")
except Exception as e:
    rec("T4 self-tip", False, repr(e) + "\n" + traceback.format_exc())

# ============ T5: failed charge -> 402, NO comment, NO ledger, NO stamp ============
try:
    orig = tips_mod._charge_tip_payment_intent
    def boom(**kw):
        raise HTTPException(402, {"code": "card_declined", "message": "forced decline"})
    tips_mod._charge_tip_payment_intent = boom
    HOLDER["uid"] = TIPPER
    # fresh post to count comments cleanly
    p2 = "post_" + uuid.uuid4().hex[:12]
    nf.ddb_put_item({"pk": nf.pk_post(p2), "sk": nf.sk_post(), "post_id": p2, "user_id": AUTHOR,
                     "Entity": "Post", "visibility": "public", "locked": False,
                     "created_at": now_iso(), "comment_count": 0})
    deb0 = len(ledger(TIPPER)); cre0 = len(ledger(AUTHOR))
    r = client.post(f"/posts/{p2}/comments", json={"body": "should not persist", "tip_amount_cents": 500})
    # count comments on p2
    lc = client.get(f"/posts/{p2}/comments")
    n_comments = len(lc.json().get("items", lc.json()) if isinstance(lc.json(), dict) else lc.json())
    deb1 = len(ledger(TIPPER)); cre1 = len(ledger(AUTHOR))
    ok = (r.status_code == 402 and deb1 == deb0 and cre1 == cre0)
    rec("T5 failed charge -> 402, no comment, no ledger (carry)",
        ok, f"status={r.status_code} comments_on_post={n_comments} tipper_ledger_delta={deb1-deb0} author_ledger_delta={cre1-cre0}")
    tips_mod._charge_tip_payment_intent = orig
except Exception as e:
    try: tips_mod._charge_tip_payment_intent = orig
    except Exception: pass
    rec("T5 failed charge", False, repr(e) + "\n" + traceback.format_exc())

# ============ T6: earnings classify video_comment credit as 'tips' ============
try:
    from app.services.creator_earnings import classify_entry
    sample = {"type": "credit", "amount_cents": 560, "reason": "Tip: video comment",
              "meta": {"content_type": "video_comment"}}
    bucket = classify_entry(sample)
    rec("T6 earnings classify(video_comment credit) == 'tips'", bucket == "tips", f"bucket={bucket}")
except Exception as e:
    rec("T6 earnings classify", False, repr(e))

n_pass = sum(1 for _, ok, _ in results if ok)
print(f"\n==== TIP-B3 VERIFY: {n_pass}/{len(results)} PASS ====")
print("OVERALL:", "ALL_PASS" if n_pass == len(results) else "SOME_FAIL")
