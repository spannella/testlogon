#!/usr/bin/env python3
"""TIPX-E verifier — notify_tip choke point + reversal notifications.

Runs in-process against the dev-clone DDB-Local (via .env.local). Pattern-tags
every synthetic user with the run tag so cleanup is exact (0 residue). Proves:

  E1: notify_tip emits a RECIPIENT alert (into T.alerts, the app store) with the
      right action_url per surface + a TIPPER receipt (tip_sent), for EVERY
      surface (post/comment/message/message_react/video/video_comment/broadcast/
      profile) — no silent surface, no dead-link.
  E3: notify_tip_reversed emits tip_reversed (creator) + tip_refunded (tipper).
  E4/N9: two distinct post tips do NOT collapse (distinct batch_key -> 2 rows).
  Registration: the new events are default-ON push + in the 'activity' category.
"""
import sys, time, uuid

from app.core.tables import T
from app.services.tip_notifications import notify_tip, notify_tip_reversed, _action_url_for
from app.services import alerts as A

TAG = f"tipxE_{int(time.time())}_{uuid.uuid4().hex[:6]}"
PASS, FAIL = [], []


def ok(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name)


def read_alerts(user):
    from boto3.dynamodb.conditions import Key
    items = []
    resp = T.alerts.query(KeyConditionExpression=Key("user_sub").eq(user))
    items.extend(resp.get("Items", []))
    return items


def clean(users):
    for u in users:
        for it in read_alerts(u):
            try:
                T.alerts.delete_item(Key={"user_sub": u, "alert_id": it["alert_id"]})
            except Exception:
                pass


users = set()


def u(role):
    x = f"{TAG}_{role}"
    users.add(x)
    return x


# ------------------------------------------------------------------ action_url
cases = [
    ("post", "P1", {}, "/feed/posts/P1"),
    ("post_react", "P2", {}, "/feed/posts/P2"),
    ("comment", "C1", {"post_id": "P9"}, "/feed/posts/P9"),
    ("message", "M1", {"conversation_id": "CONV7"}, "/messaging/thread/CONV7"),
    ("message_react", "M2", {"conversation_id": "CONV8"}, "/messaging/thread/CONV8"),
    ("video", "V1", {"video_id": "V1"}, "/videos/V1"),
    ("video_comment", "VC1", {"video_id": "V5"}, "/videos/V5"),
    ("broadcast", "B1", {}, "/broadcast/B1"),
    ("profile", "PR1", {}, "/profile/PR1"),
]
for ct, cid, meta, want in cases:
    ok(f"action_url[{ct}]=={want}", _action_url_for(ct, cid, meta) == want)

# ------------------------------------------------------------------ E1 per-surface notify
for ct, cid, meta, want in cases:
    tipper, recip = u(f"tipper_{ct}"), u(f"recip_{ct}")
    notify_tip(
        tipper_id=tipper, recipient_id=recip,
        amount_cents=1000, net_cents=800, fee_cents=200, currency="USD",
        content_type=ct, content_id=cid, tip_payment_id=f"tip_{ct}_{cid}", meta=meta,
    )
    ra = read_alerts(recip)
    ta = read_alerts(tipper)
    recv = [x for x in ra if (x.get("details") or {}).get("kind") == "tip_received"]
    sent = [x for x in ta if x.get("event") == "tip_sent"]
    ok(f"E1[{ct}] recipient alert present", len(recv) == 1)
    ok(f"E1[{ct}] recipient action_url=={want}", bool(recv) and recv[0].get("action_url") == want)
    ok(f"E1[{ct}] recipient amount=1000", bool(recv) and int((recv[0].get('details') or {}).get('amount_cents', 0)) == 1000)
    ok(f"E1[{ct}] tipper receipt present", len(sent) == 1)
    ok(f"E1[{ct}] tipper receipt action_url=={want}", bool(sent) and sent[0].get("action_url") == want)

# self-tip suppression: emit_social_alert drops recipient==actor for social type
selfu = u("self")
notify_tip(tipper_id=selfu, recipient_id=selfu, amount_cents=500, net_cents=400,
           fee_cents=100, currency="USD", content_type="post", content_id="PS",
           tip_payment_id="tip_self", meta={})
sa = read_alerts(selfu)
# The recipient (post_tip social) is self-suppressed; the tipper receipt (write_alert) still writes.
selfrecv = [x for x in sa if (x.get("details") or {}).get("kind") == "tip_received"]
ok("E1 self recipient alert suppressed", len(selfrecv) == 0)

# ------------------------------------------------------------------ E4/N9 no-collapse (two post tips, distinct txn)
t9, r9 = u("t9"), u("r9")
notify_tip(tipper_id=t9, recipient_id=r9, amount_cents=1000, net_cents=800, fee_cents=200,
           currency="USD", content_type="post", content_id="PX", tip_payment_id="tip_A", meta={})
notify_tip(tipper_id=t9, recipient_id=r9, amount_cents=2000, net_cents=1600, fee_cents=400,
           currency="USD", content_type="post", content_id="PX", tip_payment_id="tip_B", meta={})
r9a = [x for x in read_alerts(r9) if (x.get("details") or {}).get("kind") == "tip_received"]
ok("E4/N9 two distinct post tips do NOT collapse", len(r9a) == 2)

# ------------------------------------------------------------------ E3 reversal notifications
tr, rr = u("tr"), u("rr")
notify_tip_reversed(tipper_id=tr, recipient_id=rr, gross_cents=1000, net_cents=800,
                    currency="USD", content_type="post", content_id="PZ",
                    tip_payment_id="tip_rev", reason="admin_reversal")
rev = [x for x in read_alerts(rr) if x.get("event") == "tip_reversed"]
ref = [x for x in read_alerts(tr) if x.get("event") == "tip_refunded"]
ok("E3 creator tip_reversed alert present", len(rev) == 1)
ok("E3 creator reversed amount=net 800", bool(rev) and int((rev[0].get('details') or {}).get('amount_cents', 0)) == 800)
ok("E3 tipper tip_refunded alert present", len(ref) == 1)
ok("E3 tipper refunded amount=gross 1000", bool(ref) and int((ref[0].get('details') or {}).get('amount_cents', 0)) == 1000)

# ------------------------------------------------------------------ registration
for ev in ("tip_received", "tip_sent", "tip_reversed", "tip_refunded"):
    ok(f"reg[{ev}] in ALERT_EVENT_TYPES", ev in A.ALERT_EVENT_TYPES)
    ok(f"reg[{ev}] default-ON push", ev in A.DEFAULT_PUSH_EVENT_TYPES)
    ok(f"reg[{ev}] category=activity/security!=security", A.get_alert_category(ev) == "activity")

# ------------------------------------------------------------------ cleanup
clean(users)
residue = sum(len(read_alerts(x)) for x in users)
ok("cleanup 0 residue", residue == 0)

print(f"\n==== TIPX-E: {len(PASS)} PASS / {len(FAIL)} FAIL ====")
if FAIL:
    print("FAILURES:", FAIL)
    sys.exit(1)
