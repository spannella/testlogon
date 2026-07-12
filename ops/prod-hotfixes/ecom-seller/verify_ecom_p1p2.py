import os, sys, uuid
os.environ.setdefault("DEV_MODE", "1")
sys.path.insert(0, "/home/ubuntu/testlogon")
from app.core.tables import T
from app.core.settings import S
from app.core.time import now_ts
from app.services.ttl import with_ttl
from app.services import alerts as A
from app.services import push as P

results = []
def chk(name, cond, extra=""):
    results.append((name, bool(cond)))
    print(("PASS" if cond else "FAIL"), "|", name, "|", extra)

def resolve_enabled(prefs):
    explicit = set(prefs.get("push_event_types") or [])
    opted = set(prefs.get("push_opt_out_event_types") or [])
    return explicit | (set(A.DEFAULT_PUSH_EVENT_TYPES) - opted)

print("DEFAULT_PUSH_EVENT_TYPES =", A.DEFAULT_PUSH_EVENT_TYPES)

# ---------- P2: default-ON for a FRESH seller (no prefs set) ----------
uid = "verify_p1p2_" + uuid.uuid4().hex[:8]
prefs = A.get_alert_prefs(uid)
chk("P2 fresh user push_event_types empty", prefs.get("push_event_types") == [], repr(prefs.get("push_event_types")))
chk("P2 fresh user opt_out empty", prefs.get("push_opt_out_event_types") == [], repr(prefs.get("push_opt_out_event_types")))
en = resolve_enabled(prefs)
chk("P2 shop_item_sold DEFAULT-ON for fresh seller", "shop_item_sold" in en, str(sorted(en)))
chk("P2 non-transactional new_follower NOT default-on", "new_follower" not in en)

# ---------- P2: still disable-able (opt-out) ----------
A.set_alert_prefs(uid, push_opt_out_event_types=["shop_item_sold"])
p2 = A.get_alert_prefs(uid)
chk("P2 opt-out persisted", "shop_item_sold" in (p2.get("push_opt_out_event_types") or []), repr(p2.get("push_opt_out_event_types")))
chk("P2 shop_item_sold OFF after opt-out (disable-able)", "shop_item_sold" not in resolve_enabled(p2))
A.set_alert_prefs(uid, push_opt_out_event_types=["new_follower", "shop_item_sold"])
p3 = A.get_alert_prefs(uid)
chk("P2 opt-out filtered to default-on only", set(p3.get("push_opt_out_event_types")) == {"shop_item_sold"}, repr(p3.get("push_opt_out_event_types")))
A.set_alert_prefs(uid, push_opt_out_event_types=[])
chk("P2 re-enabled after clearing opt-out", "shop_item_sold" in resolve_enabled(A.get_alert_prefs(uid)))

# ---------- P1: send_push_for_alert carries action_url in FCM data ----------
captured = {}
def fake_fcm_send(tok, title, body, data=None):
    captured["data"] = data
    return True
orig_fcm = P.fcm_send
P.fcm_send = fake_fcm_send
print("S.push_enabled=", S.push_enabled, "S.fcm_enabled=", S.fcm_enabled)
try:
    S.push_enabled = True; S.fcm_enabled = True
except Exception as e:
    print("NOTE could not override S flags:", e)

def fresh_device():
    u = "vpush_" + uuid.uuid4().hex[:10]
    T.push_devices.put_item(Item=with_ttl({"user_sub": u, "device_id": "d", "token": "t_" + u,
        "platform": "android", "created_at": now_ts(), "last_seen_at": now_ts()}, ttl_epoch=now_ts() + 3600))
    return u

# P1a explicit action_url
captured.clear()
u1 = fresh_device()
au = "/seller/orders?sale=sg_verify_123"
P.send_push_for_alert(u1, "shop_item_sold", "You sold X", "body", "aid_x", action_url=au)
chk("P1 FCM data carries EXPLICIT action_url", (captured.get("data") or {}).get("action_url") == au, repr(captured.get("data")))

# P1b generic — no action_url arg; resolve from the persisted alert row
captured.clear()
u2 = fresh_device()
wr = A.write_alert(u2, event="shop_item_sold", outcome="success", title="You sold Y",
                   details={"alert_type": "shop_item_sold"}, action_url="/seller/orders?sale=sg_generic_456")
aid = (wr or {}).get("alert_id", "")
P.send_push_for_alert(u2, "shop_item_sold", "You sold Y", "body", aid)
chk("P1 GENERIC: action_url resolved from alert row -> FCM data",
    (captured.get("data") or {}).get("action_url") == "/seller/orders?sale=sg_generic_456", repr(captured.get("data")))

# P1+P2 fresh seller with NO prefs still FIRES (default-on) with the deep-link
captured.clear()
u3 = fresh_device()
P.send_push_for_alert(u3, "shop_item_sold", "You sold Z", "b", "", action_url="/seller/orders?sale=sg_z")
chk("P1+P2 fresh seller (no manual enable) push FIRES with action_url",
    (captured.get("data") or {}).get("action_url") == "/seller/orders?sale=sg_z", repr(captured.get("data")))

# contrast: a non-default opt-in event does NOT fire for a fresh user
captured.clear()
u4 = fresh_device()
P.send_push_for_alert(u4, "new_follower", "New follower", "b", "f1", action_url="/followers")
chk("P2 non-default event does NOT fire for fresh user (stays opt-in)", captured.get("data") is None, repr(captured.get("data")))

# opted-out seller does NOT fire even though default-on
captured.clear()
u5 = fresh_device()
A.set_alert_prefs(u5, push_opt_out_event_types=["shop_item_sold"])
P.send_push_for_alert(u5, "shop_item_sold", "You sold", "b", "", action_url="/seller/orders?sale=sg_q")
chk("P2 opted-out seller does NOT receive shop_item_sold push", captured.get("data") is None, repr(captured.get("data")))

P.fcm_send = orig_fcm
np = sum(1 for _, c in results if c)
print(f"OVERALL {np}/{len(results)}", "ALL_PASS" if np == len(results) else "SOME_FAIL")
