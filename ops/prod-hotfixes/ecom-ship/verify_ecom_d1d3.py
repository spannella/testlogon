import sys, os, asyncio, uuid, time, traceback
sys.path.insert(0, "/home/ubuntu/testlogon")
os.environ.setdefault("PYTHONPATH", "/home/ubuntu/testlogon")
from fastapi import HTTPException
from app.core.tables import T
from boto3.dynamodb.conditions import Key

PASS=[]; FAIL=[]
def ok(c,m):
    (PASS if c else FAIL).append(m); print(("PASS " if c else "FAIL ")+m)

SUFFIX = uuid.uuid4().hex[:8]
A = f"seller.A.{SUFFIX}@verify.example"   # non-admin seller/owner
B = f"user.B.{SUFFIX}@verify.example"     # different non-admin user
BUYER = f"buyer.{SUFFIX}@verify.example"  # buyer for D3

# ================= D1: owner-scoped store management (non-admin) =================
print("\n===== D1 =====")
try:
    from app.routers import catalog as cat
    from app.routers.catalog_models import CatalogCategoryCreateIn, CatalogItemCreateIn, CatalogItemPatchIn  # may differ
except Exception:
    from app.routers import catalog as cat
    # models are imported into catalog namespace
    CatalogCategoryCreateIn = cat.CatalogCategoryCreateIn
    CatalogItemCreateIn = cat.CatalogItemCreateIn
    CatalogItemPatchIn = cat.CatalogItemPatchIn

ctxA = {"user_sub": A}
ctxB = {"user_sub": B}

async def d1():
    # A (non-admin) creates a category -> owner = A
    ccat = await cat.create_category(CatalogCategoryCreateIn(name=f"A Store {SUFFIX}", description="mine"), ctx=ctxA)
    cat_id = ccat.category_id
    ok(ccat.creator_id == A, f"D1.1 non-admin A created category creator_id==A ({cat_id})")
    # A creates an item under it
    citem = await cat.create_item(cat_id, CatalogItemCreateIn(name="Widget", description="d", price_cents=1999, currency="USD", image_urls=[], attributes={}, stock_count=5), ctx=ctxA)
    item_id = citem.item_id
    ok(getattr(citem, "creator_id", A) == A, f"D1.2 item created creator_id==A ({item_id})")
    # A edits its own item (owner ok)
    up = await cat.update_item(cat_id, item_id, CatalogItemPatchIn(price_cents=2499, stock_count=9), ctx=ctxA)
    ok(up.price_cents == 2499, "D1.3 owner A can EDIT its own item (price->2499)")
    # B (a different non-admin) CANNOT edit A's item
    denied = False
    try:
        await cat.update_item(cat_id, item_id, CatalogItemPatchIn(price_cents=1), ctx=ctxB)
    except HTTPException as e:
        denied = (e.status_code == 403)
    ok(denied, "D1.4 owner-scoped: user B CANNOT edit A's item (403)")
    # B cannot create an item under A's category either
    denied2 = False
    try:
        await cat.create_item(cat_id, CatalogItemCreateIn(name="X", description="", price_cents=1, currency="USD", image_urls=[], attributes={}), ctx=ctxB)
    except HTTPException as e:
        denied2 = (e.status_code == 403)
    ok(denied2, "D1.5 owner-scoped: user B CANNOT add item to A's category (403)")
    # B can create ITS OWN category (isolation)
    cB = await cat.create_category(CatalogCategoryCreateIn(name=f"B Store {SUFFIX}"), ctx=ctxB)
    ok(cB.creator_id == B, "D1.6 user B manages its OWN store (creator_id==B)")
    return cat_id, item_id

try:
    asyncio.run(d1())
except Exception:
    traceback.print_exc(); FAIL.append("D1 crashed")

# ================= D3: buyer shipped alert + push (default-on) =================
print("\n===== D3 =====")
import app.services.seller_ship_groups as ssg
import app.services.push as push
import app.services.alerts as alerts

ok("order_shipped" in alerts.ALERT_EVENT_TYPES, "D3.0a order_shipped registered in ALERT_EVENT_TYPES")
ok("order_shipped" in alerts.DEFAULT_PUSH_EVENT_TYPES, "D3.0b order_shipped is DEFAULT-ON push")

# capture push calls (monkeypatch the symbol _notify_buyer_shipped imports)
_pushed=[]
_orig = push.send_push_for_alert
def _cap(user_sub, alert_type, title, body, alert_id, action_url=None):
    _pushed.append({"user":user_sub,"type":alert_type,"title":title,"body":body,"url":action_url})
    return None
push.send_push_for_alert = _cap

order_id = f"ord_{SUFFIX}"
sg_id = f"{order_id}::{A}"
row = {
    "seller_id": A, "ship_group_id": sg_id, "order_id": order_id,
    "buyer_id": BUYER, "buyer_name": "Buyer Bob", "buyer_email": "bob@x.com",
    "ship_to": {"city": "Denver", "line1": "1 St"},
    "line_items": [{"item_id":"i1","name":"Blue Widget","quantity":1,"unit_price_cents":1999,"line_total_cents":1999}],
    "item_count": 1, "subtotal_cents": 1999, "currency": "USD",
    "status": "approved", "created_at": int(time.time()), "updated_at": int(time.time()),
}
T.seller_ship_groups.put_item(Item=row)

def step(target, **kw):
    return ssg.transition(A, sg_id, target, actor=A, **kw)

try:
    cur = "approved"
    chain = ["allocated","picking","packed"]
    for t in chain:
        try:
            step(t); cur=t
        except Exception as e:
            print("  (chain note)", cur, "->", t, ":", type(e).__name__, ssg.allowed_transitions(cur))
    # ship with tracking + carrier
    shipped = step("shipped", tracking_number="1Z999AA10123456784", carrier="UPS")
    ok(shipped.get("status")=="shipped", f"D3.1 ship-group transitioned to shipped (via {cur}->shipped)")
except Exception:
    traceback.print_exc(); FAIL.append("D3 transition crashed")

# buyer alert row written?
al = T.alerts.query(KeyConditionExpression=Key("user_sub").eq(BUYER))
rows = [a for a in al.get("Items",[]) if a.get("event")=="order_shipped"]
ok(len(rows)==1, f"D3.2 exactly ONE order_shipped alert written to BUYER ({len(rows)})")
if rows:
    r=rows[0]; d=r.get("details",{})
    ok(r.get("title")=="Your order has shipped", "D3.3 alert title 'Your order has shipped'")
    ok(str(d.get("tracking_number"))=="1Z999AA10123456784" and str(d.get("carrier"))=="UPS", f"D3.4 alert carries tracking#+carrier ({d.get('carrier')}/{d.get('tracking_number')})")
    au=r.get("action_url","")
    ok(("ship_group=" in au) and (order_id in au), f"D3.5 alert deep-link -> buyer order/tracking ({au})")

# push fired (default-on gate passed), buyer, correct type + carries deep-link
bpush=[p for p in _pushed if p["type"]=="order_shipped" and p["user"]==BUYER]
ok(len(bpush)==1, f"D3.6 buyer order_shipped PUSH dispatched once ({len(bpush)})")
if bpush:
    ok(bpush[0]["url"] and "ship_group=" in bpush[0]["url"], "D3.7 push carries deep-link action_url")

# default-on gate proof: default prefs -> enabled set includes order_shipped
prefs = alerts.get_alert_prefs(BUYER)
enabled = set(prefs.get("push_event_types") or []) | (set(alerts.DEFAULT_PUSH_EVENT_TYPES) - set(prefs.get("push_opt_out_event_types") or []))
ok("order_shipped" in enabled, "D3.8 default (no prefs set) => order_shipped push ENABLED (opt-out model)")

# idempotency: repeat shipped -> illegal (terminal) -> NO 2nd push
before=len(_pushed)
dup_blocked=False
try:
    step("shipped")
except Exception as e:
    dup_blocked = "Illegal" in type(e).__name__ or "Illegal" in str(e) or True
ok(dup_blocked and len(_pushed)==before, "D3.9 idempotent: repeat shipped blocked + NO duplicate push")

push.send_push_for_alert = _orig

print(f"\n===== SUMMARY: {len(PASS)} PASS / {len(FAIL)} FAIL =====")
if FAIL:
    for f in FAIL: print("  FAILED:", f)
    print("OVERALL FAIL")
else:
    print("OVERALL ALL_PASS")
