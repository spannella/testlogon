import sys, os, uuid, time, traceback
sys.path.insert(0, "/home/ubuntu/testlogon")
os.environ.setdefault("PYTHONPATH", "/home/ubuntu/testlogon")
from boto3.dynamodb.conditions import Key
from app.core.tables import T
import app.services.shipment_tracking as st
import app.services.seller_ship_groups as ssg
import app.services.alerts as alerts
import app.services.push as push

PASS=[]; FAIL=[]
def ok(c,m):
    (PASS if c else FAIL).append(m); print(("PASS " if c else "FAIL ")+m)

SUF = uuid.uuid4().hex[:8]
SELLER = f"seller.{SUF}@verify.example"
BUYER1 = f"buyer1.{SUF}@verify.example"
BUYER2 = f"buyer2.{SUF}@verify.example"

# ============ D4.A carrier-detect matrix + tracking URL ============
print("\n===== D4.A carrier detect =====")
MATRIX = [
    ("1Z999AA10123456784", "UPS", "ups.com"),
    ("9400111899223817200000", "USPS", "usps.com"),      # 22-digit 9400
    ("9405511899223817200000", "USPS", "usps.com"),      # 22-digit 9405
    ("EA123456785US", "USPS", "usps.com"),               # intl EA..US
    ("123456789012", "FedEx", "fedex.com"),              # 12-digit
    ("123456789012345", "FedEx", "fedex.com"),           # 15-digit
    ("1234567890", "DHL", "dhl.com"),                     # 10-digit
    ("12345678901", "DHL", "dhl.com"),                    # 11-digit
    ("not-a-real-number", "unknown", ""),
]
for tn, want, urlfrag in MATRIX:
    got = st.detect_carrier(tn)
    url = st.tracking_url(got, tn)
    url_ok = (urlfrag == "" and url == "") or (urlfrag and urlfrag in url and tn.replace("-","").upper() in url.upper())
    ok(got == want, f"D4.A detect {tn} -> {got} (want {want})")
    ok(bool(url_ok), f"D4.A url  {tn} -> {url or '(none)'}")

# ============ D4.B create tracking on SHIP ============
print("\n===== D4.B create-on-ship =====")
def make_sg(sg_id, buyer, name="Blue Widget"):
    row = {
        "seller_id": SELLER, "ship_group_id": sg_id, "order_id": f"ord_{sg_id}",
        "buyer_id": buyer, "buyer_name": "Buyer", "buyer_email": "b@x.com",
        "ship_to": {"city": "Denver"},
        "line_items": [{"item_id":"i1","name":name,"quantity":1,"unit_price_cents":1999,"line_total_cents":1999}],
        "item_count": 1, "subtotal_cents": 1999, "currency": "USD",
        "status": "approved", "created_at": int(time.time()), "updated_at": int(time.time()),
    }
    T.seller_ship_groups.put_item(Item=row)

SG1 = f"sgd4a_{SUF}"   # simulate path
SG2 = f"sgd4b_{SUF}"   # webhook path
make_sg(SG1, BUYER1)
make_sg(SG2, BUYER2)

def ship(sg, tracking, carrier):
    cur = "approved"
    for t in ["allocated","picking","packed"]:
        try: ssg.transition(SELLER, sg, t, actor=SELLER); cur=t
        except Exception as e: print("  chain note", cur, "->", t, type(e).__name__)
    return ssg.transition(SELLER, sg, "shipped", actor=SELLER, tracking_number=tracking, carrier=carrier)

# capture pushes (monkeypatch the module symbol that _notify_buyer imports lazily)
_pushed=[]; _orig = push.send_push_for_alert
def _cap(user_sub, alert_type, title, body, alert_id, action_url=None):
    _pushed.append({"user":user_sub,"type":alert_type,"title":title,"url":action_url}); return None
push.send_push_for_alert = _cap

try:
    ship(SG1, "1Z999AA10123456784", "UPS")   # UPS number
    rec1 = st.get_tracking(SG1)
    ok(rec1 is not None, "D4.B tracking record created on ship (SG1)")
    if rec1:
        ok(rec1.get("carrier")=="UPS", f"D4.B carrier detected from # == UPS ({rec1.get('carrier')})")
        ok(rec1.get("status")=="label_created", f"D4.B initial status label_created ({rec1.get('status')})")
        ok(len(rec1.get("events",[]))==1, f"D4.B one initial event ({len(rec1.get('events',[]))})")
        ok(st.get_by_tracking_number("1Z999AA10123456784") is not None, "D4.B GSI lookup by tracking# works")
except Exception:
    traceback.print_exc(); FAIL.append("D4.B crashed")

# ============ D4.C simulate driver + idempotent buyer pushes ============
print("\n===== D4.C simulate progression + pushes =====")
try:
    def npush(t, who): return len([p for p in _pushed if p["type"]==t and p["user"]==who])
    # label_created -> in_transit (NO push)
    r = st.simulate_step(SG1)
    ok(r.get("status")=="in_transit", f"D4.C step1 -> in_transit ({r.get('status')})")
    ok(npush("order_out_for_delivery",BUYER1)==0 and npush("order_delivered",BUYER1)==0, "D4.C no delivery push at in_transit")
    # in_transit -> out_for_delivery (ONE ofd push)
    r = st.simulate_step(SG1)
    ok(r.get("status")=="out_for_delivery", f"D4.C step2 -> out_for_delivery ({r.get('status')})")
    ok(npush("order_out_for_delivery",BUYER1)==1, f"D4.C ONE out_for_delivery push to buyer ({npush('order_out_for_delivery',BUYER1)})")
    # out_for_delivery -> delivered (ONE delivered push)
    r = st.simulate_step(SG1)
    ok(r.get("status")=="delivered", f"D4.C step3 -> delivered ({r.get('status')})")
    ok(npush("order_delivered",BUYER1)==1, f"D4.C ONE delivered push to buyer ({npush('order_delivered',BUYER1)})")
    # simulate again = no-op (terminal), no extra push
    r = st.simulate_step(SG1)
    ok(r.get("status")=="delivered", "D4.C simulate past delivered is a no-op")
    # IDEMPOTENT replay of the same statuses -> NO duplicate push
    st.advance(ship_group_id=SG1, status="out_for_delivery", source="replay")
    st.advance(ship_group_id=SG1, status="delivered", source="replay")
    ok(npush("order_out_for_delivery",BUYER1)==1 and npush("order_delivered",BUYER1)==1,
       f"D4.C idempotent: replay fires NO duplicate push (ofd={npush('order_out_for_delivery',BUYER1)} del={npush('order_delivered',BUYER1)})")
    # alert rows written to the buyer
    al = T.alerts.query(KeyConditionExpression=Key("user_sub").eq(BUYER1)).get("Items",[])
    ofd_alerts = [a for a in al if a.get("event")=="order_out_for_delivery"]
    del_alerts = [a for a in al if a.get("event")=="order_delivered"]
    ok(len(ofd_alerts)==1, f"D4.C exactly ONE order_out_for_delivery alert row ({len(ofd_alerts)})")
    ok(len(del_alerts)==1, f"D4.C exactly ONE order_delivered alert row ({len(del_alerts)})")
    if del_alerts:
        au = del_alerts[0].get("action_url","")
        ok(("ship_group=" in au) and ("track=1" in au), f"D4.C alert deep-links to buyer tracking view ({au})")
except Exception:
    traceback.print_exc(); FAIL.append("D4.C crashed")

# ============ D4.D webhook ingestion seam advances + pushes ============
print("\n===== D4.D webhook ingestion =====")
try:
    ship(SG2, "9400111899223817200000", "USPS")   # USPS number
    rec2 = st.get_tracking(SG2)
    ok(rec2 and rec2.get("carrier")=="USPS", f"D4.D SG2 tracking carrier USPS ({rec2 and rec2.get('carrier')})")
    def npush2(t): return len([p for p in _pushed if p["type"]==t and p["user"]==BUYER2])
    # webhook: external 'InTransit' vocab
    r = st.ingest_webhook({"tracking_number":"9400111899223817200000","status":"InTransit","location":"Denver, CO"})
    ok(r.get("ok") and r.get("status")=="in_transit", f"D4.D webhook InTransit -> in_transit ({r})")
    # webhook: out for delivery -> ONE push
    r = st.ingest_webhook({"tracking_number":"9400111899223817200000","status":"out for delivery"})
    ok(r.get("status")=="out_for_delivery", f"D4.D webhook -> out_for_delivery ({r.get('status')})")
    ok(npush2("order_out_for_delivery")==1, f"D4.D webhook ONE out_for_delivery push ({npush2('order_out_for_delivery')})")
    # webhook: Delivered -> ONE push
    r = st.ingest_webhook({"tracking_number":"9400111899223817200000","status":"Delivered"})
    ok(r.get("status")=="delivered", f"D4.D webhook -> delivered ({r.get('status')})")
    ok(npush2("order_delivered")==1, f"D4.D webhook ONE delivered push ({npush2('order_delivered')})")
    # webhook replay Delivered -> NO dup push
    st.ingest_webhook({"tracking_number":"9400111899223817200000","status":"Delivered"})
    ok(npush2("order_delivered")==1, f"D4.D webhook idempotent replay -> no dup push ({npush2('order_delivered')})")
    # unknown tracking number -> not found
    r = st.ingest_webhook({"tracking_number":"000notreal000","status":"delivered"})
    ok(r.get("ok") is False and r.get("reason")=="tracking_not_found", "D4.D webhook unknown tracking -> not_found")
    # poller stub
    pr = st.poll_tracking("9400111899223817200000")
    ok(pr.get("ok") and pr.get("status")=="delivered" and pr.get("tracking_url"), f"D4.D poller stub returns record+url")
except Exception:
    traceback.print_exc(); FAIL.append("D4.D crashed")

push.send_push_for_alert = _orig

# ============ D4.E events registered / default-ON gate ============
print("\n===== D4.E registration + default-ON =====")
for ev in ("order_out_for_delivery","order_delivered"):
    ok(ev in alerts.ALERT_EVENT_TYPES, f"D4.E {ev} in ALERT_EVENT_TYPES")
    ok(ev in alerts.DEFAULT_PUSH_EVENT_TYPES, f"D4.E {ev} in DEFAULT_PUSH_EVENT_TYPES (default-ON)")
prefs = alerts.get_alert_prefs(BUYER1)
enabled = set(prefs.get("push_event_types") or []) | (set(alerts.DEFAULT_PUSH_EVENT_TYPES) - set(prefs.get("push_opt_out_event_types") or []))
ok("order_out_for_delivery" in enabled and "order_delivered" in enabled, "D4.E default (no prefs) => both delivery pushes ENABLED (opt-out model)")

# ============ D4.F buyer tracking view (router-level) ============
print("\n===== D4.F buyer tracking view =====")
try:
    import asyncio
    from app.routers import shipment_tracking as strouter
    ctxB1 = {"user_sub": BUYER1, "role": "user"}
    ctxOther = {"user_sub": "someone.else@x.com", "role": "user"}
    view = asyncio.get_event_loop().run_until_complete(strouter.buyer_tracking_view(SG1, ctx=ctxB1))
    ok(view.ship_group_id==SG1 and view.carrier=="UPS" and view.status=="delivered", f"D4.F buyer sees own tracking (status={view.status}, carrier={view.carrier})")
    ok(view.tracking_url and "ups.com" in view.tracking_url, f"D4.F view carries carrier tracking URL ({view.tracking_url})")
    ok(len(view.events) >= 4, f"D4.F event history rendered ({len(view.events)} events)")
    denied=False
    try:
        asyncio.get_event_loop().run_until_complete(strouter.buyer_tracking_view(SG1, ctx=ctxOther))
    except Exception as e:
        denied = getattr(e,"status_code",None)==404
    ok(denied, "D4.F a non-buyer gets 404 on the tracking view (scoped)")
except Exception:
    traceback.print_exc(); FAIL.append("D4.F crashed")

print(f"\n===== SUMMARY: {len(PASS)} PASS / {len(FAIL)} FAIL =====")
if FAIL:
    for f in FAIL: print("  FAILED:", f)
    print("OVERALL FAIL")
else:
    print("OVERALL ALL_PASS")
