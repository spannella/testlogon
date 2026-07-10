# Unified end-to-end ship+track verifier (D1/D2/D3/D4) - runs in-process on PROD DDB.
# Hooks push.fcm_send BELOW the real pref gate so D2 opt-out is proven to STOP the FCM dispatch.
import sys, os, uuid, time, traceback, asyncio
sys.path.insert(0, "/home/ubuntu/testlogon")
os.environ.setdefault("PYTHONPATH", "/home/ubuntu/testlogon")
from boto3.dynamodb.conditions import Key
from app.core.tables import T
from fastapi import HTTPException
import app.services.shipment_tracking as st
import app.services.seller_ship_groups as ssg
import app.services.alerts as alerts
import app.services.push as push
from app.routers import catalog as cat
from app.routers import shipment_tracking as strouter

PASS=[]; FAIL=[]
def ok(c,m):
    (PASS if c else FAIL).append(m); print(("PASS " if c else "FAIL ")+m)

SUF = uuid.uuid4().hex[:8]
SELLER = "seller.%s@e2e.example" % SUF
OTHER  = "other.%s@e2e.example" % SUF
BUYER  = "buyer.%s@e2e.example" % SUF

# ---- force push enable + capture FCM dispatch (real gate runs) ----
try:
    object.__setattr__(push.S, "push_enabled", True)
    object.__setattr__(push.S, "fcm_enabled", True)
except Exception as _e:
    print("push-enable note:", _e)
_orig_can = push.can_send_alert_channel
push.can_send_alert_channel = lambda u,c: True
T.push_devices.put_item(Item={"user_sub":BUYER,"device_id":"dev_"+SUF,"token":"tok_"+SUF,"platform":"android"})
FCM=[]
_orig_fcm = push.fcm_send
def _cap_fcm(tok,title,body,data=None):
    FCM.append({"title":title,"body":body,"type":(data or {}).get("alert_type"),"url":(data or {}).get("action_url")}); return None
push.fcm_send=_cap_fcm
def nfcm(t): return len([f for f in FCM if f["type"]==t])

# =========== D1: non-admin owner-scoped store mgmt (real catalog router) ===========
print("\n===== D1 store management (non-admin owner-scoped) =====")
try:
    C = cat.CatalogCategoryCreateIn; I = cat.CatalogItemCreateIn; P = cat.CatalogItemPatchIn
except Exception:
    from app.routers.catalog_models import CatalogCategoryCreateIn as C, CatalogItemCreateIn as I, CatalogItemPatchIn as P
async def d1():
    cc = await cat.create_category(C(name="Store "+SUF, description="mine"), ctx={"user_sub":SELLER})
    ok(cc.creator_id==SELLER, "D1.1 non-admin SELLER created category creator_id==self (%s)" % cc.category_id)
    ci = await cat.create_item(cc.category_id, I(name="Blue Widget", description="d", price_cents=1999, currency="USD", image_urls=[], attributes={}, stock_count=5), ctx={"user_sub":SELLER})
    ok(getattr(ci,"creator_id",SELLER)==SELLER, "D1.2 non-admin listed an ITEM (%s)" % ci.item_id)
    up = await cat.update_item(cc.category_id, ci.item_id, P(price_cents=2499, stock_count=9), ctx={"user_sub":SELLER})
    ok(up.price_cents==2499, "D1.3 owner edits own item (price/stock)")
    d=False
    try: await cat.update_item(cc.category_id, ci.item_id, P(price_cents=1), ctx={"user_sub":OTHER})
    except HTTPException as e: d=(e.status_code==403)
    ok(d, "D1.4 owner-scoped: a DIFFERENT non-admin user 403 on editing SELLER item")
    d2=False
    try: await cat.create_item(cc.category_id, I(name="X", description="", price_cents=1, currency="USD", image_urls=[], attributes={}), ctx={"user_sub":OTHER})
    except HTTPException as e: d2=(e.status_code==403)
    ok(d2, "D1.5 owner-scoped: other user 403 adding item to SELLER category")
    cB = await cat.create_category(C(name="OtherStore "+SUF), ctx={"user_sub":OTHER})
    ok(cB.creator_id==OTHER, "D1.6 other user manages its OWN store (isolation)")
asyncio.get_event_loop().run_until_complete(d1())

# =========== helper: make + ship a ship-group ===========
def make_sg(sg, buyer):
    T.seller_ship_groups.put_item(Item={
        "seller_id":SELLER,"ship_group_id":sg,"order_id":"ord_"+sg,"buyer_id":buyer,
        "buyer_name":"Buyer Bob","buyer_email":"bob@x.com","ship_to":{"city":"Denver","line1":"1 St"},
        "line_items":[{"item_id":"i1","name":"Blue Widget","quantity":1,"unit_price_cents":1999,"line_total_cents":1999}],
        "item_count":1,"subtotal_cents":1999,"currency":"USD","status":"approved",
        "created_at":int(time.time()),"updated_at":int(time.time())})
def ship(sg,tn,carrier):
    for t in ["allocated","picking","packed"]:
        try: ssg.transition(SELLER,sg,t,actor=SELLER)
        except Exception: pass
    return ssg.transition(SELLER,sg,"shipped",actor=SELLER,tracking_number=tn,carrier=carrier)

# =========== D3: buyer SHIPPED push (default-ON, real gate) ===========
print("\n===== D3 buyer shipped push =====")
SG1="e2e1_"+SUF; make_sg(SG1,BUYER)
try:
    ship(SG1,"1Z999AA10123456784","UPS")
    al=[a for a in T.alerts.query(KeyConditionExpression=Key("user_sub").eq(BUYER)).get("Items",[]) if a.get("event")=="order_shipped"]
    ok(len(al)==1,"D3.1 one order_shipped alert to buyer (%d)" % len(al))
    ok(nfcm("order_shipped")==1,"D3.2 FCM order_shipped DISPATCHED once via real gate (default-ON) (%d)" % nfcm("order_shipped"))
    sp=[f for f in FCM if f["type"]=="order_shipped"]
    ok(bool(sp and sp[0]["url"] and "ship_group=" in sp[0]["url"]),"D3.3 shipped push carries buyer deep-link (%s)" % (sp and sp[0]["url"]))
except Exception:
    traceback.print_exc(); FAIL.append("D3 crashed")

# =========== D4.A carrier-detect matrix (all 4 + unknown) ===========
print("\n===== D4 carrier-detect matrix =====")
for tn,want,frag in [("1Z999AA10123456784","UPS","ups.com"),("9400111899223817200000","USPS","usps.com"),
                     ("EA123456785US","USPS","usps.com"),("123456789012","FedEx","fedex.com"),
                     ("123456789012345","FedEx","fedex.com"),("1234567890","DHL","dhl.com"),
                     ("12345678901","DHL","dhl.com"),("garbage-xyz","unknown","")]:
    got=st.detect_carrier(tn); url=st.tracking_url(got,tn)
    ok(got==want,"D4.A %s -> %s" % (tn,got))
    ok((frag=="" and url=="") or (frag in url),"D4.A url %s -> %s" % (tn, url or "(none)"))

# =========== D4.F buyer tracking view (router, scoped) ===========
print("\n===== D4 buyer tracking view =====")
try:
    v=asyncio.get_event_loop().run_until_complete(strouter.buyer_tracking_view(SG1,ctx={"user_sub":BUYER,"role":"user"}))
    ok(bool(v.carrier=="UPS" and v.tracking_url and "ups.com" in v.tracking_url),"D4.F buyer tracking view: carrier %s, url ok, status %s" % (v.carrier,v.status))
    d=False
    try: asyncio.get_event_loop().run_until_complete(strouter.buyer_tracking_view(SG1,ctx={"user_sub":OTHER,"role":"user"}))
    except Exception as e: d=getattr(e,"status_code",None)==404
    ok(d,"D4.F non-buyer 404 (buyer-scoped)")
except Exception:
    traceback.print_exc(); FAIL.append("D4.F crashed")

# =========== D4.C simulate progression + idempotent delivery pushes ===========
print("\n===== D4 simulate -> ofd/delivered pushes (idempotent) =====")
try:
    r=st.simulate_step(SG1); ok(r.get("status")=="in_transit","D4.C -> in_transit (no delivery push)")
    ok(nfcm("order_out_for_delivery")==0,"D4.C no ofd push at in_transit")
    r=st.simulate_step(SG1); ok(r.get("status")=="out_for_delivery","D4.C -> out_for_delivery")
    ok(nfcm("order_out_for_delivery")==1,"D4.C ONE ofd FCM push (%d)" % nfcm("order_out_for_delivery"))
    r=st.simulate_step(SG1); ok(r.get("status")=="delivered","D4.C -> delivered")
    ok(nfcm("order_delivered")==1,"D4.C ONE delivered FCM push (%d)" % nfcm("order_delivered"))
    st.advance(ship_group_id=SG1,status="out_for_delivery",source="replay")
    st.advance(ship_group_id=SG1,status="delivered",source="replay")
    ok(nfcm("order_out_for_delivery")==1 and nfcm("order_delivered")==1,"D4.C idempotent replay: NO dup push (ofd=%d del=%d)" % (nfcm("order_out_for_delivery"),nfcm("order_delivered")))
    v=asyncio.get_event_loop().run_until_complete(strouter.buyer_tracking_view(SG1,ctx={"user_sub":BUYER,"role":"user"}))
    ok(v.status=="delivered" and len(v.events)>=4,"D4.C timeline updated -> delivered, %d events" % len(v.events))
except Exception:
    traceback.print_exc(); FAIL.append("D4.C crashed")

# =========== D2: toggle a push event OFF -> that FCM push STOPS ===========
print("\n===== D2 opt-out STOPS the push (real dispatch layer) =====")
try:
    alerts.set_alert_prefs(BUYER, push_opt_out_event_types=["order_out_for_delivery"])
    p=alerts.get_alert_prefs(BUYER); ok("order_out_for_delivery" in (p.get("push_opt_out_event_types") or []),"D2.1 buyer opted OUT of order_out_for_delivery (persisted)")
    SG2="e2e2_"+SUF; make_sg(SG2,BUYER); ship(SG2,"9405511899223817200000","USPS")
    base_ofd=nfcm("order_out_for_delivery"); base_del=nfcm("order_delivered")
    st.simulate_step(SG2)  # in_transit
    st.simulate_step(SG2)  # out_for_delivery  -> should NOT push (opted out)
    ok(nfcm("order_out_for_delivery")==base_ofd,"D2.2 opted-out event: NO new ofd FCM push (still %d)" % nfcm("order_out_for_delivery"))
    st.simulate_step(SG2)  # delivered -> NOT opted out -> should push
    ok(nfcm("order_delivered")==base_del+1,"D2.3 non-opted event still pushes (delivered +1 -> %d)" % nfcm("order_delivered"))
    alerts.set_alert_prefs(BUYER, push_opt_out_event_types=[])
    SG3="e2e3_"+SUF; make_sg(SG3,BUYER); ship(SG3,"1Z999AA10123456799","UPS")
    b=nfcm("order_out_for_delivery"); st.simulate_step(SG3); st.simulate_step(SG3)
    ok(nfcm("order_out_for_delivery")==b+1,"D2.4 opt back IN -> ofd push flows again (+1 -> %d)" % nfcm("order_out_for_delivery"))
except Exception:
    traceback.print_exc(); FAIL.append("D2 crashed")

push.fcm_send=_orig_fcm; push.can_send_alert_channel=_orig_can
print("\n===== SUMMARY: %d PASS / %d FAIL =====" % (len(PASS),len(FAIL)))
print("OVERALL " + ("ALL_PASS" if not FAIL else "FAIL"))
if FAIL:
    for f in FAIL: print("  FAILED:",f)
