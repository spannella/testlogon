"""E0 LIVE verify: synthetic seller + seeded ship-group -> HTTP /ui/seller/sales."""
import base64, hashlib, os, time, json, sys
import urllib.request, urllib.error
from http.cookiejar import CookieJar

sys.path.insert(0, "/home/ubuntu/testlogon")
os.environ.setdefault("DEV_MODE", "1")
from app.core.tables import T
from app.services import seller_ship_groups as ssg

BASE = "http://127.0.0.1:8000"
STAMP = int(time.time())
SELLER = "e0seller+%d@ecomx.test" % STAMP
BUYER  = "e0buyer+%d@ecomx.test" % STAMP
PW = "E0-Verify-Pw-%d" % STAMP
ORDER_ID = "E0ORD-%d" % STAMP
results = []
created_users = []
created_groups = []

def mkuser(sub):
    salt = os.urandom(16); iters = 200000
    h = hashlib.pbkdf2_hmac("sha256", PW.encode(), salt, iters)
    T.users.put_item(Item={
        "user_sub": sub, "email": sub, "display_name": sub.split("@")[0],
        "password_hash": {"hash_b64": base64.b64encode(h).decode(),
                          "salt_b64": base64.b64encode(salt).decode(), "iterations": iters},
        "role": "user", "created_at": STAMP, "_ecomx_e0_synth": True})
    created_users.append(sub)

def csrf_of(cj):
    for c in cj:
        if c.name == "ui_csrf":
            return c.value
    return ""

def http(method, path, cj, body=None, extra_headers=None):
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json"}
    if extra_headers: hdrs.update(extra_headers)
    req = urllib.request.Request(BASE+path, data=data, method=method, headers=hdrs)
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    try:
        r = op.open(req, timeout=15)
        return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try: payload = json.loads(e.read().decode() or "{}")
        except Exception: payload = {}
        return e.status, payload

def login(sub):
    cj = CookieJar()
    st, resp = http("POST", "/ui/session/start", cj,
                    {"challenge_context": {"username": sub, "password": PW}})
    return cj, st, resp

try:
    mkuser(SELLER); mkuser(BUYER)
    sg_id = hashlib.sha1(("%s#%s" % (ORDER_ID, SELLER)).encode()).hexdigest()
    now = int(time.time())
    T.seller_ship_groups.put_item(Item={
        "seller_id": SELLER, "ship_group_id": sg_id, "order_id": ORDER_ID,
        "status": "approved", "buyer_name": "E0 Buyer", "buyer_email": BUYER,
        "ship_to": {"line1": "1 Test Way", "city": "Testville", "region": "CA",
                    "postal_code": "90001", "country": "US"},
        "line_items": [{"item_id": "sku-e0", "sku": "sku-e0", "name": "E0 Widget",
                        "quantity": 2, "unit_price_cents": 500, "line_total_cents": 1000}],
        "item_count": 2, "subtotal_cents": 1000, "currency": "USD",
        "created_at": now, "updated_at": now, "_ecomx_e0_synth": True})
    created_groups.append((SELLER, sg_id))

    rows, _ = ssg.list_for_seller(SELLER)
    results.append(("svc.list_for_seller sees seeded group",
                    any(r.get("ship_group_id") == sg_id for r in rows)))

    cj, st, resp = login(SELLER)
    results.append(("HTTP login seller 200 + no MFA", st == 200 and resp.get("auth_required") is False))

    st, resp = http("GET", "/ui/seller/sales", cj)
    sales = None
    if isinstance(resp, list): sales = resp
    elif isinstance(resp, dict):
        for k in ("sales", "items", "ship_groups", "results", "groups"):
            if isinstance(resp.get(k), list): sales = resp[k]; break
    found = isinstance(sales, list) and any(s.get("ship_group_id") == sg_id for s in sales)
    results.append(("HTTP GET /ui/seller/sales 200", st == 200))
    results.append(("HTTP /ui/seller/sales returns seller's real sold group", found))
    if st == 200 and not found:
        print("DEBUG list resp:", json.dumps(resp)[:600])

    st, resp = http("GET", "/ui/seller/sales/%s" % sg_id, cj)
    results.append(("HTTP GET /ui/seller/sales/{sg} detail matches",
                    st == 200 and resp.get("ship_group_id") == sg_id and resp.get("order_id") == ORDER_ID))
    results.append(("  detail carries buyer ship_to", bool((resp or {}).get("ship_to"))))
    results.append(("  detail carries real line name 'E0 Widget'",
                    any(li.get("name") == "E0 Widget" for li in (resp or {}).get("line_items", []))))

    st, resp = http("POST", "/ui/seller/sales/%s/transition" % sg_id, cj, {"target_status": "allocated"}, {"x-csrf-token": csrf_of(cj)})
    if st != 200:
        st, resp = http("POST", "/ui/seller/sales/%s/transition" % sg_id, cj, {"target_status": "allocated"}, {"x-csrf-token": csrf_of(cj)})
    if st != 200:
        print("DEBUG transition resp:", st, json.dumps(resp)[:400])
    results.append(("HTTP POST seller transition -> allocated 200 (non-admin seller)",
                    st == 200 and (resp or {}).get("status") == "allocated"))

    cj2, st2, _ = login(BUYER)
    st, resp = http("GET", "/ui/seller/sales/%s" % sg_id, cj2)
    results.append(("HTTP other user GETs foreign group -> 404 (scoped)", st == 404))
finally:
    for (sid, gid) in created_groups:
        try: T.seller_ship_groups.delete_item(Key={"seller_id": sid, "ship_group_id": gid})
        except Exception as e: print("cleanup grp err", e)
    for sub in created_users:
        try: T.users.delete_item(Key={"user_sub": sub})
        except Exception as e: print("cleanup user err", e)

print("\n=== E0 LIVE SELLER-SALES VERIFY MATRIX ===")
allok = True
for name, ok in results:
    print(("PASS" if ok else "FAIL"), "-", name); allok = allok and ok
print("=== RESULT:", "ALL PASS" if allok else "HAS FAILURES", "===")
print("cleanup: removed", len(created_groups), "groups,", len(created_users), "users")
sys.exit(0 if allok else 1)
