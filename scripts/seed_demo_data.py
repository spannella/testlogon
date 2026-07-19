#!/usr/bin/env python3
"""Seed representative v2-vertical data for the demo walkthrough, owned by `root`.

Run AFTER `just restart`, BEFORE recording the demo. Seeds via the same UI APIs
the E2E specs use (cookie session + CSRF). Idempotent enough: each run appends
TS-suffixed records. Prints per-call status so failures are visible.

Goal: populate EVERY component each demo segment visits so no page shows an
empty state. Covers CRM, ATS, Hotels, OFBiz/ERP, Property, plus the core
content verticals (newsfeed, shop, calendar, ads, banking).
"""
import datetime as _dt
import json
import subprocess
import time
import urllib.error
import urllib.request

BASE = "http://localhost:8000"
TS = int(time.time())


def _load_root_session():
    import os
    _repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    raw = subprocess.check_output(
        ["python3", os.path.join(_repo, "e2e_admin_session_setup.py")],
        cwd=_repo, timeout=60,
    ).decode()
    sess = json.loads(raw[raw.index("{"):])
    s = sess["root"]
    cookie = "; ".join(f"{c['name']}={c['value']}" for c in s["cookies"])
    return cookie, s["csrf_token"]


COOKIE, CSRF = _load_root_session()


def req(method, path, body=None):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Cookie", COOKIE)
    r.add_header("Content-Type", "application/json")
    if method != "GET":
        r.add_header("x-csrf-token", CSRF)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, (e.read().decode()[:200])
    except Exception as e:  # noqa
        return 0, str(e)[:200]


def post(path, body, label, method="POST"):
    st, data = req(method, path, body)
    ok = "ok " if st in (200, 201) else "XX "
    detail = "" if st in (200, 201) else f"  -> {data}"
    print(f"  {ok}{st} {label}{detail}")
    return data if isinstance(data, dict) else {}


def put(path, body, label):
    return post(path, body, label, method="PUT")


def epoch_in(days):
    return TS + days * 86400


def isodate_in(days):
    return _dt.date.fromtimestamp(epoch_in(days)).strftime("%Y-%m-%d")


# ───────────────────────────── CRM (SuiteCRM) ─────────────────────────────
print("== CRM ==")
for fn, ln, co in [("Jordan", "Avery", "Northwind Traders"),
                   ("Riley", "Chen", "Globex"),
                   ("Sam", "Patel", "Initech")]:
    post("/ui/leads", {"first_name": fn, "last_name": ln,
                       "email": f"{fn.lower()}.{TS}@example.com", "company": co,
                       "status": "new"}, f"lead {fn} {ln}")
for nm, amt, stg, pr in [("Northwind — Platform Rollout", 4_500_000, "qualification", 40),
                         ("Globex — Annual Renewal", 1_200_000, "proposal_price_quote", 65),
                         ("Initech — Pilot", 350_000, "prospecting", 15)]:
    post("/ui/sales/opportunities", {"name": nm, "stage": stg,
                                     "amount_cents": amt, "close_date": epoch_in(30),
                                     "probability": pr, "lead_source": "web_site"}, f"opp {nm}")

# Cases (the CRM "cases" page is backed by the ticket system → POST /tickets)
for subj, pr in [("Login issue after password reset", "high"),
                 ("Billing discrepancy on invoice", "medium"),
                 ("Feature request: bulk export", "low")]:
    post("/tickets", {"subject": subj, "description": f"Demo case: {subj}",
                      "priority": pr}, f"case {subj[:24]}")

# Quotes (AOS)
for i in range(2):
    post("/ui/quotes", {"title": f"Q-{TS}-{i+1} Platform License",
                        "valid_until": epoch_in(30), "currency": "usd",
                        "notes": "Demo quote",
                        "line_items": [{"description": "Annual platform license",
                                        "qty": 1, "unit_price_cents": 1_200_000,
                                        "discount_bps": 0, "tax_rate_bps": 1000},
                                       {"description": "Onboarding services",
                                        "qty": 1, "unit_price_cents": 250_000,
                                        "discount_bps": 0, "tax_rate_bps": 0}]},
         f"quote {i+1}")

# CRM Tasks
for subj, pr in [("Call Jordan re: rollout timeline", "high"),
                 ("Send Globex renewal paperwork", "medium"),
                 ("Prep Initech pilot kickoff deck", "medium")]:
    post("/ui/crm/tasks", {"subject": subj, "description": "Demo activity",
                           "status": "not_started", "priority": pr,
                           "due_date_ts": epoch_in(3)}, f"task {subj[:24]}")

# CRM Events (create route is POST with a trailing slash)
ev = post("/ui/crm/events/", {"name": "Q3 Customer Advisory Board",
                              "description": "Quarterly advisory session",
                              "max_attendance": 50}, "event advisory board")

# CRM Campaigns + email template
post("/ui/crm-marketing/email-templates",
     {"name": "Welcome Series", "subject_template": "Welcome {{first_name}}!",
      "body_html_template": "<h1>Hello {{first_name}}</h1><p>Thanks for joining.</p>"},
     "email template")
for nm, ct in [("Q3 Email Nurture", "email"), ("Renewal Reminder", "email")]:
    post("/ui/crm-marketing/campaigns",
         {"name": nm, "campaign_type": ct, "objective": "Drive engagement",
          "budget_cents": 500_000}, f"campaign {nm}")

# CRM Projects + tasks
proj = post("/v1/crm/projects", {"name": "Northwind Implementation",
                                 "description": "Phased platform rollout",
                                 "status": "underway", "priority": 2,
                                 "start_date": epoch_in(-10), "end_date": epoch_in(80)},
            "project Northwind")
proj_id = proj.get("id") or proj.get("project_id")
if proj_id:
    for nm, dur in [("Discovery & requirements", 10), ("Data migration", 15),
                    ("UAT & go-live", 7)]:
        post(f"/v1/crm/projects/{proj_id}/tasks",
             {"name": nm, "description": "Demo task", "duration_days": dur,
              "percent_complete": 0, "is_milestone": False}, f"proj-task {nm[:20]}")

# (Org accounts B2B: no simple create API — created via party-import flow; skipped here.)

# Knowledge base articles
for title, body in [("Getting Started Guide", "<h2>Welcome</h2><p>Set up your account in 3 steps.</p>"),
                    ("Billing FAQ", "<h2>Billing</h2><p>How invoices and renewals work.</p>"),
                    ("API Quickstart", "<h2>API</h2><p>Authenticate and make your first call.</p>")]:
    art = post("/kb/articles", {"title": title, "body_html": body,
                                "excerpt": title, "tags": ["demo"]}, f"kb {title}")
    aid = art.get("article_id")
    if aid:
        post(f"/kb/articles/{aid}/publish", {}, f"kb publish {title[:18]}")

# ───────────────────────────── ATS (OpenCATS) ─────────────────────────────
print("== ATS ==")
job_ids = []
for t in ["Senior Backend Engineer", "Product Designer", "DevOps Engineer"]:
    j = post("/ui/ats/job-orders/", {"title": t, "type": "hire", "status": "active",
                                     "openings": 2, "client_company_id": "ACME",
                                     "recruiter_subs": [], "hot": True, "public": True},
             f"job {t}")
    if j.get("job_id"):
        job_ids.append(j["job_id"])
cand_ids = []
for fn, ln, ti, sk in [("Dana", "Brooks", "Software Engineer", "TypeScript, React, Go"),
                       ("Morgan", "Reed", "SRE", "Kubernetes, Terraform, AWS"),
                       ("Casey", "Nguyen", "UX Designer", "Figma, Research, Prototyping")]:
    c = post("/ui/candidates", {"first_name": fn, "last_name": ln,
                                "email": f"{fn.lower()}.{TS}@example.com", "company": "Prior Co",
                                "title": ti, "source": "direct", "status": "active",
                                "key_skills": sk, "can_relocate": True}, f"candidate {fn}")
    if c.get("candidate_id"):
        cand_ids.append(c["candidate_id"])

# Pipeline: place candidates into EVERY job order (the board auto-selects the
# first-listed job, which may not be the first-created — so populate them all).
if job_ids and cand_ids:
    stages = ["100_no_contact", "200_contacted", "300_interviewed"]
    for ji, jid in enumerate(job_ids):
        for idx, cid in enumerate(cand_ids):
            post("/ui/ats/pipeline/entries",
                 {"job_order_id": jid, "candidate_id": cid,
                  "status": stages[idx % len(stages)]}, f"pipeline job{ji+1} cand{idx+1}")

# Skills registry on first candidate
if cand_ids:
    for skill in ["Python", "React", "Leadership"]:
        post(f"/ui/ats/skills/entity/candidate/{cand_ids[0]}",
             {"name": skill, "weight": 4, "required": False}, f"skill {skill}")

# ───────────────────────────── OBP Banking ─────────────────────────────
print("== OBP Banking ==")
req("GET", "/ui/banking/accounts")  # bootstraps wallet + self-seeds house bank
st, banks = req("GET", "/ui/banking/banks")
bank_id = "testlogon"
if isinstance(banks, dict) and banks.get("banks"):
    bank_id = banks["banks"][0]["bank_id"]
for lbl, typ, cur in [("Operating Account", "CHECKING", "usd"),
                      ("Reserve Savings", "SAVINGS", "usd"),
                      ("EUR Treasury", "SAVINGS", "eur")]:
    post("/ui/banking/accounts", {"bank_id": bank_id, "label": lbl,
                                  "account_type": typ, "currency": cur}, f"account {lbl}")

# ───────────────────────────── QloApps Hotels ─────────────────────────────
print("== QloApps Hotels ==")
hotel_ids = []
for nm, city in [("Seaside Grand", "Santa Monica"), ("Mountain Lodge", "Aspen")]:
    h = post("/ui/hotels", {"name": nm,
                            "address": {"line1": "1 Resort Way", "city": city, "region": "CA",
                                        "postal_code": "90401", "country": "US"},
                            "star_rating": 5, "check_in_time": "15:00",
                            "check_out_time": "11:00"}, f"hotel {nm}")
    if h.get("hotel_id"):
        hotel_ids.append(h["hotel_id"])

# Full setup for EVERY hotel — the reservations / front-desk / folio pages
# auto-select the first-listed hotel (not necessarily the first-created), so
# both hotels must carry rooms + reservations + folios to avoid an empty board.
for hi, hid in enumerate(hotel_ids):
    rt_ids = []
    for nm, bed, rate in [("Deluxe King", "king", 18000), ("Double Queen", "queen", 14000),
                          ("Ocean Suite", "suite", 32000)]:
        rt = post(f"/ui/hotels/{hid}/room-types",
                  {"name": nm, "description": f"{nm} room", "base_occupancy_adults": 2,
                   "base_occupancy_children": 1, "max_occupancy": 4, "bed_type": bed,
                   "size_sqft": 400, "base_nightly_rate_cents": rate, "photo_urls": []},
                  f"h{hi+1} room-type {nm}")
        if rt.get("room_type_id"):
            rt_ids.append(rt["room_type_id"])
    if rt_ids:
        rtid = rt_ids[0]
        for num, fl in [("201", 2), ("202", 2), ("301", 3)]:
            post(f"/ui/hotels/{hid}/rooms",
                 {"room_type_id": rtid, "room_number": num, "floor": fl,
                  "status": "available"}, f"h{hi+1} room {num}")
        for rt_each in rt_ids:
            post(f"/ui/hotels/{hid}/rate-plans",
                 {"room_type_id": rt_each, "name": "Standard Rate",
                  "base_nightly_rate_cents": 18000, "base_occupancy": 2,
                  "currency": "USD"}, f"h{hi+1} rate-plan")
            put(f"/ui/hotels/{hid}/availability/{rt_each}/total-rooms",
                {"hotel_id": hid, "room_type_id": rt_each,
                 "start_date": isodate_in(0), "end_date": isodate_in(60),
                 "total_rooms": 8}, f"h{hi+1} availability")
        # reservations -> folios. Include a TODAY check-in (adv=0) so the
        # front-desk "Arrivals" tab (today) isn't empty.
        for gi, (adv, nights) in enumerate([(0, 2), (2, 3), (10, 2)]):
            res = post(f"/ui/hotels/{hid}/reservations",
                       {"hotel_id": hid, "guest_party_id": f"guest_{TS}_{hi}_{gi}",
                        "room_type_id": rtid, "checkin": isodate_in(adv),
                        "checkout": isodate_in(adv + nights), "adults": 2,
                        "children": 0, "rooms": 1, "deposit_cents": 5000},
                       f"h{hi+1} reservation {gi+1}")
            rid = res.get("reservation_id")
            if rid:
                req("GET", f"/ui/hotels/{hid}/reservations/{rid}/folio")  # auto-open
                post(f"/ui/hotels/{hid}/reservations/{rid}/folio/lines",
                     {"line_type": "room_night", "description": f"{nights} nights",
                      "quantity": nights, "unit_price_cents": 18000,
                      "sku": "ROOMNIGHT"}, f"h{hi+1} folio line res{gi+1}")
                post(f"/ui/hotels/{hid}/reservations/{rid}/folio/payments",
                     {"amount_cents": 18000 * nights, "method": "cash",
                      "reference": "demo"}, f"h{hi+1} folio payment res{gi+1}")
        # housekeeping tasks
        st_rooms, rooms = req("GET", f"/ui/hotels/{hid}/rooms")
        room_list = rooms.get("rooms", []) if isinstance(rooms, dict) else []
        for rm in room_list[:2]:
            post(f"/ui/hotels/{hid}/housekeeping/tasks",
                 {"room_id": rm.get("room_id"), "due_at": epoch_in(1),
                  "notes": "Turnover clean"}, f"h{hi+1} housekeeping task")

# ─────────────────────── OFBiz Manufacturing/Purchasing/ERP ───────────────
print("== OFBiz Manufacturing/Purchasing ==")
post("/ui/manufacturing/work-centers", {"name": "Assembly Line A", "capacity_per_hour": 12},
     "work-center A")
bom = post("/ui/manufacturing/boms", {"product_sku": f"FG-{TS}", "name": "Widget BOM",
                                      "output_quantity": 1,
                                      "components": [{"component_sku": f"RAW-A-{TS}", "quantity_per": 2,
                                                      "scrap_pct": 0.05, "unit_of_measure": "each"},
                                                     {"component_sku": f"RAW-B-{TS}", "quantity_per": 1}]},
           "BOM Widget")
bom_id = bom.get("bom_id")
for q in (5, 10, 25):
    post("/ui/manufacturing/work-orders", {"product_sku": f"FG-{TS}", "quantity": q,
                                           **({"bom_id": bom_id} if bom_id else {})}, f"work-order qty={q}")
supplier_ids = []
for nm in ["Globex Components", "Stark Supplies", "Wayne Industrial"]:
    s = post("/ui/purchasing/suppliers", {"name": nm, "default_currency": "USD",
                                          "payment_terms_days": 30}, f"supplier {nm}")
    if s.get("supplier_id"):
        supplier_ids.append(s["supplier_id"])

print("== OFBiz Inventory / Returns / Assets / POS / PO ==")
# Inventory levels
# Mix of in-stock, low-stock (on_hand < reorder_point) and out-of-stock so the
# inventory page's status tabs all show data.
inv_skus = [(f"SKU-WIDGET-{TS}", 500, 50), (f"SKU-GADGET-{TS}", 220, 40),
            (f"SKU-GIZMO-{TS}", 30, 75), (f"SKU-CABLE-{TS}", 0, 20)]
for sku, oh, rp in inv_skus:
    put("/ui/inventory/items", {"sku": sku, "on_hand": oh, "location_id": "warehouse",
                                "reorder_point": rp, "reason": "initial stock"}, f"inventory {sku[-6:]}")
# (Returns/RMA require a real owned sales order with line items — orders come from
#  the store-checkout flow, not a simple create API — so RMA seeding is skipped here.)
# Fixed assets
for nm, cls, cost in [("Packaging Line #3", "machinery", 50_000_000),
                      ("Delivery Van", "vehicle", 3_500_000)]:
    a = post("/ui/fixed-assets", {"name": nm, "asset_class": cls,
                                  "acquisition_cost_cents": cost,
                                  "salvage_value_cents": cost // 10,
                                  "useful_life_months": 60, "acquired_at": epoch_in(-120),
                                  "depreciation_method": "straight_line"}, f"asset {nm}")
    aid = a.get("asset_id")
    if aid:
        post(f"/ui/fixed-assets/{aid}/schedule/generate", {}, f"depreciation schedule {nm[:14]}")
# Purchase order
if supplier_ids:
    po = post("/ui/purchasing/purchase-orders",
              {"supplier_id": supplier_ids[0],
               "lines": [{"sku": inv_skus[0][0], "quantity_ordered": 100, "unit_cost_cents": 2500},
                         {"sku": inv_skus[1][0], "quantity_ordered": 50, "unit_cost_cents": 5000}],
               "currency": "USD", "expected_delivery_date": isodate_in(14)}, "purchase order")
    po_id = po.get("po_id")
    if po_id:
        post(f"/ui/purchasing/purchase-orders/{po_id}/submit", {"reason": "demo"}, "PO submit")
        post(f"/ui/purchasing/purchase-orders/{po_id}/approve", {"reason": "demo"}, "PO approve")
# POS register + session + sale
reg = post("/ui/pos/registers", {"label": "Register #1", "location_id": "warehouse",
                                 "default_currency": "USD"}, "pos register")
reg_id = reg.get("register_id")
if reg_id:
    sess = post("/ui/pos/sessions", {"register_id": reg_id, "opening_float_cents": 10000},
                "pos session")
    sess_id = sess.get("session_id")
    if sess_id:
        txn = post(f"/ui/pos/sessions/{sess_id}/txns", {"correlation_id": f"TXN-{TS}"}, "pos txn")
        txn_id = txn.get("txn_id")
        if txn_id:
            post(f"/ui/pos/txns/{txn_id}/lines",
                 {"sku": "SKU-COFFEE", "name": "Coffee Mug", "unit_price_cents": 1999,
                  "quantity": 2}, "pos line")

# ───────────────────────────── Property ─────────────────────────────
print("== Property ==")
prop = post("/ui/properties", {"name": "Riverside Apartments", "property_type": "apartment",
                               "address": {"line1": "200 River Rd", "city": "Austin", "region": "TX",
                                           "postal_code": "78701", "country": "US"},
                               "color_tags": ["residential"]}, "property Riverside")
prop_id = prop.get("property_id")
unit_id = None
if prop_id:
    unit = post(f"/ui/properties/{prop_id}/units", {"label": "Unit 101", "bedrooms": 2, "bathrooms": 1.5,
                                                    "square_footage": 900, "market_rent_cents": 180000,
                                                    "occupancy_status": "occupied"}, "unit 101")
    unit_id = unit.get("unit_id")
post("/ui/properties", {"name": "Downtown Lofts", "property_type": "apartment",
                        "address": {"line1": "55 Main St", "city": "Austin", "region": "TX",
                                    "postal_code": "78702", "country": "US"}, "color_tags": ["commercial"]},
     "property Downtown")
tenants = []
for nm in ["Alex Rivera", "Jamie Wong", "Pat Morgan"]:
    t = post("/ui/property/tenants", {"display_name": nm, "email": f"{nm.split()[0].lower()}.{TS}@example.com"},
             f"tenant {nm}")
    if t.get("tenant_id"):
        tenants.append(t["tenant_id"])
lease_id = None
if prop_id and unit_id and tenants:
    lease = post("/ui/leases", {"tenant_id": tenants[0], "property_id": prop_id, "unit_id": unit_id,
                                "start_date": epoch_in(-30), "end_date": epoch_in(335),
                                "monthly_rent_cents": 180000, "security_deposit_cents": 360000,
                                "rent_due_day": 1, "late_fee_type": "none", "currency": "usd",
                                "renewal_notice_days": 30}, "lease Unit 101")
    lease_id = lease.get("lease_id")

# Vendors
vendor_ids = []
for nm, cat in [("ABC Plumbing", "plumbing"), ("BrightSpark Electric", "electrical")]:
    v = post("/ui/maintenance/vendors", {"name": nm, "trade_category": cat,
                                         "email": f"contact.{TS}@{nm.split()[0].lower()}.test",
                                         "default_currency": "USD", "payment_terms_days": 30},
             f"vendor {nm}")
    if v.get("vendor_id"):
        vendor_ids.append(v["vendor_id"])
# Work orders
if prop_id:
    for title, pr in [("Repair kitchen faucet", "high"), ("Replace hallway light", "normal")]:
        post(f"/ui/properties/{prop_id}/work-orders",
             {"title": title, "description": f"Demo: {title}", "priority": pr,
              "property_id": prop_id, **({"unit_id": unit_id} if unit_id else {})},
             f"work-order {title[:18]}")
# Rent payments (populate ledger + aging)
if lease_id:
    for mo in (-2, -1, 0):
        post(f"/ui/rent/leases/{lease_id}/payments",
             {"amount_cents": 180000, "method": "bank_transfer", "paid_on": epoch_in(mo * 30),
              "reference": f"ACH-{TS}-{mo}",
              "period": _dt.date.fromtimestamp(epoch_in(mo * 30)).strftime("%Y-%m")}, f"rent payment m{mo}")

# ───────────────────────────── Newsfeed ─────────────────────────────
print("== Newsfeed ==")
for body in ["Welcome to the platform! Excited to share what we've been building. 🚀",
             "New behind-the-scenes content dropping this week — subscribers get early access.",
             "Premium tutorial: advanced workflows (subscriber-only)."]:
    post("/posts", {"body": body}, f"post {body[:28]}…")
post("/posts", {"body": "Exclusive deep-dive — unlock to read the full breakdown.",
                "unlock_price_cents": 500}, "post (locked)")

# ───────────────────────────── Shop Catalog ─────────────────────────────
print("== Shop Catalog ==")
cat = post("/ui/catalog/categories", {"name": "Merch & Digital", "description": "Apparel, presets & digital goods"},
           "category Merch & Digital")
cat_id = cat.get("category_id")
if cat_id:
    for nm, desc, price in [("Signature Hoodie", "Premium embroidered hoodie", 6500),
                            ("Lightroom Preset Pack", "20 cinematic presets", 2499),
                            ("Sticker Sheet", "Die-cut vinyl stickers", 899)]:
        post(f"/ui/catalog/categories/{cat_id}/items",
             {"name": nm, "description": desc, "price_cents": price, "currency": "USD",
              "image_urls": [], "attributes": {}}, f"item {nm}")

# ───────────────────────────── Calendar ─────────────────────────────
print("== Calendar ==")
cal = post("/ui/calendars", {"name": "Content Schedule", "timezone": "UTC"}, "calendar Content Schedule")
cal_id = cal.get("calendar_id")
if cal_id:
    base = _dt.datetime.utcnow().replace(microsecond=0)
    for nm, dh in [("Livestream Q&A", 24), ("Photo Shoot", 72), ("Subscriber AMA", 120)]:
        s = base + _dt.timedelta(hours=dh)
        e = s + _dt.timedelta(hours=1)
        post(f"/ui/calendars/{cal_id}/events",
             {"name": nm, "start_utc": s.strftime("%Y-%m-%dT%H:%M:%SZ"),
              "end_utc": e.strftime("%Y-%m-%dT%H:%M:%SZ"), "timezone": "UTC"}, f"event {nm}")

# ───────────────────────────── Ads ─────────────────────────────
print("== Ads ==")
acct = post("/ui/ads/accounts", {"company_name": "Northwind Media",
                                 "billing_email": f"ads.{TS}@northwind.test"}, "ad account Northwind Media")
acct_id = acct.get("account_id")
if acct_id:
    post(f"/ui/admin/ads/accounts/{acct_id}/review", {"decision": "approve", "notes": "Approved for demo"},
         "approve ad account")
    for nm, obj, bud in [("Summer Sale Awareness", "awareness", 5000),
                         ("Retargeting — Cart Abandoners", "conversions", 8000)]:
        post(f"/ui/ads/accounts/{acct_id}/campaigns",
             {"name": nm, "objective": obj, "budget_cents": bud, "budget_type": "daily"}, f"campaign {nm}")

print("done.")
