import os, sys, time, json
os.environ.setdefault("DEV_MODE", "1")
ROOT = "/home/ubuntu/testlogon"; sys.path.insert(0, ROOT); os.chdir(ROOT)
def E(m): print("EVIDENCE| " + str(m), flush=True)

TS = int(time.time())
PW = "TestLogon!2026"
SELLER = f"mia.maker.{TS}@testlogon.example"
BUYER = f"ben.buyer.{TS}@testlogon.example"

from app.core.tables import T
from app.services.registration import create_user_record, mark_user_verified

def mkuser(email, name):
    try:
        create_user_record(email=email, full_name=name, password=PW, verification_required=False)
    except Exception as e:
        E(f"create_user_record {email} warn: {str(e)[:90]}")
    mark_user_verified(email)
    return email

mkuser(SELLER, "Mia Maker")
mkuser(BUYER, "Ben Buyer")
E(f"seller={SELLER} buyer={BUYER} pw={PW}")

# ---- buyer profile with mailing address (echoed into the ship-group ship_to) ----
addr = {"line1": "742 Evergreen Terrace", "line2": "Unit 3", "city": "Columbus", "state": "OH",
        "postal_code": "43215", "country": "US", "name": "Ben Buyer"}
try:
    from app.services.profile import save_profile
    save_profile(BUYER, {"display_name": "Ben Buyer", "displayed_email": BUYER, "mailing_address": addr}, [])
    E("buyer profile+address saved")
except Exception as e:
    E(f"save_profile err: {repr(e)[:90]}")
    try:
        from app.services.addresses import create_address
        create_address(BUYER, {**addr, "is_primary": True})
        E("buyer address via create_address")
    except Exception as e2:
        E(f"create_address err: {repr(e2)[:90]}")

# ---- seller catalog item ----
CAT = f"mia_store_{TS}"
ITEM = f"mug_{TS}"
T.catalog.put_item(Item={"PK": f"CAT#{CAT}", "SK": f"ITEM#{ITEM}", "entity": "item",
    "name": "Handmade Ceramic Mug", "currency": "USD", "price_cents": 2800,
    "creator_id": SELLER, "stock_count": 25})
E(f"catalog category={CAT} item={ITEM} name='Handmade Ceramic Mug' price_cents=2800 seller={SELLER}")

E("SEED_IDS " + json.dumps({"seller": SELLER, "buyer": BUYER, "pw": PW,
    "category_id": CAT, "item_id": ITEM, "ts": TS}))
print("SEED_DONE")
