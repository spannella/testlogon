import os
ROOT="/home/ubuntu/testlogon"
def rd(p):
    with open(os.path.join(ROOT,p),encoding="utf-8") as f: return f.read()

checks = {
 "app/services/ad_serving.py": [
   '    content_owner_id: str = "",\n) -> Dict[str, Any]:',
   '        # Get approved creatives\n        creatives = list_approved_creatives(campaign["campaign_id"])\n        if not creatives:\n            continue',
   '            "creative_id": creative["creative_id"],\n            "content_owner_sub": content_owner_id or "",',
   '        "ctas": creative.get("ctas") or [],\n        "image_url": creative.get("image_url"),',
 ],
}
markers = {
 "app/services/ad_serving.py":"B2: shop surfaces serve only PRODUCT-LINKED",
 "app/services/ad_creatives.py":"B1: product-linked creative",
 "app/routers/ads.py":"ADV x ECOM: product creative (B1)",
}
for p,ancs in checks.items():
    s=rd(p)
    for a in ancs:
        print("ANCHOR", p, "count=", s.count(a), repr(a[:55]))
for p,m in markers.items():
    try: s=rd(p); print("MARKER", p, "present" if m in s else "absent")
    except Exception as e: print("MARKER", p, "READERR", e)
# does shop_ads exist?
print("shop_ads_exists", os.path.exists(os.path.join(ROOT,"app/services/shop_ads.py")))
# ByItemId GSI + catalog table sanity: check catalog router present
print("catalog_router", os.path.exists(os.path.join(ROOT,"app/routers/catalog.py")))
print("shoppingcart_adv403", "attribute_conversion" in rd("app/routers/shoppingcart.py"))
