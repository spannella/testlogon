import hashlib, os
files = [
 "app/routers/advertiser_api.py",
 "app/routers/kyc_partner_api.py",
 "app/services/advertiser_api.py",
 "app/services/kyc_partner_api.py",
 "app/services/api_key_auth_dependency.py",
 "app/services/api_key_capabilities.py",
]
for f in files:
    try:
        h = hashlib.sha256(open(f,'rb').read()).hexdigest()
    except Exception as e:
        h = "MISSING:%s" % e
    print(h, f)
# Also confirm main.py wiring + registry has no ads/kyc
import subprocess
def grepcount(pat, path):
    try:
        return sum(1 for l in open(path, encoding='utf-8', errors='replace') if pat in l)
    except Exception as e:
        return "ERR:%s" % e
print("MAIN advertiser_api_router incl:", grepcount("app.include_router(advertiser_api_router)", "app/main.py"))
print("MAIN kyc_partner_api_router incl:", grepcount("app.include_router(kyc_partner_api_router)", "app/main.py"))
print("REGISTRY ads refs:", grepcount("/api/v1/ads", "app/services/api_key_route_scope_registry.py"))
print("REGISTRY kyc refs:", grepcount("/api/v1/kyc", "app/services/api_key_route_scope_registry.py"))
# confirm routers do NOT depend on maybe_enforce / require_ui_session / get_authenticated_user
for f in ["app/routers/advertiser_api.py","app/routers/kyc_partner_api.py"]:
    src = open(f, encoding='utf-8', errors='replace').read()
    print("ROUTER", f, "maybe_enforce:", "maybe_enforce_api_key_route_policy" in src,
          "require_ui_session:", "require_ui_session" in src,
          "get_authenticated_user:", "get_authenticated_user" in src,
          "require_api_key_principal:", "require_api_key_principal" in src)
