"""Idempotent anchored insert of the EasyPost settings (runs on dev + prod)."""
import sys, os
ROOT = os.environ.get("ROOT", os.path.expanduser("~/dev/testlogon"))
p = os.path.join(ROOT, "app/core/settings.py")
s = open(p, encoding="utf-8").read()
if "easypost_api_key" in s:
    print("SETTINGS_SKIP_ALREADY_PRESENT")
    sys.exit(0)
anchor = '    shipment_webhook_secret: str = os.environ.get("SHIPMENT_WEBHOOK_SECRET", "")\n'
assert s.count(anchor) == 1, "anchor count=%d" % s.count(anchor)
add = (
    '    # EasyPost integration (config-gated shipment tracking). When the key is\n'
    '    # set, real EasyPost Trackers are created on ship + tracker.updated webhooks\n'
    '    # drive status; when absent the internal/simulate driver is used (unchanged).\n'
    '    easypost_api_key: str = os.environ.get("EASYPOST_API_KEY", "")\n'
    '    easypost_webhook_secret: str = os.environ.get("EASYPOST_WEBHOOK_SECRET", "")\n'
    '    easypost_api_base: str = os.environ.get("EASYPOST_API_BASE", "https://api.easypost.com/v2")\n'
)
s = s.replace(anchor, anchor + add, 1)
open(p, "w", encoding="utf-8").write(s)
print("SETTINGS_PATCHED")
