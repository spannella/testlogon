#!/usr/bin/env python3
"""ADV2-E5 (F5) idempotent apply. app/services/ad_messaging.py ships as a
committed repo file; this only APPENDS the F5 endpoints block to
app/routers/ads.py (guarded on a marker so it is safe to re-run on the divergent
prod ads.py). ROOT env selects the repo (default ".").
"""
import os, sys

ROOT = os.environ.get("ROOT", ".")
ADS = os.path.join(ROOT, "app", "routers", "ads.py")
SVC = os.path.join(ROOT, "app", "services", "ad_messaging.py")
BLOCK = os.path.join(os.path.dirname(__file__), "ads_endpoints_block.py")
MARKER = "Ad-messaging: shared engine + F5 sponsored mass-messaging (ADV2-E5)"

if not os.path.exists(SVC):
    print("ERROR ad_messaging.py missing (should be a committed repo file):", SVC)
    sys.exit(1)

ads = open(ADS, "r", encoding="utf-8").read()
if MARKER in ads:
    print("APPEND_SKIPPED_ALREADY_PRESENT")
else:
    block = open(BLOCK, "r", encoding="utf-8").read()
    if not ads.endswith("\n"):
        ads += "\n"
    open(ADS, "w", encoding="utf-8").write(ads + block)
    print("APPEND_DONE")

import py_compile
py_compile.compile(SVC, doraise=True)
py_compile.compile(ADS, doraise=True)
print("PYCOMPILE_OK")
