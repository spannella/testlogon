#!/usr/bin/env python3
"""TIPX-E1: register tip_received in SOCIAL_ALERT_TYPES."""
import io, sys, time

PATH = "app/services/social_alerts.py"
src = io.open(PATH, encoding="utf-8").read()
orig = src
ts = int(time.time())

a = '''    "post_tip",
    "message_tip",
]'''
b = '''    "post_tip",
    "message_tip",
    "tip_received",
]'''
assert src.count(a) == 1, f"anchor={src.count(a)}"
src = src.replace(a, b)

if src == orig:
    print("NO CHANGE"); sys.exit(1)
io.open(PATH + f".bak_tipx_{ts}", "w", encoding="utf-8").write(orig)
io.open(PATH, "w", encoding="utf-8").write(src)
print(f"PATCHED social_alerts.py; bak=.bak_tipx_{ts}")
