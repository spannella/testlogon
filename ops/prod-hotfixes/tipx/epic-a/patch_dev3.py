#!/usr/bin/env python3
"""TIPX-A2 (reversal route wiring) + A6 (leaderboard reversed-exclusion) patcher."""
import io, sys

def read(p):
    with io.open(p, encoding="utf-8") as f: return f.read()
def write(p, s):
    with io.open(p, "w", encoding="utf-8") as f: f.write(s)

def sub_once(path, old, new, label):
    s = read(path)
    if new in s and old not in s:
        print(f"  [skip] {label}"); return
    n = s.count(old)
    if n != 1:
        print(f"  [FAIL] {label}: found {n} anchors"); sys.exit(2)
    write(path, s.replace(old, new, 1))
    print(f"  [ok]   {label}")

# A2: append the reversal-by-payment-id helper to tips.py.
TIPS = "app/services/tips.py"
append_src = read("/tmp/tips_append.py")
s = read(TIPS)
if "def reverse_tip_by_payment_id(" in s:
    print("  [skip] A2: tips.py reversal helper (already present)")
else:
    if not s.endswith("\n"):
        s += "\n"
    write(TIPS, s + append_src)
    print("  [ok]   A2: append reverse_tip_by_payment_id to tips.py")

# A2: register the admin router in main.py (import + include).
MAIN = "app/main.py"
sub_once(MAIN,
    "from app.routers.admin_payouts import router as admin_payouts_router\n",
    "from app.routers.admin_payouts import router as admin_payouts_router\n"
    "from app.routers.admin_tip_reversal import router as admin_tip_reversal_router  # TIPX-A2\n",
    "A2: import admin_tip_reversal_router")

sub_once(MAIN,
    "    app.include_router(admin_payouts_router)\n",
    "    app.include_router(admin_payouts_router)\n"
    "    app.include_router(admin_tip_reversal_router)  # TIPX-A2\n",
    "A2: include admin_tip_reversal_router")

# A6: leaderboard excludes reversed credits (the reversal flips state->reversed).
LB = "app/services/tip_leaderboard.py"
sub_once(LB,
    "    filter_expr = Attr(\"type\").eq(\"credit\") & Attr(\"reason\").begins_with(\"Tip\")",
    "    # TIPX-A6/D2: exclude reversed credits so a refunded tip drops from the\n"
    "    # leaderboard (reverse_tip flips the original credit to state=\"reversed\").\n"
    "    filter_expr = Attr(\"type\").eq(\"credit\") & Attr(\"reason\").begins_with(\"Tip\") & Attr(\"state\").ne(\"reversed\")",
    "A6: leaderboard excludes reversed")

print("done")
