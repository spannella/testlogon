#!/usr/bin/env python3
"""ADV-sign (cosmetic): register ``ad_revenue_reversal`` in LEDGER_ENTRY_SIGN as a
debit-direction (-1) entry (it is a creator clawback). Harmless today -- the row is
type=="ad_revenue_reversal" (not "credit") so no earnings/balance reader sums it --
but this makes the canonical sign map complete so derive_signed_amount_cents no longer
defaults it to +1 (and stops logging the "not in LEDGER_ENTRY_SIGN" WARNING).

Idempotent. Safely NO-OPs where LEDGER_ENTRY_SIGN is absent (the older dev clone
billing_shared.py predates the signed_amount_cents system). Run: python apply_advsign.py [ROOT]
"""
import sys, os
ROOT = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
FP = os.path.join(ROOT, "app/services/billing_shared.py")
src = open(FP, encoding="utf-8").read()

if "LEDGER_ENTRY_SIGN" not in src:
    print("SKIP: billing_shared.py has no LEDGER_ENTRY_SIGN (predates signed-amount system); nothing to do.")
    raise SystemExit(0)
if '"ad_revenue_reversal"' in src:
    print("SKIP: ad_revenue_reversal already in LEDGER_ENTRY_SIGN.")
    raise SystemExit(0)

OLD = '''    "sponsorship_escrow_hold": -1,
    "sponsorship_commission": -1,
}'''
NEW = '''    "sponsorship_escrow_hold": -1,
    "sponsorship_commission": -1,
    "ad_revenue_reversal": -1,  # ADV-sign: ad-revenue clawback (creator debit direction)
}'''
assert src.count(OLD) == 1, "LEDGER_ENTRY_SIGN tail anchor not unique/found"
src = src.replace(OLD, NEW)
open(FP, "w", encoding="utf-8").write(src)
print("WROTE app/services/billing_shared.py (ad_revenue_reversal -> -1)")
