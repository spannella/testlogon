#!/usr/bin/env python3
"""DISP E1 fold — apply the USER-LEVEL dispute flow to a checkout.

Idempotent (sentinel-guarded). E1 wires the user dispute track to the E0
dispatcher so an admin resolution actually moves money (the first real money
movement of the payment-disputes program). Applies, in order:

  1. NEW  app/services/dispute_lifecycle.py — DISP-010 reason enum + per-charge
     gating; DISP-011 forward-only user state machine (open/needs_response/
     under_review/resolved/withdrawn/escalated); DISP-012 creator response window
     (respond_by) + SLA sweep (needs_response past respond_by -> under_review,
     NOT auto-loss); detect_charge_from_entry.
  2. app/services/billing_disputes.py  (whole file; prod == dev HEAD md5
     753595...): DISP-010 reason gating at open, DISP-014 pre-open guards (dedup +
     refund-then-dispute via the E0 mutex), auto-open response window, DISP-013
     resolve_dispute wired to dispute_dispatch.dispatch_reversal
     (refunded->full / partial->override / denied->state-only), withdraw_dispute.
  3. app/routers/billing_disputes.py  (whole file; prod == dev HEAD md5
     871f72...): pass charge_type/charge_ref/recipient_id/reason_detail on file;
     POST /ui/billing/disputes/{id}/withdraw; override_amount on resolve; admin
     POST /ui/admin/disputes/sweep.
  4. app/models.py  (targeted patch): DisputeFileIn gains reason_detail/charge_type/
     charge_ref/recipient_id + reason min_length 10->1; DisputeResolveIn accepts
     refunded|partial|denied (+legacy) + override_amount_cents.
  5. app/core/settings.py  (targeted patch): dispute_response_window_days (7) +
     dispute_auto_refund_threshold_cents (0).

Usage:
  python3 apply_dispe1.py <ROOT> <ARTDIR>
where ARTDIR holds dispute_lifecycle.py + billing_disputes.py + router_billing_disputes.py.
Backs up each edited file to <file>.bak_disp_<ts> before touching it.
"""
import os, sys, time, shutil

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
ART = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, "ops/prod-hotfixes/disp/e1")
TS = int(time.time())


def rp(*p):
    return os.path.join(ROOT, *p)


def backup(path):
    if os.path.exists(path):
        b = f"{path}.bak_disp_{TS}"
        shutil.copy2(path, b)
        print("  backup ->", b)


def copy_whole(art_name, dst_rel):
    src = os.path.join(ART, art_name)
    dst = rp(dst_rel)
    backup(dst)
    shutil.copy2(src, dst)
    print("  wrote ->", dst_rel)


# 1) NEW dispute_lifecycle.py
copy_whole("dispute_lifecycle.py", "app/services/dispute_lifecycle.py")

# 2) whole-file billing_disputes.py (prod == dev HEAD; safe overwrite)
copy_whole("billing_disputes.py", "app/services/billing_disputes.py")

# 3) whole-file router (prod == dev HEAD; safe overwrite)
copy_whole("router_billing_disputes.py", "app/routers/billing_disputes.py")

# 4) models.py targeted patch (huge shared file — string-replace, idempotent)
mp = rp("app/models.py")
ms = open(mp).read()
DISPUTE_FILE_OLD = (
    'class DisputeFileIn(BaseModel):\n'
    '    """Customer-initiated dispute (e.g. a chargeback claim) for a transaction."""\n'
    '    transaction_entry_id: Optional[str] = Field(default=None, max_length=200)\n'
    '    amount_cents: int = Field(ge=1)\n'
    '    currency: str = "USD"\n'
    '    reason: str = Field(min_length=10, max_length=2000)\n'
    '    provider: str = Field(default="manual", max_length=40)'
)
DISPUTE_FILE_NEW = (
    'class DisputeFileIn(BaseModel):\n'
    '    """Customer-initiated dispute (e.g. a chargeback claim) for a transaction.\n'
    '\n'
    '    DISP-010: ``reason`` is now the canonical enum\n'
    '    (not_received|not_as_described|unauthorized|duplicate|quality); ``charge_type``\n'
    '    + ``charge_ref`` (or ``transaction_entry_id`` for auto-detection) locate the\n'
    '    underlying charge for the reversal-rail dispatcher; ``reason_detail`` carries\n'
    '    the free-text the old ``reason`` field used to.\n'
    '    """\n'
    '    transaction_entry_id: Optional[str] = Field(default=None, max_length=200)\n'
    '    amount_cents: int = Field(ge=1)\n'
    '    currency: str = "USD"\n'
    '    # accept the enum OR a legacy free-text reason (>=1 char); gating happens in\n'
    '    # dispute_lifecycle.validate_reason once the charge_type is known.\n'
    '    reason: str = Field(min_length=1, max_length=2000)\n'
    '    reason_detail: Optional[str] = Field(default=None, max_length=2000)\n'
    '    charge_type: Optional[str] = Field(default=None, max_length=40)\n'
    '    charge_ref: Optional[str] = Field(default=None, max_length=200)\n'
    '    recipient_id: Optional[str] = Field(default=None, max_length=200)\n'
    '    provider: str = Field(default="manual", max_length=40)'
)
DISPUTE_RESOLVE_OLD = (
    'class DisputeResolveIn(BaseModel):\n'
    '    resolution: str = Field(pattern="^(won|lost|accepted)$")\n'
    '    notes: Optional[str] = Field(default=None, max_length=2000)'
)
DISPUTE_RESOLVE_NEW = (
    'class DisputeResolveIn(BaseModel):\n'
    '    # DISP-013: user-track outcomes drive the reversal dispatcher; legacy\n'
    '    # won|lost|accepted still accepted + mapped for the old admin path.\n'
    '    resolution: str = Field(pattern="^(refunded|partial|denied|won|lost|accepted)$")\n'
    '    override_amount_cents: Optional[int] = Field(default=None, ge=1)\n'
    '    notes: Optional[str] = Field(default=None, max_length=2000)'
)
if "reason_detail: Optional[str]" in ms and "class DisputeFileIn" in ms.split("reason_detail")[0][-400:]:
    print("  models.py DisputeFileIn already patched (sentinel)")
else:
    assert DISPUTE_FILE_OLD in ms, "models.py: DisputeFileIn anchor not found (prod-divergent?)"
    ms = ms.replace(DISPUTE_FILE_OLD, DISPUTE_FILE_NEW, 1)
if 'refunded|partial|denied' in ms:
    print("  models.py DisputeResolveIn already patched (sentinel)")
else:
    assert DISPUTE_RESOLVE_OLD in ms, "models.py: DisputeResolveIn anchor not found"
    ms = ms.replace(DISPUTE_RESOLVE_OLD, DISPUTE_RESOLVE_NEW, 1)
backup(mp)
open(mp, "w").write(ms)
print("  patched -> app/models.py")

# 5) settings.py targeted patch
sp = rp("app/core/settings.py")
ss = open(sp).read()
S_ANCHOR = '    billing_disputes_default_deadline_days: int = int(os.environ.get("BILLING_DISPUTES_DEADLINE_DAYS", "14"))'
S_ADD = (S_ANCHOR +
         '\n    dispute_response_window_days: int = int(os.environ.get("DISPUTE_RESPONSE_WINDOW_DAYS", "7"))'
         '\n    dispute_auto_refund_threshold_cents: int = int(os.environ.get("DISPUTE_AUTO_REFUND_THRESHOLD_CENTS", "0"))')
if "dispute_response_window_days" in ss:
    print("  settings.py already patched (sentinel)")
else:
    assert S_ANCHOR in ss, "settings.py: anchor not found"
    ss = ss.replace(S_ANCHOR, S_ADD, 1)
    backup(sp)
    open(sp, "w").write(ss)
    print("  patched -> app/core/settings.py")

print(f"DISP E1 fold applied (ts={TS}).")
