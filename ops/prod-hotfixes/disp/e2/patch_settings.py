p = "app/core/settings.py"
s = open(p).read()
assert "dispute_dual_approval_threshold_cents" not in s, "already patched"
anchor = '    dispute_auto_refund_threshold_cents: int = int(os.environ.get("DISPUTE_AUTO_REFUND_THRESHOLD_CENTS", "0"))\n'
assert anchor in s, "anchor not found"
add = (
    '    # DISP-022: a resolve that MOVES money (refunded/partial) above this\n'
    '    # threshold requires real, non-self-attested dual approval (a second\n'
    '    # PAYMENT_DISPUTES admin), mirroring the moderation permanent-ban gate.\n'
    '    dispute_dual_approval_threshold_cents: int = int(os.environ.get("DISPUTE_DUAL_APPROVAL_THRESHOLD_CENTS", "5000"))\n'
    '    dispute_dual_approval_enabled: bool = os.environ.get("DISPUTE_DUAL_APPROVAL_ENABLED", "1") not in ("0", "false", "False")\n'
)
s = s.replace(anchor, anchor + add, 1)
open(p, "w").write(s)
print("settings.py patched OK")
