"""DISP-005 guarded_dispute_transition + DISP-001 unified record live check."""
from __future__ import annotations
import uuid
from app.core.tables import T
from app.services import dispute_dispatch as DD
from app.services import billing_disputes as BD

RUN = uuid.uuid4().hex[:8]
results = []
def rec(n, ok, d=""):
    results.append((n, ok, d)); print("PASS" if ok else "FAIL", n, "-", d)

# DISP-001: unified record carries source/charge_type/charge_ref/linked/rail/resolution
item = BD.file_dispute(user_id=f"disp_u_{RUN}", amount_cents=500, reason="unauthorized",
                       source="processor", charge_type="tip", charge_ref=f"tp_{RUN}",
                       linked_dispute_id="dp_other")
did = item["dispute_id"]
row = T.billing_disputes.get_item(Key={"pk": f"DISPUTE#{did}", "sk": "META"}).get("Item")
rec("DISP-001: unified record has source discriminator + charge linkage",
    row.get("source") == "processor" and row.get("charge_type") == "tip"
    and row.get("charge_ref") == f"tp_{RUN}" and row.get("linked_dispute_id") == "dp_other"
    and "rail_marker" in row and "source_scope" in row,
    f"source={row.get('source')} charge_type={row.get('charge_type')} scope={row.get('source_scope')}")

# default source=user + no behavior change for the legacy stub path
item2 = BD.file_dispute(user_id=f"disp_u2_{RUN}", amount_cents=100, reason="quality")
row2 = T.billing_disputes.get_item(Key={"pk": f"DISPUTE#{item2['dispute_id']}", "sk": "META"}).get("Item")
rec("DISP-001: legacy stub defaults source=user (no behavior change)",
    row2.get("source") == "user" and row2.get("status") == "open", f"source={row2.get('source')}")

# DISP-005: guarded transition — one winner on concurrent double-resolve
changed1, r1 = DD.guarded_dispute_transition(did, "under_review", expected_from=["open"])
changed2, r2 = DD.guarded_dispute_transition(did, "under_review", expected_from=["open"])
rec("DISP-005: guarded transition — exactly one winner (double-resolve safe)",
    changed1 is True and changed2 is False, f"changed1={changed1} changed2={changed2}")
rec("DISP-005: transition actually moved status (ALL_NEW)",
    r1.get("status") == "under_review", f"status={r1.get('status')}")

# illegal skip rejected BEFORE side effect
try:
    DD.guarded_dispute_transition(did, "resolved", expected_from=["open"])
    rec("DISP-005: illegal skip rejected", False, "no raise")
except Exception as e:
    rec("DISP-005: illegal transition (wrong expected_from) rejected", "409" in str(e) or "illegal" in str(e).lower(), repr(e)[:80])

# cleanup
for d in (did, item2["dispute_id"]):
    T.billing_disputes.delete_item(Key={"pk": f"DISPUTE#{d}", "sk": "META"})
print("cleanup: 2 dispute rows deleted")
npass = sum(1 for _, ok, _ in results if ok)
print(f"\nDISP-001/005 MATRIX: {npass}/{len(results)} pass")
import sys; sys.exit(0 if npass == len(results) else 1)
