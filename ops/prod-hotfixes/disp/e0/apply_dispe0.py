#!/usr/bin/env python3
"""DISP E0 fold — apply the payment-disputes FOUNDATION to a checkout.

Idempotent (sentinel-guarded). Applies, in order:
  1. NEW app/services/dispute_dispatch.py  (DISP-002 resolver, DISP-003 rail
     dispatcher, DISP-005 credit-flip mutex + guarded dispute transition).
  2. app/services/vod_purchase.py  (DISP-004 N1): add imports + _vod_av transact
     serializer + reverse_vod_purchase (clawback + buyer refund + flip original
     credit state=reversed + DELETE T.vod_entitlements row so a refunded buyer
     LOSES access + VODREVERSAL#{purchase_id} marker; clawback_only for E3).
  3. app/services/billing_disputes.py  (DISP-001): file_dispute gains
     source/charge_type/charge_ref/linked_dispute_id params + persists
     source/source_scope/charge_type/charge_ref/linked_dispute_id/rail_marker on
     the META row (unified dispute record; legacy rows default source=user, no
     behavior change).

Usage:
  python3 apply_dispe0.py /home/ubuntu/testlogon /home/ubuntu/testlogon/ops/prod-hotfixes/disp/e0
where argv[2] is the artifact dir holding dispute_dispatch.py + the two snippets.
Backs up each edited file to <file>.bak_disp_<ts> before touching it.
"""
import os, sys, time, shutil

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
ART = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, "ops/prod-hotfixes/disp/e0")
TS = int(time.time())


def rp(*p):
    return os.path.join(ROOT, *p)


def backup(path):
    b = f"{path}.bak_disp_{TS}"
    if os.path.exists(path):
        shutil.copy2(path, b)
        print("  backup ->", b)


# 1) dispute_dispatch.py (new file, overwrite-safe)
dd_dst = rp("app/services/dispute_dispatch.py")
dd_src = os.path.join(ART, "dispute_dispatch.py")
shutil.copy2(dd_src, dd_dst)
print("PLACED app/services/dispute_dispatch.py")

# 2) vod_purchase.py
vp = rp("app/services/vod_purchase.py")
s = open(vp, encoding="utf-8").read()
if "def reverse_vod_purchase(" in s:
    print("SKIP vod_purchase.py (reverse_vod_purchase already present)")
else:
    backup(vp)
    anchor = "from app.services.subscription_access import has_active_subscription, is_platform_admin"
    assert anchor in s, "vod import anchor missing"
    s = s.replace(anchor, anchor + "\n"
                  "from botocore.exceptions import ClientError\n"
                  "from boto3.dynamodb.types import TypeSerializer as _VodTypeSerializer\n"
                  "from app.core.settings import S\n"
                  "from app.core.aws_clients import ddb_transact_client", 1)
    logger_line = "logger = logging.getLogger(__name__)"
    assert logger_line in s, "vod logger anchor missing"
    header = open(os.path.join(ART, "vod_header_snippet.py"), encoding="utf-8").read()
    s = s.replace(logger_line, logger_line + "\n\n" + header, 1)
    rev = open(os.path.join(ART, "vod_reverse_snippet.py"), encoding="utf-8").read()
    if not s.endswith("\n"):
        s += "\n"
    s += rev
    open(vp, "w", encoding="utf-8").write(s)
    print("PATCHED app/services/vod_purchase.py (+reverse_vod_purchase)")

# 3) billing_disputes.py
bd = rp("app/services/billing_disputes.py")
s = open(bd, encoding="utf-8").read()
if '"source": source or "user"' in s:
    print("SKIP billing_disputes.py (DISP-001 fields already present)")
else:
    backup(bd)
    sig_old = (
        "    transaction_entry_id: Optional[str] = None,\n"
        "    provider: str = \"manual\",\n"
        "    provider_dispute_id: Optional[str] = None,\n"
        "    request_obj: Any = None,\n"
        ") -> Dict[str, Any]:\n"
        "    \"\"\"File a new dispute. Returns the created item dict.\"\"\""
    )
    assert sig_old in s, "billing_disputes file_dispute signature anchor missing"
    sig_new = (
        "    transaction_entry_id: Optional[str] = None,\n"
        "    provider: str = \"manual\",\n"
        "    provider_dispute_id: Optional[str] = None,\n"
        "    source: str = \"user\",\n"
        "    charge_type: str = \"\",\n"
        "    charge_ref: str = \"\",\n"
        "    linked_dispute_id: str = \"\",\n"
        "    request_obj: Any = None,\n"
        ") -> Dict[str, Any]:\n"
        "    \"\"\"File a new dispute. Returns the created item dict.\n\n"
        "    DISP-001: the unified dispute record spans both origins via ``source`` in\n"
        "    {user, processor}. ``charge_type`` (tip|message|subscription|ad|ecom|vod) +\n"
        "    ``charge_ref`` locate the underlying charge for the reversal-rail dispatcher;\n"
        "    ``rail_marker``/``resolution`` are stamped on resolution; ``linked_dispute_id``\n"
        "    cross-links a user<->processor dispute on the same charge. Existing stub rows\n"
        "    default ``source=user`` and empty charge_* (no behavior change).\n"
        "    \"\"\""
    )
    s = s.replace(sig_old, sig_new, 1)
    item_anchor = '        "transaction_entry_id": transaction_entry_id or "",\n        "created_at": ts,'
    assert item_anchor in s, "billing_disputes item anchor missing"
    item_new = (
        '        "transaction_entry_id": transaction_entry_id or "",\n'
        '        # DISP-001: unified dispute record fields (source discriminator + charge\n'
        '        # linkage + resolution/rail markers). source_scope backs a BySource GSI.\n'
        '        "source": source or "user",\n'
        "        \"source_scope\": f\"SOURCE#{source or 'user'}\",\n"
        '        "charge_type": charge_type or "",\n'
        '        "charge_ref": charge_ref or transaction_entry_id or "",\n'
        '        "linked_dispute_id": linked_dispute_id or "",\n'
        '        "rail_marker": "",\n'
        '        "created_at": ts,'
    )
    s = s.replace(item_anchor, item_new, 1)
    open(bd, "w", encoding="utf-8").write(s)
    print("PATCHED app/services/billing_disputes.py (+DISP-001 unified record fields)")

# AST sanity
import ast
for f in (dd_dst, vp, bd):
    ast.parse(open(f, encoding="utf-8").read())
print("AST OK for all three files")
print("DISP E0 fold applied.")
