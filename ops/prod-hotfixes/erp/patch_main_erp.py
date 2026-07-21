#!/usr/bin/env python3
"""Idempotent anchor patcher: mount the ERP GL/AR/pricing routers in app/main.py.

Injects the identical include_router block used on the dev clone, immediately
after the entitlement_requests conditional mount. Byte-identical anchor
(md5 d073c526...) confirmed present on prod before running. Idempotent: if the
block is already present, does nothing.
"""
import sys

P = "app/main.py"
s = open(P).read()

if "erp_gl_router" in s:
    print("PATCH: already mounted, skipping")
    sys.exit(0)

anchor = (
    '    if getattr(_S, "open_bank_project_enabled", False) and getattr(_S, "entitlement_requests_enabled", False):\n'
    '        from app.routers.entitlement_requests import router as entitlement_requests_router\n'
    '        app.include_router(entitlement_requests_router)\n'
)
if s.count(anchor) != 1:
    print("PATCH: anchor not unique (count=%d) — ABORT" % s.count(anchor))
    sys.exit(2)

inject = anchor + (
    "    # ── ERP finance admin surfaces (P1): mount the previously-unmounted GL /\n"
    "    # AR / pricing-rule services over an operator/admin (require_admin_or_root)\n"
    "    # surface. Each is flag-gated to its own ERP flag; the services themselves\n"
    "    # also re-check the flag. Role-based auth (no api-key policy dep) so no\n"
    "    # scope-registry entry is required and boot never RuntimeErrors.\n"
    '    if getattr(_S, "gl_double_entry_enabled", False):\n'
    "        from app.routers.erp_gl import router as erp_gl_router\n"
    "        app.include_router(erp_gl_router)\n"
    '    if getattr(_S, "ar_ap_subledgers_enabled", False):\n'
    "        from app.routers.erp_ar import router as erp_ar_router\n"
    "        app.include_router(erp_ar_router)\n"
    '    if getattr(_S, "pricing_rules_enabled", False):\n'
    "        from app.routers.erp_pricing import router as erp_pricing_router\n"
    "        app.include_router(erp_pricing_router)\n"
)
s = s.replace(anchor, inject, 1)
open(P, "w").write(s)
print("PATCH: mounted erp routers")
