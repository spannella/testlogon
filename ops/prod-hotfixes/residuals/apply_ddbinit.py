#!/usr/bin/env python3
"""MOD-1: register the ByOffenderCreatedAt GSI on the UserEnforcementHistory table
in scripts/local-ddb-init.py so a fresh local/CI DDB is created with the offender
index (prod gets it via update_table). Idempotent. Run: python apply_ddbinit.py [ROOT]
"""
import sys, os
ROOT = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
FP = os.path.join(ROOT, "scripts/local-ddb-init.py")
src = open(FP, encoding="utf-8").read()

if '"index_name": "ByOffenderCreatedAt"' in src:
    print("SKIP: ByOffenderCreatedAt already registered.")
    raise SystemExit(0)

OLD = '''                {
                    "index_name": "BySourceTicketCreatedAt",
                    "partition_key": "source_ticket_id",
                    "sort_key": "created_at",
                },
            ],
        ),
        TableDef(
            _resolve_table_name(S.dmca_claims_table_name, "DmcaClaims"),'''
NEW = '''                {
                    "index_name": "BySourceTicketCreatedAt",
                    "partition_key": "source_ticket_id",
                    "sort_key": "created_at",
                },
                {
                    # MOD-1: complete offender history (all enforcement records for a
                    # user, newest-first) for the admin offender summary / detail.
                    # Hashes on the existing user_id (the offender) so every row is
                    # auto-indexed with no new attribute / backfill.
                    "index_name": "ByOffenderCreatedAt",
                    "partition_key": "user_id",
                    "sort_key": "created_at",
                },
            ],
        ),
        TableDef(
            _resolve_table_name(S.dmca_claims_table_name, "DmcaClaims"),'''
assert src.count(OLD) == 1, "enforcement TableDef anchor not unique/found"
src = src.replace(OLD, NEW)
open(FP, "w", encoding="utf-8").write(src)
print("WROTE scripts/local-ddb-init.py (ByOffenderCreatedAt GSI)")
