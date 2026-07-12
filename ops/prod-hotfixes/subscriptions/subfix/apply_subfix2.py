import sys, os, shutil, glob, subprocess, hashlib, py_compile

TARGET = os.environ.get("SUBFIX_TARGET", "app/services/subscription_cycle_orders.py")
BAK = os.environ.get("SUBFIX_BAK")
DRY = "--dry" in sys.argv

src = open(TARGET, "r", encoding="utf-8").read()
orig = src

A_OLD = '''    def put_entitlement(self, record: Any) -> None:
        super().put_entitlement(record)
        item = self._serialize_record(record)
        try:
            self.entitlements_table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(entitlement_id)",
            )
'''
A_NEW = '''    def put_entitlement(self, record: Any) -> None:
        super().put_entitlement(record)
        item = self._serialize_record(record)
        # The entitlements table backs GSIs on ends_at/starts_at/status/sku (all
        # type S). A subscription cycle entitlement legitimately has ends_at=None
        # (open-ended, bounded by the subscription lifecycle instead). DynamoDB
        # rejects a NULL value for an index-key attribute with "Invalid attribute
        # value type", which previously dead-lettered every grant. Drop None
        # attributes so the put succeeds (sparse-index semantics).
        item = {k: v for k, v in item.items() if v is not None}
        try:
            self.entitlements_table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(entitlement_id)",
            )
'''

if "sparse-index semantics" not in src:
    assert A_OLD in src, "put_entitlement anchor not found"
    src = src.replace(A_OLD, A_NEW, 1)

changed = src != orig
print("PATH", TARGET, "changed:", changed, "has_fix:", "sparse-index semantics" in src)
if DRY:
    print("DRY - not writing"); sys.exit(0)
if changed:
    if BAK:
        b = TARGET + ".bak_" + BAK
        shutil.copy2(TARGET, b); print("backup:", b)
    open(TARGET, "w", encoding="utf-8").write(src)
    print("WROTE", TARGET)
else:
    print("already patched")
py_compile.compile(TARGET, doraise=True)
print("py_compile OK")
