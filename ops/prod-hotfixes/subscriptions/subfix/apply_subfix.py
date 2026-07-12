import sys, os, time, shutil
DRY = "--dry" in sys.argv
BAK = os.environ.get("SUBFIX_BAK")  # if set, cp .bak_<BAK> before writing
PATH = os.environ.get("SUBFIX_TARGET", "app/services/subscription_cycle_orders.py")

src = open(PATH, "r", encoding="utf-8").read()
orig = src

# ---- Patch 1: header-sk constant -------------------------------------------
A1 = 'SUBSCRIPTION_SYSTEM_PROVIDER = "subscription_system"\n'
A1_NEW = A1 + 'ORDER_HEADER_SK = "ORDER"\n'
if 'ORDER_HEADER_SK' not in src:
    assert A1 in src, "anchor A1 (provider const) not found"
    src = src.replace(A1, A1_NEW, 1)

# ---- Patch 2: fix get_order to read the composite-key header row ------------
A2_OLD = '''    def get_order(self, order_id: str) -> Optional[Dict[str, Any]]:
        cached = super().get_order(order_id)
        if cached is not None:
            return cached
        try:
            item = self.orders_table.get_item(Key={"order_id": order_id}).get("Item")
        except Exception:
            item = None
        if item is None:
            return None
        self.orders[order_id] = dict(item)
        return self.orders[order_id]
'''
A2_NEW = '''    def _load_order_row(self, order_id: str) -> Optional[Dict[str, Any]]:
        # The canonical `orders` table uses a COMPOSITE key (order_id HASH, sk
        # RANGE); the order header row is written under sk="ORDER" (ecom ORD-003).
        # A plain get_item(Key={"order_id": ...}) therefore raises a schema
        # ValidationException, which the old code swallowed -> the order looked
        # "missing" -> BOTH the subscription cycle reconcile (missing_order) and
        # the ecom commerce entitlement orchestrator ("order not found")
        # dead-lettered. Read the header row correctly, with fallbacks for any
        # legacy single-key orders table.
        try:
            item = self.orders_table.get_item(
                Key={"order_id": order_id, "sk": ORDER_HEADER_SK}
            ).get("Item")
            if item is not None:
                return dict(item)
        except Exception:
            pass
        try:
            item = self.orders_table.get_item(Key={"order_id": order_id}).get("Item")
            if item is not None:
                return dict(item)
        except Exception:
            pass
        try:
            resp = self.orders_table.query(KeyConditionExpression=Key("order_id").eq(order_id))
            rows = [dict(it) for it in resp.get("Items", [])]
            if rows:
                return next((r for r in rows if str(r.get("sk") or "") == ORDER_HEADER_SK), rows[0])
        except Exception:
            pass
        return None

    def get_order(self, order_id: str) -> Optional[Dict[str, Any]]:
        cached = super().get_order(order_id)
        if cached is not None:
            return cached
        item = self._load_order_row(order_id)
        if item is None:
            return None
        self.orders[order_id] = dict(item)
        return self.orders[order_id]
'''
if '_load_order_row' not in src:
    assert A2_OLD in src, "anchor A2 (get_order) not found"
    src = src.replace(A2_OLD, A2_NEW, 1)

# ---- Patch 3: mark the cycle order paid so the grant is ACTIVE --------------
A3_HELPER_ANCHOR = 'def _subscription_charge_event_id(invoice_id: str) -> str:\n    return f"subscription_charge:{invoice_id}"\n'
A3_HELPER_NEW = A3_HELPER_ANCHOR + '''

def _mark_subscription_order_paid(order_id: str) -> None:
    """Best-effort: stamp the cycle order header row `paid`.

    A subscription cycle order is emitted only AFTER the cycle invoice has been
    collected (subscribe / renewal / trial-conversion charge succeeded), so the
    canonical order is already paid. Marking it paid lets the downstream
    reconcile grant an ACTIVE entitlement instead of leaving it pending_payment.
    Never allowed to break the money path -> every failure is swallowed.
    """
    if not order_id:
        return
    now_iso = datetime.now(timezone.utc).isoformat()
    for key in ({"order_id": order_id, "sk": ORDER_HEADER_SK}, {"order_id": order_id}):
        try:
            T.orders.update_item(
                Key=key,
                UpdateExpression="SET #s = :paid, updated_at = :now",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":paid": "paid", ":now": now_iso},
                ConditionExpression="attribute_exists(order_id)",
            )
            return
        except Exception:
            continue
'''
if '_mark_subscription_order_paid' not in src:
    assert A3_HELPER_ANCHOR in src, "anchor A3 helper not found"
    src = src.replace(A3_HELPER_ANCHOR, A3_HELPER_NEW, 1)

A3_CALL_ANCHOR = '''    order_id = str(order.get("order_id") or "")
    reconciliation_result: Dict[str, Any] = {"status": "skipped", "reason": "disabled"}
'''
A3_CALL_NEW = '''    order_id = str(order.get("order_id") or "")
    # Cycle already charged upstream -> mark the canonical order paid so the
    # reconcile grants an ACTIVE entitlement (best-effort, never breaks money).
    _mark_subscription_order_paid(order_id)
    reconciliation_result: Dict[str, Any] = {"status": "skipped", "reason": "disabled"}
'''
if '_mark_subscription_order_paid(order_id)' not in src:
    assert A3_CALL_ANCHOR in src, "anchor A3 call not found"
    src = src.replace(A3_CALL_ANCHOR, A3_CALL_NEW, 1)

changed = (src != orig)
print("PATH", PATH)
print("changed:", changed)
print("has_load_order_row:", '_load_order_row' in src)
print("has_mark_paid:", '_mark_subscription_order_paid' in src)
print("has_const:", 'ORDER_HEADER_SK' in src)

if DRY:
    print("DRY RUN - not writing")
    sys.exit(0)

if changed:
    if BAK:
        bpath = PATH + ".bak_" + BAK
        shutil.copy2(PATH, bpath)
        print("backup:", bpath)
    open(PATH, "w", encoding="utf-8").write(src)
    print("WROTE", PATH)
else:
    print("already patched, no write")

# compile check
import py_compile
py_compile.compile(PATH, doraise=True)
print("py_compile OK")
