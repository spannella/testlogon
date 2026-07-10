"""ECOM-SELLER (G1-G4) idempotent apply: per-seller ship-groups + seller-scoped
sales endpoint + "you sold it" notify + G4 real line names + new DDB table.

Idempotent + anchored (works on divergent prod AND dev clone). ROOT env selects
the tree (default /home/ubuntu/testlogon); set ROOT=/tmp/probe_ecomsell to probe.
"""
import base64, os, sys, py_compile

ROOT = os.environ.get("ROOT", "/home/ubuntu/testlogon")
PROBE = os.environ.get("PROBE", "0") == "1"

SVC_B64 = "__SVC_B64__"
ROUTER_B64 = "__ROUTER_B64__"

log = []
def note(x): log.append(x); print(x)

def write_new(relpath, b64):
    path = os.path.join(ROOT, relpath)
    content = base64.b64decode(b64).decode("utf-8")
    if os.path.exists(path) and open(path, encoding="utf-8").read() == content:
        note(f"SKIP (identical) {relpath}"); return path
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    note(f"WROTE {relpath} ({len(content)} bytes)"); return path

def edit(relpath, marker, anchor, insert_after=True, replacement=None):
    """If marker already in file -> SKIP. Else anchor-replace."""
    path = os.path.join(ROOT, relpath)
    txt = open(path, encoding="utf-8").read()
    if marker in txt:
        note(f"SKIP (marker present) {relpath}"); return
    if anchor not in txt:
        note(f"!! ANCHOR MISSING in {relpath}: {anchor[:60]!r}"); return
    if replacement is not None:
        newtxt = txt.replace(anchor, replacement, 1)
    else:
        newtxt = txt  # not used
    if newtxt == txt:
        note(f"!! NO-OP replace {relpath}"); return
    with open(path, "w", encoding="utf-8") as f:
        f.write(newtxt)
    note(f"EDITED {relpath}")

# 1) new files ---------------------------------------------------------------
write_new("app/services/seller_ship_groups.py", SVC_B64)
write_new("app/routers/seller_ship_groups.py", ROUTER_B64)

# 2) shoppingcart approval hook ----------------------------------------------
SC_ANCHOR = (
    '        _logging_ol.getLogger(__name__).exception(\n'
    '            "Failed to advance order lifecycle for cart %s order %s", cart_id, order_id\n'
    '        )\n'
)
SC_INSERT = SC_ANCHOR + (
    "\n"
    "    # ECOM-SELLER (G1-G4): on order approval, split the paid cart into per-seller\n"
    "    # ship-groups (each = that seller's line items w/ REAL names + the buyer ship\n"
    "    # address), notify each seller (you-sold-it alert+push), backfill line names.\n"
    "    try:\n"
    "        if S.order_lifecycle_enabled and order_id:\n"
    "            from app.services import seller_ship_groups as _ssg\n"
    "            _ssg.populate_on_approval(\n"
    "                order_id=order_id,\n"
    "                buyer_sub=user_sub,\n"
    "                cart_items=items,\n"
    "                buyer=buyer,\n"
    "                currency=str(cart.get(\"currency\", \"USD\")),\n"
    "            )\n"
    "    except Exception:\n"
    "        import logging as _lg_ssg\n"
    "        _lg_ssg.getLogger(__name__).exception(\"seller ship-group populate failed for order %s\", order_id)\n"
)
edit("app/services/shoppingcart.py", "ECOM-SELLER (G1-G4)", SC_ANCHOR, replacement=SC_INSERT)

# 3) main.py import + include ------------------------------------------------
edit("app/main.py", "seller_ship_groups import router as seller_sales_router",
     "from app.routers.orders import router as orders_adj_ship_router\n",
     replacement="from app.routers.orders import router as orders_adj_ship_router\n"
                 "from app.routers.seller_ship_groups import router as seller_sales_router  # ECOM-SELLER\n")
edit("app/main.py", "include_router(seller_sales_router)",
     "    app.include_router(orders_adj_ship_router)\n",
     replacement="    app.include_router(orders_adj_ship_router)\n"
                 "    app.include_router(seller_sales_router)  # ECOM-SELLER seller-scoped sales\n")

# 4) settings.py table name --------------------------------------------------
edit("app/core/settings.py", "seller_ship_groups_table_name",
     '    order_items_table_name: str = os.environ.get("ORDER_ITEMS_TABLE_NAME", "order_items")\n',
     replacement='    order_items_table_name: str = os.environ.get("ORDER_ITEMS_TABLE_NAME", "order_items")\n'
                 '    seller_ship_groups_table_name: str = os.environ.get("SELLER_SHIP_GROUPS_TABLE_NAME", "seller_ship_groups")\n')

# 5) tables.py field + registration ------------------------------------------
edit("app/core/tables.py", "seller_ship_groups: Any",
     "    order_items: Any\n",
     replacement="    order_items: Any\n    seller_ship_groups: Any\n")
edit("app/core/tables.py", "seller_ship_groups=_safe_table",
     "    order_items=_safe_table(S.order_items_table_name),\n",
     replacement="    order_items=_safe_table(S.order_items_table_name),\n"
                 "    seller_ship_groups=_safe_table(S.seller_ship_groups_table_name),\n")

# 6) local-ddb-init TableDef -------------------------------------------------
DDB_ANCHOR = '        TableDef(_resolve_table_name(S.order_items_table_name, "order_items"), "order_id", "item_id"),\n'
DDB_INSERT = DDB_ANCHOR + (
    '        TableDef(\n'
    '            _resolve_table_name(S.seller_ship_groups_table_name, "seller_ship_groups"),\n'
    '            "seller_id",\n'
    '            "ship_group_id",\n'
    '            gsi=[\n'
    '                {"index_name": "GSI_ORDER", "partition_key": "order_id", "sort_key": "ship_group_id"},\n'
    '            ],\n'
    '        ),\n'
)
edit("scripts/local-ddb-init.py", "seller_ship_groups", DDB_ANCHOR, replacement=DDB_INSERT)

# 7) create the DDB table (idempotent) ---------------------------------------
if not PROBE:
    sys.path.insert(0, ROOT)
    os.chdir(ROOT)
    try:
        from app.core.tables import T
        from app.core.settings import S as _S
        client = T.order_items.meta.client
        name = _S.seller_ship_groups_table_name
        try:
            client.create_table(
                TableName=name,
                KeySchema=[
                    {"AttributeName": "seller_id", "KeyType": "HASH"},
                    {"AttributeName": "ship_group_id", "KeyType": "RANGE"},
                ],
                AttributeDefinitions=[
                    {"AttributeName": "seller_id", "AttributeType": "S"},
                    {"AttributeName": "ship_group_id", "AttributeType": "S"},
                    {"AttributeName": "order_id", "AttributeType": "S"},
                ],
                GlobalSecondaryIndexes=[{
                    "IndexName": "GSI_ORDER",
                    "KeySchema": [
                        {"AttributeName": "order_id", "KeyType": "HASH"},
                        {"AttributeName": "ship_group_id", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }],
                BillingMode="PAY_PER_REQUEST",
            )
            note(f"CREATED TABLE {name}")
        except client.exceptions.ResourceInUseException:
            note(f"TABLE EXISTS {name}")
        except Exception as e:
            if "ResourceInUseException" in type(e).__name__ or "Table already exists" in str(e):
                note(f"TABLE EXISTS {name}")
            else:
                note(f"!! create_table error: {e!r}")
    except Exception as e:
        note(f"!! table step error: {e!r}")

# 8) py_compile the touched python files -------------------------------------
for f in ["app/services/seller_ship_groups.py", "app/routers/seller_ship_groups.py",
          "app/services/shoppingcart.py", "app/main.py", "app/core/settings.py",
          "app/core/tables.py", "scripts/local-ddb-init.py"]:
    p = os.path.join(ROOT, f)
    try:
        py_compile.compile(p, doraise=True)
    except Exception as e:
        note(f"!! PYCOMPILE FAIL {f}: {e}")
    else:
        note(f"pycompile OK {f}")

print("APPLY_DONE")
