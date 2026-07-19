#!/usr/bin/env python3
"""selldash E1 — anchor-patch app/models.py on PROD (models.py diverges from the
dev clone, so we cannot copy the whole file). Idempotent: a re-run is a no-op
once OrderShipmentOut is present. Same four insertions applied on dev."""
import sys

p = "app/models.py"
s = open(p, encoding="utf-8").read()
orig = s

if "class OrderShipmentOut(BaseModel):" in s:
    print("models.py already has OrderShipmentOut — no-op")
    sys.exit(0)

# 1) Insert OrderShipmentOut model right before OrderLifecycleOut.
model_def = '''class OrderShipmentOut(BaseModel):
    """ECOMX-E1: compact inline shipment surfaced on the buyer ORDER list/detail.

    Joined from the seller ship-group(s) belonging to the order (via the
    order_fulfillment_bridge) so the buyer sees the real carrier / tracking# /
    status the seller entered WITHOUT needing the ship_group_id."""
    ship_group_id: str = ""
    carrier: str = ""
    tracking_number: str = ""
    tracking_url: str = ""
    status: str = ""
    last_event: Optional[Dict[str, Any]] = None
    updated_at: int = Field(default=0, ge=0)


class OrderLifecycleOut(BaseModel):'''
anchor = "class OrderLifecycleOut(BaseModel):"
assert s.count(anchor) == 1, "anchor OrderLifecycleOut count!=1"
s = s.replace(anchor, model_def, 1)

# 2) Add shipments + fulfillment_status to OrderLifecycleOut.
li_anchor = '    # ── Joined order items; populated by get_order_lifecycle ──\n    line_items: Optional[List["OrderLineItemOut"]] = None'
assert s.count(li_anchor) == 1, "line_items anchor count!=1"
s = s.replace(li_anchor, li_anchor + '''

    # ── ECOMX-E1: buyer-visible inline shipments joined from the seller ship
    # groups + their tracking (carrier/number/status/last-event) so the buyer
    # order DETAIL surfaces tracking without the ship_group_id. None=not fetched.
    fulfillment_status: Optional[str] = None
    shipments: Optional[List["OrderShipmentOut"]] = None''', 1)

# 3) Add fulfillment_status + shipments to OrderListItem.
lit_anchor = '''    amount_cents: int = Field(default=0, ge=0)
    currency: str = "USD"
    line_item_count: int = Field(default=0, ge=0)


class OrderListOut(BaseModel):'''
assert s.count(lit_anchor) == 1, "OrderListItem tail anchor count!=1"
s = s.replace(lit_anchor, '''    amount_cents: int = Field(default=0, ge=0)
    currency: str = "USD"
    line_item_count: int = Field(default=0, ge=0)
    # ── ECOMX-E1: buyer-visible inline shipments (list view) ──
    fulfillment_status: Optional[str] = None
    shipments: List["OrderShipmentOut"] = Field(default_factory=list)


class OrderListOut(BaseModel):''', 1)

# 4) Rebuild the list models so the OrderShipmentOut forward ref resolves.
rebuild_anchor = '''class OrderListOut(BaseModel):
    orders: List[OrderListItem] = Field(default_factory=list)
    next_cursor: Optional[str] = None'''
assert s.count(rebuild_anchor) == 1, "OrderListOut rebuild anchor count!=1"
s = s.replace(rebuild_anchor, rebuild_anchor + '''


# ECOMX-E1: resolve the OrderShipmentOut forward ref on the list models.
OrderListItem.model_rebuild()
OrderListOut.model_rebuild()''', 1)

assert s != orig, "no change made"
open(p, "w", encoding="utf-8").write(s)
print("patched models.py OK (selldash E1)")
