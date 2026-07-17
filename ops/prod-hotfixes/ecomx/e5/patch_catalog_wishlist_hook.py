p="app/routers/catalog.py"
s=open(p).read()

# Add a helper right after the logger definition.
helper='''

def _notify_wishlist_watchers(category_id: str, item: Dict[str, Any]) -> None:
    """ECOMX-54: fire wishlist restock / price-drop alerts for a changed item.
    Best-effort; never raises into the catalog write path."""
    try:
        from app.services.wishlist_watch import notify_item_changed
        item_id = str(item.get("item_id") or item.get("id") or "")
        if not item_id:
            return
        notify_item_changed(
            str(category_id),
            item_id,
            new_stock_status=_compute_stock_status(item),
            new_price_cents=(int(item["price_cents"]) if item.get("price_cents") is not None else None),
        )
    except Exception:
        logger.exception("wishlist watcher failed for %s/%s", category_id, item.get("item_id"))
'''
anchor="logger = logging.getLogger(__name__)\n"
assert anchor in s
s=s.replace(anchor, anchor+helper, 1)

# Hook update_item: before returning the item.
old_u='''    item = resp.get("Attributes")
    if not item:
        raise HTTPException(status_code=404, detail="Item not found.")
    return _catalog_item_out(item)'''
new_u='''    item = resp.get("Attributes")
    if not item:
        raise HTTPException(status_code=404, detail="Item not found.")
    # ECOMX-54: notify wishlisters on price/stock change.
    if body.price_cents is not None or body.stock_count is not None:
        _notify_wishlist_watchers(category_id, item)
    return _catalog_item_out(item)'''
assert old_u in s, "update_item return missing"
s=s.replace(old_u,new_u,1)

open(p,"w").write(s)
print("update_item wishlist hook added")
