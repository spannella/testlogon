p="app/routers/catalog.py"
s=open(p).read()
old='''    sc = updated.get("stock_count")
    return CatalogStockOut(
        item_id=item_id,
        stock_count=int(sc) if sc is not None else None,
        stock_status=_compute_stock_status(updated),
        low_stock_threshold=int(updated.get("low_stock_threshold") or S.catalog_default_low_stock_threshold),
        stock_updated_at=updated.get("stock_updated_at"),
    )'''
new='''    sc = updated.get("stock_count")
    # ECOMX-54: notify wishlisters when stock changes (e.g. restock).
    _wl_item = dict(updated)
    _wl_item.setdefault("item_id", item_id)
    _notify_wishlist_watchers(category_id, _wl_item)
    return CatalogStockOut(
        item_id=item_id,
        stock_count=int(sc) if sc is not None else None,
        stock_status=_compute_stock_status(updated),
        low_stock_threshold=int(updated.get("low_stock_threshold") or S.catalog_default_low_stock_threshold),
        stock_updated_at=updated.get("stock_updated_at"),
    )'''
assert old in s, "adjust_stock return missing"
s=s.replace(old,new,1)
open(p,"w").write(s)
print("adjust_stock wishlist hook added")
