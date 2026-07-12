"""Idempotent, anchor-matched apply for LIVE-STREAM COMMERCE (LIVECOM L1-L4).

Patches existing files (settings/tables/models/shoppingcart/router/main). The three
NEW service+router files are pushed separately. Safe to re-run on prod AND the
divergent dev clone: every edit is guarded by a presence check.

Usage:  python apply_livecom.py <repo_base>
"""
import sys, os, py_compile

BASE = sys.argv[1] if len(sys.argv) > 1 else "/home/ubuntu/testlogon"


def read(p):
    return open(os.path.join(BASE, p), encoding="utf-8").read()


def write(p, s):
    open(os.path.join(BASE, p), "w", encoding="utf-8").write(s)


def patch(path, anchor, insert, marker):
    txt = read(path)
    if marker in txt:
        print("SKIP  %-28s (marker present)" % path)
        return txt
    if anchor not in txt:
        print("FAIL  %-28s ANCHOR NOT FOUND: %r" % (path, anchor[:60]))
        raise SystemExit(2)
    if txt.count(anchor) != 1:
        print("FAIL  %-28s anchor not unique (%d)" % (path, txt.count(anchor)))
        raise SystemExit(2)
    txt = txt.replace(anchor, anchor + insert)
    write(path, txt)
    print("PATCH %-28s ok" % path)
    return txt


def replace(path, old, new, marker):
    txt = read(path)
    if marker in txt:
        print("SKIP  %-28s (marker present)" % path)
        return txt
    if old not in txt:
        print("FAIL  %-28s OLD NOT FOUND" % path)
        raise SystemExit(2)
    if txt.count(old) != 1:
        print("FAIL  %-28s old not unique (%d)" % (path, txt.count(old)))
        raise SystemExit(2)
    write(path, txt.replace(old, new))
    print("REPL  %-28s ok" % path)
    return txt


# A) settings.py -- new table name
patch("app/core/settings.py",
      '    shipment_tracking_table_name: str = os.environ.get("SHIPMENT_TRACKING_TABLE_NAME", "shipment_tracking")',
      '\n    live_stream_products_table_name: str = os.environ.get("DDB_LIVE_STREAM_PRODUCTS", "LiveStreamProducts")',
      "live_stream_products_table_name")

# B) tables.py -- dataclass field + instantiation
patch("app/core/tables.py",
      "    shipment_tracking: Any",
      "\n    live_stream_products: Any",
      "live_stream_products: Any")
patch("app/core/tables.py",
      "    shipment_tracking=_safe_table(S.shipment_tracking_table_name),",
      "\n    live_stream_products=_safe_table(S.live_stream_products_table_name),",
      "live_stream_products=_safe_table")

# C) models.py -- CartPurchaseIn attribution fields (L3)
patch("app/models.py",
      "    # ADV-403: optional last-click CPA attribution handle carried from an ad CTA.\n    ad_click_id: Optional[str] = None",
      "\n    # LIVECOM L3: in-stream purchase attribution (broadcast session + host).\n    broadcast_session_id: Optional[str] = None\n    host_id: Optional[str] = None",
      "LIVECOM L3: in-stream purchase attribution")

# D) routers/shoppingcart.py -- thread attribution into purchase_cart()
replace("app/routers/shoppingcart.py",
        "    purchase = purchase_cart(\n"
        "        ctx[\"user_sub\"],\n"
        "        cart_id,\n"
        "        idempotency_key=idem,\n"
        "        promo_code=body.promo_code,\n"
        "        promo_code_id=body.promo_code_id,\n"
        "    )",
        "    purchase = purchase_cart(\n"
        "        ctx[\"user_sub\"],\n"
        "        cart_id,\n"
        "        idempotency_key=idem,\n"
        "        promo_code=body.promo_code,\n"
        "        promo_code_id=body.promo_code_id,\n"
        "        broadcast_session_id=getattr(body, \"broadcast_session_id\", None),  # LIVECOM L3\n"
        "        host_id=getattr(body, \"host_id\", None),\n"
        "    )",
        "broadcast_session_id=getattr(body")

# E) shoppingcart.py -- purchase_cart signature params
replace("app/services/shoppingcart.py",
        "    idempotency_key: str | None = None,\n"
        "    promo_code: str | None = None,\n"
        "    promo_code_id: str | None = None,\n"
        ") -> Dict[str, Any]:\n"
        "    cart = get_cart(user_sub, cart_id)",
        "    idempotency_key: str | None = None,\n"
        "    promo_code: str | None = None,\n"
        "    promo_code_id: str | None = None,\n"
        "    broadcast_session_id: str | None = None,  # LIVECOM L3\n"
        "    host_id: str | None = None,\n"
        ") -> Dict[str, Any]:\n"
        "    cart = get_cart(user_sub, cart_id)",
        "broadcast_session_id: str | None = None,  # LIVECOM L3")

# F) shoppingcart.py -- thread attribution onto the order metadata (L3)
replace("app/services/shoppingcart.py",
        '        metadata={\n'
        '            "cart_id": cart_id,\n'
        '            "idempotency_key": canonical_idempotency_key,',
        '        metadata={\n'
        '            "cart_id": cart_id,\n'
        '            "broadcast_session_id": broadcast_session_id,  # LIVECOM L3\n'
        '            "host_id": host_id,\n'
        '            "is_stream_attributed": bool(broadcast_session_id),\n'
        '            "idempotency_key": canonical_idempotency_key,',
        '"broadcast_session_id": broadcast_session_id,  # LIVECOM L3')

# G) shoppingcart.py -- skip legacy seller credit for stream carts
replace("app/services/shoppingcart.py",
        "        _by_creator = {}\n        for _ci in items:",
        "        _by_creator = {}\n        _stream_attributed = bool(broadcast_session_id)  # LIVECOM L4\n        for _ci in items:",
        "_stream_attributed = bool(broadcast_session_id)")
replace("app/services/shoppingcart.py",
        "        _gross = sum(_by_creator.values())\n        for _cid, _amt in _by_creator.items():",
        "        _gross = sum(_by_creator.values())\n        for _cid, _amt in ({}.items() if _stream_attributed else _by_creator.items()):  # LIVECOM L4",
        "if _stream_attributed else _by_creator.items()")

# H) shoppingcart.py -- invoke the commission split after the legacy block (L4)
patch("app/services/shoppingcart.py",
      '        _logging.getLogger(__name__).exception("Failed to write seller credit ledger for cart %s", cart_id)',
      "\n\n    # LIVECOM L4: stream-attributed commission split (host commission + seller\n"
      "    # net + platform fee), idempotent per order. Replaces the legacy seller\n"
      "    # credit for in-stream sales (skipped above when broadcast_session_id set).\n"
      "    if broadcast_session_id:\n"
      "        try:\n"
      "            from app.services.live_commerce_split import settle_stream_order as _settle_livecom\n"
      "            _settle_livecom(order_id=order_id, session_id=broadcast_session_id,\n"
      "                            host_id=host_id, buyer_sub=user_sub, items=items,\n"
      "                            final_total=final_total, currency=cart.get(\"currency\", \"USD\"),\n"
      "                            cart_id=cart_id, txn_id=txn_id)\n"
      "        except Exception:\n"
      "            import logging as _lg_lc\n"
      "            _lg_lc.getLogger(__name__).exception(\"livecom split failed for order %s\", order_id)",
      "LIVECOM L4: stream-attributed commission split")

# I) main.py -- register the router
patch("app/main.py",
      "    app.include_router(creator_payouts_router)",
      "\n    from app.routers.live_commerce import router as live_commerce_router  # LIVECOM\n    app.include_router(live_commerce_router)",
      "live_commerce_router")

# compile touched files
for p in ["app/core/settings.py", "app/core/tables.py", "app/models.py",
          "app/routers/shoppingcart.py", "app/services/shoppingcart.py", "app/main.py",
          "app/services/live_stream_products.py", "app/services/live_commerce_split.py",
          "app/routers/live_commerce.py"]:
    py_compile.compile(os.path.join(BASE, p), doraise=True)
    print("COMPILE_OK", p)

print("APPLY_DONE")
