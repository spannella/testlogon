p="app/services/alerts.py"
s=open(p).read()

# 1) category: add the new commerce events to the commerce category
old_cat='''    "commerce": {"cart.abandoned", "order_shipped", "order_out_for_delivery", "order_delivered"},'''
new_cat='''    "commerce": {"cart.abandoned", "order_shipped", "order_out_for_delivery", "order_delivered",
                 "shop_item_sold", "review_received", "order_refunded",
                 "refund_approved", "refund_denied",
                 "wishlist_restock", "wishlist_price_drop"},'''
assert old_cat in s, "commerce category missing"
s=s.replace(old_cat,new_cat,1)

# 2) url_map: add deep-links for the new events. Insert after moderation block.
anchor='''        "moderation_content_restored": "/moderation/review",
    }
    return url_map.get(alert_type)'''
new_block='''        "moderation_content_restored": "/moderation/review",
        # ECOMX-52 (E5): commerce comms deep-link to real, non-empty screens.
        "review_received":  (f"/catalog/items/{details.get('item_id')}#reviews" if details.get("item_id") else "/seller/analytics"),
        "order_refunded":   (f"/orders?order={details.get('order_id')}" if details.get("order_id") else "/purchases"),
        "refund_approved":  (f"/orders?order={details.get('order_id')}" if details.get("order_id") else "/purchases"),
        "refund_denied":    (f"/orders?order={details.get('order_id')}" if details.get("order_id") else "/purchases"),
        "wishlist_restock":    (f"/catalog/items/{details.get('item_id')}" if details.get("item_id") else "/wishlist"),
        "wishlist_price_drop": (f"/catalog/items/{details.get('item_id')}" if details.get("item_id") else "/wishlist"),
    }
    return url_map.get(alert_type)'''
assert anchor in s, "url_map anchor missing"
s=s.replace(anchor,new_block,1)

# 3) ALERT_EVENT_TYPES: register the new events (so prefs/push respect them)
anchor2='''    # Commerce / buyer delivery lifecycle (ECOM D4)
    "order_out_for_delivery",
    "order_delivered",'''
new2='''    # Commerce / buyer delivery lifecycle (ECOM D4)
    "order_out_for_delivery",
    "order_delivered",
    # ECOMX-52 (E5): commerce comms completeness (default-on transactional).
    "review_received",
    "order_refunded",
    "refund_approved",
    "refund_denied",
    # ECOMX-54 (E5): wishlist restock / price-drop watcher alerts.
    "wishlist_restock",
    "wishlist_price_drop",'''
assert anchor2 in s, "ALERT_EVENT_TYPES anchor missing"
s=s.replace(anchor2,new2,1)

# 4) DEFAULT_PUSH_EVENT_TYPES: default-ON push for the transactional ones
anchor3='''    "order_delivered",         # your order was delivered (buyer, D4)'''
new3='''    "order_delivered",         # your order was delivered (buyer, D4)
    "review_received",         # ECOMX-52: a buyer reviewed your item (seller)
    "order_refunded",          # ECOMX-52: your order was refunded (buyer)
    "refund_approved",         # ECOMX-52: your refund request was approved (buyer)
    "refund_denied",           # ECOMX-52: your refund request was denied (buyer)
    "wishlist_restock",        # ECOMX-54: a wishlisted item is back in stock (buyer)
    "wishlist_price_drop",     # ECOMX-54: a wishlisted item dropped in price (buyer)'''
assert anchor3 in s, "DEFAULT_PUSH anchor missing"
s=s.replace(anchor3,new3,1)

open(p,"w").write(s)
print("alerts.py patched (E5 commerce notifications registered)")
