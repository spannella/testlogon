from __future__ import annotations

from typing import Dict, Iterable, List, TypedDict


class RouteScopePolicy(TypedDict):
    product: str
    required_scopes: List[str]
    entitlement_required: bool


class RouteExemption(TypedDict):
    reason: str


# Initial rollout scope registry across filemanager, newsfeed, tickets, shopping, messager.
API_KEY_ROUTE_SCOPE_REGISTRY: Dict[str, RouteScopePolicy] = {
    # File Manager -- APIK-E3 (#118): real fs product surface promoted from fail-closed
    # exemptions. read/write/share; entitlement_required=True. Intentional blocks
    # (mount-credential ops + admin/* + client-telemetry + purge-deleted + usage/*) stay exempt.
    # filemanager:admin inherits read+write+share (see api_key_capabilities).
    "DELETE:/v1/fs": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "DELETE:/v1/fs/file": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "DELETE:/v1/fs/folder": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "DELETE:/v1/fs/shared-file": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "DELETE:/v1/fs/shared-folder": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "GET:/v1/fs/crm-search": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "GET:/v1/fs/download": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "GET:/v1/fs/info": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "GET:/v1/fs/list": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "GET:/v1/fs/preview": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "GET:/v1/fs/search": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "GET:/v1/fs/search-text": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "GET:/v1/fs/shared-download": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "GET:/v1/fs/shared-info": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "GET:/v1/fs/shared-list": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "GET:/v1/fs/shared-preview": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "GET:/v1/fs/shared-thumbnail": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "GET:/v1/fs/shared-with": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "GET:/v1/fs/shared-with-me": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "GET:/v1/fs/thumbnail": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "PATCH:/v1/fs/crm-metadata": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/batch-upload": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/complete-upload": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/copy": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/download-zip": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "POST:/v1/fs/folder": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/move": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/move-resume": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/move-rollback": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/presign-upload": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/rename-file": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/rename-folder": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/share": {"product": "filemanager", "required_scopes": ["filemanager:share"], "entitlement_required": True},
    "POST:/v1/fs/shared-download-zip": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "POST:/v1/fs/shared-folder": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/shared-move": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/shared-rename-file": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/shared-rename-folder": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/shared-upload": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/shared-upload-archive": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/shared-upload-zip": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/unshare": {"product": "filemanager", "required_scopes": ["filemanager:share"], "entitlement_required": True},
    "POST:/v1/fs/upload": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/upload-archive": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/upload-zip": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    # Newsfeed -- APIK-E1-1: re-pointed off phantom /v1/newsfeed* onto the REAL
    # newsfeed.py routes (no prefix). reads->newsfeed:read, author mutations->newsfeed:write.
    # newsfeed:moderate has no distinct route (all deletes are owner-scoped write) but
    # remains a valid superset via inheritance (moderate>=write>=read).
    "GET:/feed": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/feed/capabilities": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/feed/hidden": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/feed/interesting": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/notifications": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/posts/drafts": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/posts/drafts/{draft_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/posts/find-datetime/{poll_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/posts/scheduled": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/posts/{post_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/posts/{post_id}/attachments/{attachment_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/posts/{post_id}/comments": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/posts/{post_id}/files/{file_index}": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/posts/{post_id}/poll-results": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/posts/{post_id}/reposts": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/sse": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/uploads/object": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/ui/bookmarks": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/ui/bookmarks/status": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "GET:/ui/bookmark-collections": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "POST:/posts/{post_id}/video/entitlement": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": True},
    "POST:/posts": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "PATCH:/posts/{post_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "DELETE:/posts/{post_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/{post_id}/cancel": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/bulk-archive": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/bulk-delete": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/drafts": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "PATCH:/posts/drafts/{draft_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "DELETE:/posts/drafts/{draft_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/drafts/{draft_id}/publish": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/find-datetime": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/find-datetime/{poll_id}/availability": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/find-datetime/{poll_id}/close": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/{post_id}/close-poll": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/{post_id}/vote": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/{post_id}/write-in": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},  # R1 (prod-forward): poll write-in option
    "DELETE:/posts/{post_id}/vote": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/{post_id}/like": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/{post_id}/unlike": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/{post_id}/reactions": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/{post_id}/unreact": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/{post_id}/repost": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "DELETE:/posts/{post_id}/repost": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/{post_id}/comments": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "PATCH:/posts/{post_id}/comments/{comment_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "DELETE:/posts/{post_id}/comments/{comment_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/{post_id}/comments/{comment_id}/reactions": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/posts/{post_id}/comments/{comment_id}/unreact": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/uploads/image": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/feed/hide": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/feed/unhide": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/feed/interesting": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/feed/uninteresting": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/social/refollow": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/social/unfollow": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/ui/bookmarks": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "PATCH:/ui/bookmarks/{content_type}/{content_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "DELETE:/ui/bookmarks/{content_type}/{content_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "POST:/ui/bookmark-collections": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "PATCH:/ui/bookmark-collections/{collection_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    "DELETE:/ui/bookmark-collections/{collection_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": True},
    # APIK-E1-2 [SECURITY] money routes: tips / paid content unlock require the distinct
    # newsfeed:tips money scope, NEVER the coarse newsfeed:write.
    "POST:/posts/{post_id}/tip": {"product": "newsfeed", "required_scopes": ["newsfeed:tips"], "entitlement_required": True},
    "POST:/posts/{post_id}/reactions/tip": {"product": "newsfeed", "required_scopes": ["newsfeed:tips"], "entitlement_required": True},
    "POST:/posts/{post_id}/comments/{comment_id}/tip": {"product": "newsfeed", "required_scopes": ["newsfeed:tips"], "entitlement_required": True},
    "POST:/posts/unlock": {"product": "newsfeed", "required_scopes": ["newsfeed:tips"], "entitlement_required": True},
    # Tickets
    "GET:/tickets": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "POST:/tickets": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "GET:/tickets/{ticket_id}": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "GET:/tickets/admin/summary": {"product": "tickets", "required_scopes": ["tickets:admin"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/messages": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/assign": {"product": "tickets", "required_scopes": ["tickets:admin"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/status": {"product": "tickets", "required_scopes": ["tickets:admin"], "entitlement_required": True},
    # Ticket bounties (TBT-009). Board read uses tickets:read; mutations are
    # owner/claimant/admin-gated bounty flows.
    "GET:/tickets/bounties/open": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/bounty": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/bounty/claim": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/bounty/unclaim": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/bounty/submit": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/bounty/approve": {"product": "tickets", "required_scopes": ["tickets:admin"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/bounty/reject": {"product": "tickets", "required_scopes": ["tickets:admin"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/bounty/cancel": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    # TKA-001/002 — ticket file attachments
    "POST:/tickets/{ticket_id}/attachments/presign": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/attachments": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "GET:/tickets/{ticket_id}/attachments": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "GET:/tickets/{ticket_id}/attachments/{attachment_id}/download": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "DELETE:/tickets/{ticket_id}/attachments/{attachment_id}": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    # R1 (residual #118): tickets collaboration surface -> parity. reads(watchers/
    # links/by-account/by-contact)->tickets:read; collab+state mutations(watchers/links
    # add-remove, contact-account, priority, close, reopen)->tickets:write. NOTE: close/
    # reopen are PROD-FORWARD (absent on dev clone -> appear as dev-only stale until dev catches up).
    "DELETE:/tickets/{ticket_id}/links/{related_ticket_id}": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "DELETE:/tickets/{ticket_id}/watchers/{watcher_sub}": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "GET:/tickets/by-account/{account_id}": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "GET:/tickets/by-contact/{contact_id}": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "GET:/tickets/{ticket_id}/links": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "GET:/tickets/{ticket_id}/watchers": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "PATCH:/tickets/{ticket_id}/contact-account": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "PATCH:/tickets/{ticket_id}/priority": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/close": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/links": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/reopen": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/watchers": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    # Shopping
    "GET:/ui/catalog/categories": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/categories/{category_id}/items": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/items/search": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/shoppingcart/carts": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "POST:/ui/shoppingcart/carts": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "GET:/ui/shoppingcart/carts/{cart_id}/items": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "POST:/ui/shoppingcart/carts/{cart_id}/items": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "POST:/ui/shoppingcart/carts/{cart_id}/items/catalog": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "PATCH:/ui/shoppingcart/carts/{cart_id}/items/{sku}": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "DELETE:/ui/shoppingcart/carts/{cart_id}/items/{sku}": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "POST:/ui/shoppingcart/carts/{cart_id}/purchase": {"product": "shopping", "required_scopes": ["shopping:checkout:write"], "entitlement_required": True},
    "POST:/ui/purchase-history/transactions": {"product": "shopping", "required_scopes": ["shopping:checkout:write"], "entitlement_required": True},
    "GET:/ui/purchase-history/transactions": {"product": "shopping", "required_scopes": ["shopping:orders:read"], "entitlement_required": True},
    "GET:/ui/purchase-history/transactions/{txn_id}": {"product": "shopping", "required_scopes": ["shopping:orders:read"], "entitlement_required": True},
    "GET:/ui/purchase-history/transactions/search": {"product": "shopping", "required_scopes": ["shopping:orders:read"], "entitlement_required": True},
    # R1 (residual #118): catalog taxonomy/detail reads -> shopping:catalog:read
    # (public catalog, entitlement not required, matches sibling catalog reads).
    "GET:/ui/catalog/categories/{category_id}/breadcrumb": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/categories/{category_id}/tree": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/feature-categories": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/items/{item_id}/associations": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/items/{item_id}/bundle-components": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/items/{item_id}/effective-price": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/items/{item_id}/expand": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/items/{item_id}/features": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/items/{item_id}/price-components": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/items/{item_id}/product-features": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/items/{item_id}/product-type": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/items/{item_id}/variants": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    # R1: cart-scoped read -> shopping:cart:write (matches sibling GET cart items);
    # order/shipment/tracking reads -> shopping:orders:read.
    "GET:/ui/shoppingcart/carts/{cart_id}/abandonment-status": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "GET:/ui/shoppingcart/orders/{order_id}": {"product": "shopping", "required_scopes": ["shopping:orders:read"], "entitlement_required": True},
    "GET:/ui/purchase-history/transactions/{txn_id}/tracking": {"product": "shopping", "required_scopes": ["shopping:orders:read"], "entitlement_required": True},
    # ECOMX-02 (E0): wishlist router mounted -> register its policy-guarded routes.
    "GET:/ui/wishlist": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "POST:/ui/wishlist": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "DELETE:/ui/wishlist/{category_id}/{item_id}": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    # Messager -- APIK-E2 (#118): full messaging parity. messager:manage>=write>=read.
    # read=reads/realtime/search/receipts-view; write=bootstrap+rich-sends(incl image presign)+
    # reactions+read-receipts+calls+pins/forward+privacy; manage=participant/lifecycle admin+
    # scheduled-send cancel/edit+helpdesk transfer. Money & intentional blocks stay exempt below.
    # E2 read
    "GET:/messaging/config": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/contacts/search": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}/gallery": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}/messages": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}/messages/scheduled": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}/messages/search": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}/messages/{message_id}/attachment": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}/messages/{message_id}/edits": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}/messages/{message_id}/reactions/details": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}/messages/{message_id}/views": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}/participants": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}/pins": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}/polls/{poll_id}": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}/routing-events": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}/typing": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/events": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/events/poll": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/events/stream": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/helpdesk/availability": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/helpdesk/groups/{group_id}/agents": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/helpdesk/queue": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/messages/calls/{call_id}/billing": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/messages/find-datetime/{poll_id}": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/messages/search": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/presence": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/privacy/message": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/threads/{thread_id}/messages": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    # E2 write (bootstrap / rich sends / image presign->send / reactions / receipts / calls / organize)
    "POST:/messaging/conversations": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/dm/find-or-create": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/group": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/accept": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/images/presign": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/leave": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/poll": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},  # R1 (prod-forward): in-conversation poll send
    "POST:/messaging/conversations/{conversation_id}/messages/calendar-event": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/calendar-share": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/countdown": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/file": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/file-share": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/find-datetime": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/gallery": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/gif": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/image": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/meeting-poll": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/sticker": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/video-share": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/pin": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}/pin": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/reactions": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/transcribe": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/translate": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/view": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/polls/{poll_id}/confirm": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/polls/{poll_id}/vote": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/read": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/tts-voice-message": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/typing": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/voice-message": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/voice-message/presign": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/voicemail": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/voicemail/presign": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{target_conversation_id}/messages/forward": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/helpdesk/conversations/{conversation_id}/claim": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/messages/calls/invite": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/messages/calls/{call_id}/accept": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/messages/calls/{call_id}/decline": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/messages/calls/{call_id}/end": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "PATCH:/messaging/messages/calls/{call_id}/heartbeat": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/messages/calls/{call_id}/signal": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/messages/calls/{call_id}/timeout": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/messages/calls/{call_id}/turn-credentials": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/messages/find-datetime/{poll_id}/availability": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/messages/find-datetime/{poll_id}/close": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/presence/heartbeat": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "PUT:/messaging/privacy/message": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/privacy/message/allowlist": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "DELETE:/messaging/privacy/message/allowlist/{allow_user_id}": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    # E2 manage (participant + conversation lifecycle, scheduled-send cancel/edit, helpdesk transfer)
    "PATCH:/messaging/conversations/{conversation_id}": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "DELETE:/messaging/conversations/{conversation_id}": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/participants": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "PATCH:/messaging/conversations/{conversation_id}/participants/{participant_id}": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "DELETE:/messaging/conversations/{conversation_id}/participants/{participant_id}": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "PATCH:/messaging/conversations/{conversation_id}/messages/{message_id}": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}/revoke": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "PATCH:/messaging/conversations/{conversation_id}/messages/{message_id}/schedule": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}/schedule": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "POST:/messaging/helpdesk/conversations/{conversation_id}/transfer": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    # APIK-E2-5: mass-message campaigns require messager:manage (+entitlement) - distinct high-priv broadcast.
    "GET:/messaging/mass-messages": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "POST:/messaging/mass-messages": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "GET:/messaging/mass-messages/{campaign_id}": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "POST:/messaging/mass-messages/{campaign_id}/cancel": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    # Groups -- APIK-E4 (#118): groups parity. product=groups.
    # reads->groups:read; mutations->groups:write; settings/role/remove/dissolve->groups:manage.
    # MONEY (SECURITY): treasury contribute/spend/goal->groups:treasury (standalone high-priv);
    # campaign+fundraiser CRUD->fundraising:write (standalone). confirm-donation is intentionally
    # UNREGISTERED -> require_root_session only -> fail-closed (403 unmapped) to every key.
    "DELETE:/ui/groups/{group_id}": {"product": "groups", "required_scopes": ["groups:manage"], "entitlement_required": True},
    "DELETE:/ui/groups/{group_id}/members/{user_id}": {"product": "groups", "required_scopes": ["groups:manage"], "entitlement_required": True},
    "DELETE:/ui/groups/{group_id}/posts/{post_id}": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "DELETE:/ui/groups/{group_id}/posts/{post_id}/pin": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "GET:/ui/calls/group/active/{conversation_id}": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/calls/group/history/{conversation_id}": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/calls/group/{call_id}": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/calls/group/{call_id}/participants": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/groups": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/groups/discover": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/groups/fundraising/{group_id}/campaigns": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/groups/fundraising/{group_id}/campaigns/{campaign_id}/stats": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/groups/fundraising/{group_id}/fundraisers": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/groups/fundraising/{group_id}/fundraisers/{fundraiser_id}": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/groups/fundraising/{group_id}/fundraisers/{fundraiser_id}/donations": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/groups/{group_id}": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/groups/{group_id}/feed": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/groups/{group_id}/members": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/groups/{group_id}/pending": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/groups/{group_id}/treasury": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/groups/{group_id}/treasury/contributors": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "GET:/ui/groups/{group_id}/treasury/ledger": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},
    "PATCH:/ui/calls/group/{call_id}/media": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "PATCH:/ui/groups/fundraising/{group_id}/campaigns/{campaign_id}": {"product": "groups", "required_scopes": ["fundraising:write"], "entitlement_required": True},
    "PATCH:/ui/groups/fundraising/{group_id}/fundraisers/{fundraiser_id}": {"product": "groups", "required_scopes": ["fundraising:write"], "entitlement_required": True},
    "PATCH:/ui/groups/{group_id}": {"product": "groups", "required_scopes": ["groups:manage"], "entitlement_required": True},
    "PATCH:/ui/groups/{group_id}/members/{user_id}/role": {"product": "groups", "required_scopes": ["groups:manage"], "entitlement_required": True},
    "PATCH:/ui/groups/{group_id}/treasury/goal": {"product": "groups", "required_scopes": ["groups:treasury"], "entitlement_required": True},
    "POST:/ui/calls/group/create": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "POST:/ui/calls/group/{call_id}/end": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "POST:/ui/calls/group/{call_id}/join": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "POST:/ui/calls/group/{call_id}/leave": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "POST:/ui/calls/group/{call_id}/signal": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "POST:/ui/groups": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "POST:/ui/groups/fundraising/{group_id}/campaigns": {"product": "groups", "required_scopes": ["fundraising:write"], "entitlement_required": True},
    "POST:/ui/groups/fundraising/{group_id}/fundraisers": {"product": "groups", "required_scopes": ["fundraising:write"], "entitlement_required": True},
    "POST:/ui/groups/{group_id}/invite": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "POST:/ui/groups/{group_id}/invites/{user_id}/respond": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "POST:/ui/groups/{group_id}/join": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "POST:/ui/groups/{group_id}/leave": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "POST:/ui/groups/{group_id}/posts": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "POST:/ui/groups/{group_id}/posts/{post_id}/pin": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "POST:/ui/groups/{group_id}/requests/{user_id}/review": {"product": "groups", "required_scopes": ["groups:write"], "entitlement_required": True},
    "POST:/ui/groups/{group_id}/treasury/contribute": {"product": "groups", "required_scopes": ["groups:treasury"], "entitlement_required": True},
    "POST:/ui/groups/{group_id}/treasury/spend": {"product": "groups", "required_scopes": ["groups:treasury"], "entitlement_required": True},
    # Video -- APIK-E5 (#118): video-publishing parity. product=video.
    # reads->video:read; ingest(presign/complete)/transcode/edit/clip/combine/subtitle
    # mutations->video:write; gallery publish/unpublish->video:publish.
    # MONEY (SECURITY): pricing + ad-config->video:monetize (standalone high-priv;
    # manage inherits write+publish but NOT monetize/moderate). MODERATION (SECURITY):
    # admin by-status->video:moderate (admin-owner create-gated via require_admin_or_root).
    # tip/comment-tip/purchase/access/playback-complete/purchases-list/view/like/comments/
    # GET-ad-config/ad-impression/ad-stats/download are intentionally UNREGISTERED ->
    # fail-closed (403 unmapped) to every key. DRM router not wired (public serve intact).
    "DELETE:/ui/videos/{video_id}": {"product": "video", "required_scopes": ["video:write"], "entitlement_required": True},
    "DELETE:/ui/videos/{video_id}/subtitles/{track_id}": {"product": "video", "required_scopes": ["video:write"], "entitlement_required": True},
    "DELETE:/ui/vod-bridge/{video_id}/link": {"product": "video", "required_scopes": ["video:write"], "entitlement_required": True},
    "GET:/ui/transcode-jobs": {"product": "video", "required_scopes": ["video:read"], "entitlement_required": True},
    "GET:/ui/transcode-jobs/{job_id}": {"product": "video", "required_scopes": ["video:read"], "entitlement_required": True},
    "GET:/ui/videos": {"product": "video", "required_scopes": ["video:read"], "entitlement_required": True},
    "GET:/ui/videos/admin/by-status/{status}": {"product": "video", "required_scopes": ["video:moderate"], "entitlement_required": True},
    "GET:/ui/videos/by-creator/{creator_id}": {"product": "video", "required_scopes": ["video:read"], "entitlement_required": True},
    "GET:/ui/videos/creator/{creator_id}": {"product": "video", "required_scopes": ["video:read"], "entitlement_required": True},
    "GET:/ui/videos/gallery": {"product": "video", "required_scopes": ["video:read"], "entitlement_required": True},
    "GET:/ui/videos/gallery/categories": {"product": "video", "required_scopes": ["video:read"], "entitlement_required": True},
    "GET:/ui/videos/gallery/search": {"product": "video", "required_scopes": ["video:read"], "entitlement_required": True},
    "GET:/ui/videos/public": {"product": "video", "required_scopes": ["video:read"], "entitlement_required": True},
    "GET:/ui/videos/{video_id}": {"product": "video", "required_scopes": ["video:read"], "entitlement_required": True},
    "GET:/ui/videos/{video_id}/subtitles": {"product": "video", "required_scopes": ["video:read"], "entitlement_required": True},
    "GET:/ui/videos/{video_id}/transcode/status": {"product": "video", "required_scopes": ["video:read"], "entitlement_required": True},
    "GET:/ui/vod-bridge/status/{video_id}": {"product": "video", "required_scopes": ["video:read"], "entitlement_required": True},
    "PATCH:/ui/videos/{video_id}": {"product": "video", "required_scopes": ["video:write"], "entitlement_required": True},
    "PATCH:/ui/videos/{video_id}/ad-config": {"product": "video", "required_scopes": ["video:monetize"], "entitlement_required": True},
    "PATCH:/ui/videos/{video_id}/pricing": {"product": "video", "required_scopes": ["video:monetize"], "entitlement_required": True},
    "PATCH:/ui/videos/{video_id}/subtitles/{track_id}": {"product": "video", "required_scopes": ["video:write"], "entitlement_required": True},
    "POST:/ui/transcode-jobs": {"product": "video", "required_scopes": ["video:write"], "entitlement_required": True},
    "POST:/ui/videos/combine": {"product": "video", "required_scopes": ["video:write"], "entitlement_required": True},
    "POST:/ui/videos/upload/complete": {"product": "video", "required_scopes": ["video:write"], "entitlement_required": True},
    "POST:/ui/videos/upload/presign": {"product": "video", "required_scopes": ["video:write"], "entitlement_required": True},
    "POST:/ui/videos/{video_id}/clip": {"product": "video", "required_scopes": ["video:write"], "entitlement_required": True},
    "POST:/ui/videos/{video_id}/gallery/publish": {"product": "video", "required_scopes": ["video:publish"], "entitlement_required": True},
    "POST:/ui/videos/{video_id}/gallery/unpublish": {"product": "video", "required_scopes": ["video:publish"], "entitlement_required": True},
    "POST:/ui/videos/{video_id}/subtitles": {"product": "video", "required_scopes": ["video:write"], "entitlement_required": True},
    "POST:/ui/videos/{video_id}/transcode": {"product": "video", "required_scopes": ["video:write"], "entitlement_required": True},
    "POST:/ui/videos/{video_id}/upload/complete": {"product": "video", "required_scopes": ["video:write"], "entitlement_required": True},
    "POST:/ui/vod-bridge/import": {"product": "video", "required_scopes": ["video:write"], "entitlement_required": True},
}


API_KEY_ROUTE_EXEMPTIONS: Dict[str, RouteExemption] = {
    # Messager -- APIK-E2 (#118): intentional blocks + money routes stay fail-closed (== 403 under GA).
    "GET:/messaging/conversations/{conversation_id}/drafts": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "POST:/messaging/conversations/{conversation_id}/drafts": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "GET:/messaging/conversations/{conversation_id}/drafts/{draft_id}": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "PATCH:/messaging/conversations/{conversation_id}/drafts/{draft_id}": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "DELETE:/messaging/conversations/{conversation_id}/drafts/{draft_id}": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "POST:/messaging/conversations/{conversation_id}/mute": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "GET:/messaging/compliance/archive/events": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "GET:/messaging/compliance/archive/exports": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "POST:/messaging/compliance/archive/exports": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "GET:/messaging/compliance/archive/exports/{export_id}": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "GET:/messaging/compliance/archive/exports/{export_id}/manifest": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "GET:/messaging/compliance/archive/exports/{export_id}/records": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "GET:/messaging/conversations/{conversation_id}/hidden-messages": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "GET:/messaging/conversations/{conversation_id}/legal-holds": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "POST:/messaging/conversations/{conversation_id}/legal-holds": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "POST:/messaging/conversations/{conversation_id}/legal-holds/{hold_id}/release": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/hide": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}/hide": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/report": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "PATCH:/messaging/conversations/{conversation_id}/reports/{report_id}/status": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/moderate-revoke": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "GET:/messaging/delegate/{creator_id}/audit": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "GET:/messaging/delegate/{creator_id}/conversations": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "GET:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "POST:/messaging/admin/users/upsert": {"reason": "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"},
    "GET:/messaging/healthz": {"reason": "health probe, no API-key product traffic (APIK-E2)"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/tip": {"reason": "MONEY route fail-closed: no messager money scope exists; stays 403 until a distinct high-priv money scope is modeled (never coarse messager:write) (APIK-E2)"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/reactions/tip": {"reason": "MONEY route fail-closed: no messager money scope exists; stays 403 until a distinct high-priv money scope is modeled (never coarse messager:write) (APIK-E2)"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/unlock": {"reason": "MONEY route fail-closed: no messager money scope exists; stays 403 until a distinct high-priv money scope is modeled (never coarse messager:write) (APIK-E2)"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/attachment/grant": {"reason": "MONEY route fail-closed: no messager money scope exists; stays 403 until a distinct high-priv money scope is modeled (never coarse messager:write) (APIK-E2)"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/attachment/consume": {"reason": "MONEY route fail-closed: no messager money scope exists; stays 403 until a distinct high-priv money scope is modeled (never coarse messager:write) (APIK-E2)"},
    "POST:/messaging/messages/lottery": {"reason": "MONEY route fail-closed: no messager money scope exists; stays 403 until a distinct high-priv money scope is modeled (never coarse messager:write) (APIK-E2)"},
    "POST:/messaging/messages/{message_id}/lottery/unlock": {"reason": "MONEY route fail-closed: no messager money scope exists; stays 403 until a distinct high-priv money scope is modeled (never coarse messager:write) (APIK-E2)"},
    "GET:/messaging/messages/{message_id}/lottery": {"reason": "MONEY route fail-closed: no messager money scope exists; stays 403 until a distinct high-priv money scope is modeled (never coarse messager:write) (APIK-E2)"},
    "GET:/feed/for-you": {"reason": "session-auth newsfeed For-You route, not in initial API-key rollout scope"},
    # APIK-E1-1: newsfeed client telemetry is session-only (honest exemption).
    "POST:/telemetry/content-render": {"reason": "client render telemetry, session-auth only, not API-key product traffic"},
    "POST:/telemetry/draft-lifecycle": {"reason": "client draft-lifecycle telemetry, session-auth only, not API-key product traffic"},
    # OAU-002: OAuth2 authorization-server endpoints
    "GET:/oauth/authorize": {"reason": "OAuth2 authorization endpoint, auth handled by require_ui_session"},
    "POST:/oauth/token": {"reason": "OAuth2 token endpoint, auth handled by client credentials"},
    # OAU-003: OIDC public endpoints
    "GET:/.well-known/openid-configuration": {"reason": "OIDC discovery endpoint, no-auth public"},
    "GET:/oauth/jwks": {"reason": "OIDC public key endpoint, no-auth public"},
    "GET:/userinfo": {"reason": "OIDC userinfo, auth handled by OAuth bearer branch"},
    "POST:/ui/ats/integration/candidate-contact-links": {"reason": "session-auth ATS integration cross-link route, not in initial API-key rollout scope"},
    "POST:/ui/ats/integration/job-opportunity-links": {"reason": "session-auth ATS integration cross-link route, not in initial API-key rollout scope"},
    "GET:/ui/ats/integration/links": {"reason": "session-auth ATS integration cross-link route, not in initial API-key rollout scope"},
    "DELETE:/ui/ats/integration/links/{link_type}/{link_id}": {"reason": "session-auth ATS integration cross-link route, not in initial API-key rollout scope"},
    "GET:/health": {"reason": "health probe endpoint, not product API traffic"},
    "GET:/metrics": {"reason": "internal metrics endpoint"},
    "GET:/openapi.json": {"reason": "schema discovery endpoint"},
    # CSN-005: Open Data public endpoints — no auth required
    "GET:/open-data/branches": {"reason": "OBP open-data public endpoint, no auth required"},
    "GET:/open-data/branches/{branch_id}": {"reason": "OBP open-data public endpoint, no auth required"},
    "GET:/open-data/atms": {"reason": "OBP open-data public endpoint, no auth required"},
    "GET:/open-data/atms/{atm_id}": {"reason": "OBP open-data public endpoint, no auth required"},
    # PLT-003: Public glossary reads — unauthenticated, no API key required
    "GET:/v1/glossary": {"reason": "public unauthenticated glossary read endpoint"},
    "GET:/v1/glossary/{term_id}": {"reason": "public unauthenticated glossary term read"},
    "DELETE:/tickets/admin/kyc-sync-deadletter": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "DELETE:/tickets/{ticket_id}/external-links/{link_id}": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "DELETE:/ui/catalog/categories/{category_id}": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "DELETE:/ui/catalog/categories/{category_id}/items/{item_id}": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "DELETE:/ui/catalog/items/{item_id}/reviews/{review_id}": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "DELETE:/ui/shoppingcart/carts/{cart_id}": {"reason": "session-auth shopping cart route, not in initial API-key rollout scope"},
    "DELETE:/v1/fs/mounts/{mount_id}": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/tickets/admin/kyc-sync-deadletter": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "GET:/tickets/admin/kyc-sync-metrics": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "GET:/tickets/{ticket_id}/sync-status": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "GET:/ui/catalog/images": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "GET:/ui/catalog/items/{item_id}/reviews": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "GET:/ui/purchase-history/transactions/{txn_id}/events": {"reason": "session-auth purchase-history route, not in initial API-key rollout scope"},
    "GET:/ui/purchase-history/transactions/{txn_id}/receipt": {"reason": "session-auth purchase-history route, not in initial API-key rollout scope"},
    "GET:/ui/shoppingcart/carts/items/search": {"reason": "session-auth shopping cart route, not in initial API-key rollout scope"},
    "GET:/ui/shoppingcart/carts/{cart_id}/total": {"reason": "session-auth shopping cart route, not in initial API-key rollout scope"},
    "GET:/ui/shoppingcart/recover/{token}": {"reason": "public one-time cart recovery link, not in initial API-key rollout scope"},
    "GET:/ui/shoppingcart/reminders/preferences": {"reason": "session-auth shopping cart route, not in initial API-key rollout scope"},
    "PUT:/ui/shoppingcart/reminders/preferences": {"reason": "session-auth shopping cart route, not in initial API-key rollout scope"},
    "GET:/ui/orders": {"reason": "session-auth order-lifecycle route, not in initial API-key rollout scope"},
    "POST:/ui/orders/{order_id}/transition": {"reason": "session-auth order-lifecycle route, not in initial API-key rollout scope"},
    "GET:/ui/orders/{order_id}/lifecycle": {"reason": "session-auth order-lifecycle route, not in initial API-key rollout scope"},
    "GET:/ui/orders/{order_id}/history": {"reason": "session-auth order-lifecycle route, not in initial API-key rollout scope"},
    "POST:/ui/orders/{order_id}/cancel": {"reason": "session-auth order-lifecycle route, not in initial API-key rollout scope"},
    "GET:/v1/fs/admin/audit": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/admin/list": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/admin/mounts/reconcile": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/admin/read": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/admin/search": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/mounts": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/mounts/{mount_id}": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/mounts/{mount_id}/mock-files": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/usage/daily": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/usage/storage": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/usage/summary": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "PATCH:/ui/catalog/categories/{category_id}/items/{item_id}": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "PATCH:/v1/fs/mounts/{mount_id}": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/tickets/admin/kyc-sync-deadletter/replay-batch": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "POST:/tickets/admin/kyc-sync-deadletter/{entry_id}/replay": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "POST:/tickets/{ticket_id}/external-links/jira": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "POST:/tickets/{ticket_id}/external-links/jira/link-existing": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "POST:/tickets/{ticket_id}/external-links/{link_id}/resolve-conflict": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "POST:/ui/catalog/api-packages": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "POST:/ui/catalog/categories": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "POST:/ui/catalog/categories/{category_id}/items": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "POST:/ui/catalog/categories/{category_id}/items/{item_id}/images/upload": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "POST:/ui/catalog/file-bundles": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "POST:/ui/catalog/items/{item_id}/reviews": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "POST:/ui/catalog/items/{item_id}/reviews/{review_id}/response": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "POST:/ui/purchase-history/transactions/{txn_id}/cancel/request": {"reason": "session-auth purchase-history route, not in initial API-key rollout scope"},
    "POST:/ui/purchase-history/transactions/{txn_id}/cancel/respond": {"reason": "session-auth purchase-history route, not in initial API-key rollout scope"},
    "POST:/ui/purchase-history/transactions/{txn_id}/complete": {"reason": "session-auth purchase-history route, not in initial API-key rollout scope"},
    "POST:/ui/purchase-history/transactions/{txn_id}/confirm-received": {"reason": "session-auth purchase-history route, not in initial API-key rollout scope"},
    "POST:/ui/purchase-history/transactions/{txn_id}/revert": {"reason": "session-auth purchase-history route, not in initial API-key rollout scope"},
    "POST:/v1/fs/admin/mounts/{mount_id}/disable": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/admin/mounts/{mount_id}/reconcile-disable": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/client-telemetry": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/icloud/initiate": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/icloud/revoke": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/icloud/rotate": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/icloud/verify": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/sftp": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/{mount_id}/revoke": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/{mount_id}/rotate-credential": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/{mount_id}/status-override": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/{mount_id}/test": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/{mount_id}/validate": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/purge-deleted": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "PUT:/ui/purchase-history/transactions/{txn_id}/shipping": {"reason": "session-auth purchase-history route, not in initial API-key rollout scope"},
    # ATS — Job Orders (JOB-003, JOB-004, JOB-005)
    "GET:/ui/ats/job-orders/feature-status": {"reason": "session-auth-optional ATS feature flag probe, not in API-key rollout scope"},
    "POST:/ui/ats/job-orders": {"reason": "session-auth ATS job-orders route, not in initial API-key rollout scope"},
    "GET:/ui/ats/job-orders/{job_id}": {"reason": "session-auth ATS job-orders route, not in initial API-key rollout scope"},
    "PATCH:/ui/ats/job-orders/{job_id}": {"reason": "session-auth ATS job-orders route, not in initial API-key rollout scope"},
    "POST:/ui/ats/job-orders/{job_id}/status": {"reason": "session-auth ATS job-orders route, not in initial API-key rollout scope"},
    "GET:/ui/ats/job-orders/{job_id}/openings": {"reason": "session-auth ATS job-orders route, not in initial API-key rollout scope"},
    "DELETE:/ui/ats/job-orders/{job_id}": {"reason": "session-auth ATS job-orders route, not in initial API-key rollout scope"},
    "GET:/ui/ats/job-orders/open": {"reason": "session-auth ATS route, not in initial API-key rollout scope"},
    "GET:/ui/ats/job-orders/hot": {"reason": "session-auth ATS route, not in initial API-key rollout scope"},
    "GET:/ui/ats/job-orders/mine": {"reason": "session-auth ATS route, not in initial API-key rollout scope"},
    # Knowledge Base public portal (KB-011) — unauthenticated browse/search
    "GET:/public/kb/articles": {"reason": "unauthenticated KB public portal endpoint"},
    "GET:/public/kb/articles/{article_id}": {"reason": "unauthenticated KB public portal endpoint"},
    "GET:/public/kb/search": {"reason": "unauthenticated KB public search endpoint"},
    "GET:/public/kb/categories": {"reason": "unauthenticated KB public portal endpoint"},
    "GET:/public/kb/categories/{category_id}": {"reason": "unauthenticated KB public portal endpoint"},
    "GET:/public/kb/tags": {"reason": "unauthenticated KB public portal endpoint"},
    "GET:/public/kb/tags/{tag}/articles": {"reason": "unauthenticated KB public portal endpoint"},
    # Knowledge Base authenticated endpoints (KB-002..KB-011) — session-auth
    "GET:/kb/search": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "GET:/kb/categories": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "POST:/kb/categories": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "GET:/kb/categories/{category_id}": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "PUT:/kb/categories/{category_id}": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "DELETE:/kb/categories/{category_id}": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "GET:/kb/articles": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "GET:/kb/my-articles": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "POST:/kb/articles": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "GET:/kb/articles/{article_id}": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "PUT:/kb/articles/{article_id}": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "DELETE:/kb/articles/{article_id}": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "POST:/kb/articles/{article_id}/publish": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "POST:/kb/articles/{article_id}/expire": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "POST:/kb/articles/{article_id}/unpublish": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "POST:/kb/articles/{article_id}/rate": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "GET:/kb/articles/{article_id}/attachments": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "POST:/kb/articles/{article_id}/attachments": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "DELETE:/kb/articles/{article_id}/attachments/{attachment_id}": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    # PRT-001..PRT-005: ATS Career Portal public endpoints (no auth)
    "GET:/public/careers/config": {"reason": "Public unauthenticated career portal"},
    "GET:/public/careers/jobs": {"reason": "Public unauthenticated career portal"},
    "GET:/public/careers/jobs.rss": {"reason": "Public unauthenticated career portal RSS feed"},
    "GET:/public/careers/jobs/{slug}": {"reason": "Public unauthenticated career portal"},
    "POST:/public/careers/jobs/{slug}/apply": {"reason": "public career-portal self-apply endpoint; anonymous callers carry no API key"},
    "POST:/public/careers/jobs/{slug}/resume-presign": {"reason": "public unauthenticated career portal résumé presign — no API key scope required"},
    # Admin config endpoints (session-auth, not in API-key rollout scope)
    "GET:/ui/admin/career-portal/config": {"reason": "session-auth admin career portal endpoint, not in API-key rollout scope"},
    "PUT:/ui/admin/career-portal/config": {"reason": "session-auth admin career portal endpoint, not in API-key rollout scope"},
    # ============================================================================
    # R1 (residual #118) INTENTIONAL API-KEY DENY-LIST (documented fail-closed).
    # Routes intentionally NOT exposed to ak_ API keys: exempt==unmapped==403 to
    # every key. Kept in this COVERED table so they do NOT inflate the registry-
    # drift `unregistered_live` signal and so the startup policy-coverage check
    # stays clean. `critical` is driven by stale rows only (see classify_registry_drift).
    # --- catalog admin mutations (session/admin-only; no catalog-write scope) ---
    "DELETE:/ui/catalog/feature-categories/{fc_id}": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "DELETE:/ui/catalog/feature-categories/{fc_id}/values/{fv_id}": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "DELETE:/ui/catalog/items/{item_id}/associations/{to_item_id}": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "DELETE:/ui/catalog/items/{item_id}/bundle-components/{component_item_id}": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "DELETE:/ui/catalog/items/{item_id}/feature-categories/{fc_id}": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "DELETE:/ui/catalog/items/{item_id}/product-features/{feature_category_id}": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "DELETE:/ui/catalog/items/{item_id}/variants/{variant_id}": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "PATCH:/ui/catalog/categories/{category_id}/move": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "PATCH:/ui/catalog/items/reorder": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "PATCH:/ui/catalog/items/{item_id}/stock": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "POST:/ui/catalog/categories/{category_id}/children": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "POST:/ui/catalog/feature-categories": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "POST:/ui/catalog/feature-categories/{fc_id}/values": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "POST:/ui/catalog/items/bulk-delete": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "POST:/ui/catalog/items/bulk-update": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "POST:/ui/catalog/items/{item_id}/associations": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "POST:/ui/catalog/items/{item_id}/bundle-components": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "POST:/ui/catalog/items/{item_id}/feature-categories": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "POST:/ui/catalog/items/{item_id}/mark-virtual": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "POST:/ui/catalog/items/{item_id}/price-components": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "POST:/ui/catalog/items/{item_id}/product-features": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "POST:/ui/catalog/items/{item_id}/product-features/{feature_category_id}/values": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "POST:/ui/catalog/items/{item_id}/product-type": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "POST:/ui/catalog/items/{item_id}/variants": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "POST:/ui/catalog/products/{product_id}/sale": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    "PUT:/ui/catalog/items/{item_id}/price-components": {"reason": "DENY: catalog admin mutation, session/admin-only; no api-key catalog-write scope by design (R1)"},
    # --- shopping-cart abandonment admin ops (session/admin-only) ---
    "GET:/ui/shoppingcart/admin/cart-abandonment/stats": {"reason": "DENY: cart-abandonment admin op, session/admin-only (R1)"},
    "POST:/ui/shoppingcart/admin/cart-abandonment/scan": {"reason": "DENY: cart-abandonment admin op, session/admin-only (R1)"},
    # --- messaging delegate (creator-impersonation) surface (session/admin-only) ---
    "DELETE:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/{message_id}": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "DELETE:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/{message_id}/hide": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "DELETE:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/{message_id}/pin": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "GET:/messaging/delegate/{creator_id}/events/poll": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "PATCH:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/{message_id}": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/images/presign": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/calendar-event": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/calendar-share": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/countdown": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/file": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/find-datetime": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/gallery": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/gif": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/image": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/poll": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/sticker": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/text": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/video-share": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/{message_id}/hide": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/{message_id}/pin": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages/{message_id}/reactions": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/read": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/typing": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/voice-message": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/voice-message/presign": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/voicemail": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/voicemail/presign": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/messages/find-datetime/{poll_id}/availability": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/messages/find-datetime/{poll_id}/close": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/messages/lottery": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/polls/{poll_id}/close": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/polls/{poll_id}/vote": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    "POST:/messaging/delegate/{creator_id}/polls/{poll_id}/write-in": {"reason": "DENY: delegate creator-impersonation surface, session/admin-only (APIK-E2 delegate intentional block, R1)"},
    # --- video social/monetization/moderation surface (fail-closed to keys) ---
    "GET:/ui/videos/purchases/list": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "GET:/ui/videos/{video_id}/access": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "GET:/ui/videos/{video_id}/ad-config": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "GET:/ui/videos/{video_id}/ad-stats": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "GET:/ui/videos/{video_id}/comments": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "GET:/ui/videos/{video_id}/download": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "GET:/ui/videos/{video_id}/like": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "DELETE:/ui/videos/{video_id}/comments/{comment_id}": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "PATCH:/ui/videos/{video_id}/comments/{comment_id}": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "POST:/ui/videos/{video_id}/ad-impression": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "POST:/ui/videos/{video_id}/comments": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "POST:/ui/videos/{video_id}/comments/{comment_id}/reactions": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "POST:/ui/videos/{video_id}/comments/{comment_id}/tip": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "POST:/ui/videos/{video_id}/comments/{comment_id}/unreact": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "POST:/ui/videos/{video_id}/like": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "POST:/ui/videos/{video_id}/playback-complete": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "POST:/ui/videos/{video_id}/purchase": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "POST:/ui/videos/{video_id}/reactions": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "POST:/ui/videos/{video_id}/tip": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "POST:/ui/videos/{video_id}/unreact": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    "POST:/ui/videos/{video_id}/view": {"reason": "DENY: video social/monetization/moderation surface, intentionally fail-closed to API keys (APIK-E5, R1)"},
    # --- groups money confirm-donation + social comments (fail-closed to keys) ---
    "POST:/ui/groups/fundraising/{group_id}/fundraisers/{fundraiser_id}/donations/{donation_id}/confirm": {"reason": "DENY: fundraiser donation-confirm is require_root_session only, fail-closed to API keys (APIK-E4, R1)"},
    "DELETE:/ui/groups/{group_id}/posts/{post_id}/comments/{comment_id}": {"reason": "DENY: group-post social comments, fail-closed to API keys (APIK-E4, R1)"},
    "GET:/ui/groups/{group_id}/posts/{post_id}/comments": {"reason": "DENY: group-post social comments, fail-closed to API keys (APIK-E4, R1)"},
    "POST:/ui/groups/{group_id}/posts/{post_id}/comments": {"reason": "DENY: group-post social comments, fail-closed to API keys (APIK-E4, R1)"},
}

API_KEY_INITIAL_ROLLOUT_PATH_PREFIXES = (
    "/v1/fs",
    # APIK-E1-1: real newsfeed surfaces (phantom "/v1/newsfeed" retired).
    "/feed",
    "/posts",
    "/uploads",
    "/social",
    "/notifications",
    "/sse",
    "/ui/bookmarks",
    "/ui/bookmark-collections",
    "/tickets",
    "/ui/catalog",
    "/ui/shoppingcart",
    "/ui/purchase-history",
    "/messaging",
)


# Tagged initial rollout routes that must be represented either as protected routes or explicit exemptions.
API_KEY_INITIAL_ROLLOUT_TAGGED_ROUTES: List[str] = sorted(
    set(list(API_KEY_ROUTE_SCOPE_REGISTRY.keys()) + list(API_KEY_ROUTE_EXEMPTIONS.keys()))
)


def get_route_scope_policy(route_id: str) -> RouteScopePolicy | None:
    return API_KEY_ROUTE_SCOPE_REGISTRY.get((route_id or "").strip())


def resolve_required_scopes_for_route(route_id: str) -> List[str]:
    policy = get_route_scope_policy(route_id)
    if not policy:
        return []
    return list(policy["required_scopes"])


def is_entitlement_required_for_route(route_id: str) -> bool:
    policy = get_route_scope_policy(route_id)
    if not policy:
        return False
    return bool(policy["entitlement_required"])


def get_route_exemption(route_id: str) -> RouteExemption | None:
    return API_KEY_ROUTE_EXEMPTIONS.get((route_id or "").strip())


def missing_registered_route_ids(live_route_ids: Iterable[str]) -> List[str]:
    live = {(route_id or "").strip() for route_id in live_route_ids if (route_id or "").strip()}
    return sorted(route_id for route_id in API_KEY_ROUTE_SCOPE_REGISTRY.keys() if route_id not in live)


def unregistered_live_route_ids(live_route_ids: Iterable[str]) -> List[str]:
    live = {(route_id or "").strip() for route_id in live_route_ids if (route_id or "").strip()}
    out: List[str] = []
    for route_id in sorted(live):
        if route_id in API_KEY_ROUTE_SCOPE_REGISTRY or route_id in API_KEY_ROUTE_EXEMPTIONS:
            continue
        _, _, path = route_id.partition(":")
        if not path:
            continue
        if any(path.startswith(prefix) for prefix in API_KEY_INITIAL_ROLLOUT_PATH_PREFIXES):
            out.append(route_id)
    return out


def is_route_registered_or_exempt(route_id: str) -> bool:
    normalized = (route_id or "").strip()
    return normalized in API_KEY_ROUTE_SCOPE_REGISTRY or normalized in API_KEY_ROUTE_EXEMPTIONS


def summarize_registry_drift(live_route_ids: Iterable[str], *, preview_limit: int = 25) -> Dict[str, object]:
    missing = missing_registered_route_ids(live_route_ids)
    unregistered = unregistered_live_route_ids(live_route_ids)
    limit = max(0, int(preview_limit))
    return {
        "stale_route_count": len(missing),
        "stale_route_preview": missing[:limit],
        "unregistered_live_route_count": len(unregistered),
        "unregistered_live_route_preview": unregistered[:limit],
    }


def classify_registry_drift(*, stale_route_count: int, unregistered_live_route_count: int, warn_threshold: int) -> str:
    stale = max(0, int(stale_route_count))
    unregistered = max(0, int(unregistered_live_route_count))
    threshold = max(0, int(warn_threshold))
    # R1 Part B (#118 residual): `critical` reflects the REAL registry-rot problem
    # = stale rows (registry entries -> DEAD routes) beyond tolerance. Intentionally
    # fail-closed routes live on the documented deny-list section of
    # API_KEY_ROUTE_EXEMPTIONS and are excluded from `unregistered_live_route_count`
    # upstream, so a non-zero accidental-unregistered count is an actionable
    # "warning" (triage the gap) rather than a false "critical".
    if stale > threshold:
        return "critical"
    if unregistered > 0:
        return "warning"
    return "ok"
