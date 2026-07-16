import sys
path = sys.argv[1]
src = open(path).read()
anchor = '    "GET:/ui/purchase-history/transactions/{txn_id}/tracking": {"product": "shopping", "required_scopes": ["shopping:orders:read"], "entitlement_required": True},\n'
block = (
    '    # ECOMX-02 (E0): wishlist router mounted -> register its policy-guarded routes.\n'
    '    "GET:/ui/wishlist": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},\n'
    '    "POST:/ui/wishlist": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},\n'
    '    "DELETE:/ui/wishlist/{category_id}/{item_id}": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},\n'
)
if '"GET:/ui/wishlist"' in src:
    print("ALREADY REGISTERED -- skip"); sys.exit(0)
assert anchor in src, "anchor not found"
src = src.replace(anchor, anchor + block, 1)
open(path, "w").write(src)
print("REGISTERED wishlist routes")
