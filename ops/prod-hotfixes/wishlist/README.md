# Wishlist router (LIVE PROD HOTFIX 2026-07-04)

New per-user wishlist/favorites for catalog items. Prod-deployed via SSM to
/home/ubuntu/testlogon (prod diverges from this branch).

## Files
- `app/routers/wishlist.py` (NEW) -> copy in this dir.
- `app/main.py` (registration only):
  - import after `from app.routers.catalog import router as catalog_router`:
    `from app.routers.wishlist import router as wishlist_router`
  - include after `app.include_router(catalog_router)`:
    `app.include_router(wishlist_router)`
  - prod backup: app/main.py.bak_ecom3_1783144898

## Storage keyspace (NO new infra)
Reuses the existing per-user `shopping_cart` DynamoDB table:
- PK = `USER#<user_sub>`
- SK = `WISH#<category_id>#<item_id>`
- entity = `wishlist_item`; render fields snapshotted at save (name, description,
  price_cents, currency, image_urls, creator_id, stock_status, added_at).
Catalog items are read from `T.catalog` at PK=`CAT#<category_id>` SK=`ITEM#<item_id>`.

## Endpoints (auth: require_ui_session, cookie/session)
- POST   /ui/wishlist            {category_id,item_id} -> WishlistItemOut (404 if item missing; idempotent upsert)
- GET    /ui/wishlist            -> {items:[WishlistItemOut],count} (newest first; available=false if item later deleted)
- DELETE /ui/wishlist/{category_id}/{item_id} -> {deleted:true} (idempotent)

Verified round-trip on prod 2026-07-04: add 200, list count=1, idempotent re-add=1,
bogus item 404, delete deleted:true count=0, idempotent re-delete ok.
