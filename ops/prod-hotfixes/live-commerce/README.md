# LIVE-STREAM COMMERCE (live shopping) — LIVECOM L1-L4 (backend money-path)

LIVE PROD HOTFIX (EC2 i-08f937fc705ebea75 via SSM) + mirrored to the android-impl
dev clone. Adds a NEW commission split: a host pins products to a live broadcast
session (own OR affiliate-any) and viewers buy in-stream; an affiliate sale credits
the host a seller-set commission %, the seller the net, and the platform its fee.

## Scope
- **L1 pin/unpin (host-only) + shop-this-stream** — `app/services/live_stream_products.py`
  + `app/routers/live_commerce.py`. New `LiveStreamProducts` table (PK `session_id`
  / SK `PRODUCT#<product_id>`; is_affiliate DERIVED from ownership). GET shop list is
  viewer-readable.
- **L2 seller affiliate commission (owner-scoped)** — per-listing
  `affiliate_commission_bps` on the catalog item (default 1000 = 10%); only the
  listing's `creator_id` may set it. `POST/GET /ui/live-commerce/listings/{cat}/{item}/affiliate-commission`.
- **L3 stream-attributed buy** — `CartPurchaseIn` gains `broadcast_session_id` +
  `host_id`; `ui_purchase_cart` + `purchase_cart` thread them onto the order metadata
  (`is_stream_attributed`).
- **L4 commission split** — `app/services/live_commerce_split.py::settle_stream_order`,
  invoked from `purchase_cart` when stream-attributed. The legacy full-gross seller
  credit is SKIPPED for stream carts (no double credit). Idempotent per order via a
  claim marker (`session_id="ORDER#<id>"`, SK=`SETTLEMENT`).

## Money model (per pinned product line; gross = line's pro-rata of the paid total)
    platform_fee = gross * LIVECOM_PLATFORM_FEE_BPS (default 1500 = 15%)
    seller_pool  = gross - platform_fee            (the seller-earnings pool)
  AFFILIATE (host != seller):
    host_commission = seller_pool * affiliate_commission_bps   (seller-set %)
    seller_net      = seller_pool - host_commission
    invariant: host_commission + seller_net == seller_pool  (both type:"credit")
  OWN (host == seller): host keeps seller_pool (single credit, no extra split)
  both: platform_fee + seller_pool == gross == buyer payment share (buyer unchanged)

## Files
NEW: app/services/live_stream_products.py, app/services/live_commerce_split.py,
app/routers/live_commerce.py.
PATCHED (anchor-idempotent, see apply_livecom.py): app/core/settings.py,
app/core/tables.py, app/models.py, app/routers/shoppingcart.py,
app/services/shoppingcart.py, app/main.py.
NEW TABLE: LiveStreamProducts (PAY_PER_REQUEST) — create_table.py.

## Apply (idempotent, runs on prod AND the divergent dev clone)
    python apply_livecom.py /home/ubuntu/testlogon     # patch existing files
    python create_table.py                             # create LiveStreamProducts
    # restart backend; then:
    python verify_livecom.py                            # in-process prod DDB verify

## Verify (prod DDB, in-process): 32/32 ALL_PASS
Affiliate $100 sale @ 20% commission, 15% platform fee: platform 1500 + host 1700 +
seller 6800; host+seller == 8500 pool; platform+pool == 10000 == buyer. Idempotent
(repeat = no double). Own $50 sale: platform 750 + host keeps 4250; no extra split.
Real stream-attributed purchase_cart: order created→approved, split fired, no legacy
double credit, buyer total unchanged.
