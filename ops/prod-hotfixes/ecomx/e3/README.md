# ECOMX EPIC E3 — CARRIER TRACKING: real advancement, one detector, once-only pushes

Makes the seller ship-group `shipment_tracking` status ADVANCE FOR REAL, collapses the two carrier
detectors into one, hardens the tracking writes against out-of-order/replayed events, and confirms the
buyer Track screen shows the real carrier/number/status the seller entered (the txn-vs-ship-group key
mismatch — already bridged in E0/E2 — is re-verified end-to-end here).

Live prod hotfix folded here. The four core files are **byte-identical dev==prod==repo** (md5-verified);
`settings.py` + `main.py` diverge on prod so they are patched in place (anchored edits — see
`settings.patch` / `main.patch`). Verified **31/31** against the live PROD uvicorn over real HTTP (NOT
an in-process TestClient) + a 4/4 transient-vs-dedupe unit check. E1 money re-verified **29/29**, E2
lifecycle **33/33** (no regression). 0 residue.

## Files (md5)
- `carrier_tracking.py` (service)         `16879435e92da7c5f3fec04f2b881718`
- `shipment_tracking.py` (service)        `8706c206cff7b2adc6b914963616cfed`
- `shipment_tracking_runner.py` (NEW svc) `846ca96658e6119435638032aa41a398`
- `shipment_tracking_router.py` (router)  `b4ffcd8fba37fdc1aa1106e1becbc78e`
- `settings.patch` / `main.patch` — anchored in-place edits to the divergent prod files.

## Ticket-by-ticket

- **ECOMX-31 — one `detect_carrier`.** The two duplicate detectors are collapsed: `carrier_tracking.py`
  (the buyer-txn/`shipping`-record path) now DELEGATES `detect_carrier` to the canonical
  `shipment_tracking.detect_carrier`, mapping its UPPERCASE result (USPS/UPS/FedEx/DHL) back to this
  module's lowercase vocab (ups/fedex/usps/dhl) so `CARRIER_TRACKING_URLS` + the buyer surfaces are
  unchanged. The old regex tables (`_UPS_PATTERN`, `_FEDEX_LENGTHS`, `_USPS_*`, `_DHL_PATTERN`) are
  removed. *AC met:* one number → one carrier → one valid tracking URL; one delivery-notification rail.

- **ECOMX-30 — real carrier sync (honest poll/mock-that-progresses runner).** New
  `app/services/shipment_tracking_runner.py` (modelled on the payout runner) advances every in-flight
  ship-group shipment ONE honest step per cycle. When EasyPost is configured (`EASYPOST_API_KEY`) and a
  shipment carries an `easypost_tracker_id`, it polls the REAL EasyPost Tracker (`poll_tracking` →
  `advance`); otherwise (prod-mock, no key) it drives the internal mock progression forward
  (label_created → in_transit → out_for_delivery → delivered) so a shipped order reaches delivered
  WITHOUT an admin clicking simulate — while the buyer out-for-delivery/delivered pushes still fire
  exactly once each via `_claim_notify`. Both drivers funnel through
  `shipment_tracking.run_progression_once`. Gated by `SHIPMENT_PROGRESSION_ENABLED` (background timer,
  default off); the deterministic trigger is the new admin endpoint
  `POST /ui/admin/shipment-tracking/run-progression`. The `tracker.updated` webhook
  (`POST /ui/shipping/tracking/webhook`) + `poll` seam remain the real-feed drop-ins.

- **ECOMX-32 — harden tracking writes.** (1) A monotonic status RANK guard on `advance` — a lower-ranked
  (out-of-order / replayed) status can no longer REGRESS a shipment (e.g. `delivered → in_transit` is
  refused; a same-status replay is a no-op; `exception` is off-ladder but cannot overwrite a final
  `delivered`), enforced both in the read-guard AND as a DDB CAS `ConditionExpression` so a concurrent
  writer can't clobber a further-along status. (2) `_claim_notify` now DISTINGUISHES a genuine
  ConditionalCheckFailed dedupe (return False → suppress) from a transient DDB error (raise
  `_TransientNotifyError`); `advance` calls `_claim_notify_with_retry` so a transient blip retries
  instead of silently dropping the buyer delivery push.

## Buyer-tracking key-mismatch (re-verified)
The buyer Track screen reads two routes, both of which now populate off the seller-entered ship-group
tracking:
- `GET /ui/orders/tracking/{ship_group_id}` — ship-group-keyed (Android `feature/ordertracking`).
- `GET /ui/purchase-history/transactions/{txn_id}/tracking` — buyer-txn-keyed (Android
  `feature/tracking`); resolves the order off the txn (`external_ref`/`metadata.order_id`) →
  `order_fulfillment_bridge.order_tracking` → the ship-group `shipment_tracking` records (E0/E2 bridge).
So the permanently-empty stub is gone: the buyer sees the real carrier/number/status.

## LIVE verify matrix (31/31, real HTTP against prod uvicorn — see verify_ecomx3.py)
Synthetic seller+buyer+admin; seed approved ship-group + linked buyer txn; seller logs in and walks the
group to shipped WITH a UPS tracking #; buyer sees it on BOTH tracking routes; admin drives
run-progression → status advances label_created → in_transit → out_for_delivery → delivered (no simulate
click); out-for-delivery + delivered pushes fire EXACTLY once each (re-running progression does not
duplicate); delivered alert carries the deep-link `action_url` `/orders?order=..&ship_group=..&track=1`;
monotonic guard refuses a `delivered → in_transit` regress (direct + via the live webhook route); one
detector resolves one carrier + one URL; regression (seller sales, refund routes) intact. Auto-cleaned
(0 residue: groups, tracking, txn, alerts, users all removed).

Plus a 4/4 unit check of the transient-vs-dedupe `_claim_notify` (raises `_TransientNotifyError` on
transient; retry wrapper drops-not-crashes after exhaustion; ConditionalCheckFailed returns False; rank
map monotonic).

## Apply
`apply_prod_e3.sh` — base64-writes the four core files + anchored python edits to `settings.py`/`main.py`
+ chown ubuntu + import check. Restart `sudo -u ubuntu bash /home/ubuntu/restart_backend.sh`; openapi 200
+ `/ui/admin/shipment-tracking/run-progression` present.
