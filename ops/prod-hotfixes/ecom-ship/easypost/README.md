# ECOM D5 — EasyPost integration (seam-ready, config-gated)

Real EasyPost integration for the shipment-tracking subsystem, GATED on
`EASYPOST_API_KEY`. Behavior is UNCHANGED when the key is absent (the
internal/simulate driver stays the demo path).

## What ships
- **app/services/easypost_client.py** (NEW): `is_enabled()` (key gate),
  `create_tracker(tracking_code, carrier)` (POST /v2/trackers, Basic auth),
  `get_tracker(id)` (GET /v2/trackers/{id}), `map_status()` (EasyPost
  Tracker.status -> internal), `parse_webhook()` (EasyPost tracker.updated
  Event: result.status + tracking_details[]), `verify_signature()`
  (HMAC-SHA256 of the raw body vs X-Hmac-Signature, gated on
  EASYPOST_WEBHOOK_SECRET). Uses stdlib urllib (no new deps); every network
  entrypoint is a no-op when the key is absent.
- **app/services/shipment_tracking.py** (patched): create_on_ship creates a
  real EasyPost Tracker + stores easypost_tracker_id when keyed;
  ingest_webhook detects + parses the EasyPost Event shape; poll_tracking GETs
  the tracker by id when keyed; _EXTERNAL_STATUS_MAP extended with EasyPost
  vocab (available_for_pickup/unknown/error/cancelled).
- **app/core/settings.py** (patched, apply_settings_easypost.py): adds
  easypost_api_key / easypost_webhook_secret / easypost_api_base.

## Status map (EasyPost Tracker.status -> internal)
pre_transit,unknown -> label_created | in_transit,available_for_pickup ->
in_transit | out_for_delivery -> out_for_delivery | delivered -> delivered |
return_to_sender,failure,error,cancelled -> exception

## Activate (per environment)
export EASYPOST_API_KEY=EZAK...            # enables real Trackers + polling
export EASYPOST_WEBHOOK_SECRET=whsec...     # (optional) enforce webhook HMAC
# point an EasyPost webhook at POST /ui/shipping/tracking/webhook
Restart the backend. No key = internal/simulate (unchanged).

## Prod hotfix (LIVE via SSM)
Backups: app/services/shipment_tracking.py.bak_easypost_1783714824,
app/core/settings.py.bak_easypost_1783714824 on i-08f937fc705ebea75.
Probe confirmed prod shipment_tracking.py matched dev (sha d85712dfa3db) before
whole-file replace; settings anchored-patched; restart openapi 200.

## Verify
- Unit: tests/test_easypost_tracking.py (13/13) — status map + webhook parse
  (real EasyPost sample) + signature + ingest/advance/push + create_on_ship
  keyed-vs-nokey.
- Prod in-process: verify_easypost.py via SSM (15/15 ALL_PASS) — no-key
  create_on_ship unchanged, EasyPost webhook in_transit/out_for_delivery/
  delivered -> advance + push (idempotent), keyed dry-run create_tracker called.
