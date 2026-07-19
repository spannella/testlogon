# Hotfix: fixed-assets global work-order queue 500 (shared maintenance_orders table)

## Symptom
GET /ui/fixed-assets/work-orders (the global work-order queue; also the
wo_status / assignee_sub filtered variants) returned 500 Internal Server Error
whenever ANY property-maintenance work order existed.
e2e: fixed-assets.spec.ts 93.5 "Global work-order queue" -> 500 (18/19).

## Root cause
The DynamoDB table maintenance_orders is SHARED by two features:
  - Fixed-assets work orders: pk = "ASSET#<asset_id>",   has asset_id.
  - Property-maintenance orders: pk = "PROPERTY#<prop_id>", has property_id/
    unit_id, NO asset_id.
app/services/fixed_assets.list_work_orders() unfiltered path did a bare
T.maintenance_orders.scan() (and the GSI_WO_STATUS / GSI_WO_ASSIGNEE queries
span both feature families too), then mapped EVERY row through
_item_to_work_order(), which does item["asset_id"] -> KeyError: asset_id
on the first property row -> 500. Independent of DDB namespace; purely a
cross-feature table-sharing parse bug.

## Fix (app/services/fixed_assets.py, list_work_orders)
Scope every non-asset-id path to asset work orders:
  - scan path: add FilterExpression Attr("pk").begins_with("ASSET#")
  - GSI_WO_STATUS / GSI_WO_ASSIGNEE queries: same FilterExpression
  - plus a defensive post-filter (drop any row whose pk != ASSET#...) before
    mapping, so a legacy/unfiltered row can never 500 the queue again.
Patch: fixed_assets_shared_table_asset_filter.patch
After fix: fixed-assets.spec.ts 19/19 green; queue returns only asset WOs.

## Prod impact
AFFECTS THE RUNNING SERVER. Prod maintenance_orders is a single real-AWS table
shared by both features, so any tenant that created a property work order
breaks the fixed-assets global queue + status/assignee filters with a 500.
NOT dev-only.

## Prod mirror status
PENDING -- must be applied to prod (/home/ubuntu/testlogon) via AWS SSM from an
AWS-credentialed machine (dev host .249 has no aws CLI / SSM plugin). Pure
string-anchored edit in app/services/fixed_assets.py (see .patch); apply,
restart uvicorn, re-verify GET /ui/fixed-assets/work-orders returns 200.
