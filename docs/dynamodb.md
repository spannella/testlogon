# DynamoDB Setup

This service uses multiple DynamoDB tables to store sessions, MFA devices, recovery codes, API keys, alerts, and billing artifacts. You must create the tables and export the table names as environment variables before running the app.

## Required tables and environment variables

| Purpose | Env var | Notes |
| --- | --- | --- |
| UI sessions | `DDB_SESSIONS_TABLE` | Required. |
| TOTP devices | `DDB_TOTP_TABLE` | Required. |
| SMS MFA devices | `DDB_SMS_TABLE` | Required. |
| Email MFA devices | `DDB_EMAIL_TABLE` | Required. |
| Recovery codes | `DDB_RECOVERY_TABLE` | Required. |
| API keys | `API_KEYS_TABLE_NAME` | Default: `api_keys`. |
| Alerts | `ALERTS_TABLE_NAME` | Default: `alerts`. |
| Alert preferences | `ALERT_PREFS_TABLE_NAME` | Default: `alert_prefs`. |
| Billing data | `BILLING_TABLE_NAME` | Required for Stripe/PayPal/CCBill billing features. |
| API usage events | `API_USAGE_TABLE_NAME` | Append-only API metering events + GSIs for period/key/route queries. |
| Signature packets | `SIGNATURE_PACKETS_TABLE_NAME` | Packet metadata and sender-owner lookup (`OWNER_CREATED_INDEX`). |
| Signature packet signers | `SIGNATURE_PACKET_SIGNERS_TABLE_NAME` | Signer assignments and signer inbox lookup (`SIGNER_STATUS_INDEX`). |
| Signature packet fields | `SIGNATURE_PACKET_FIELDS_TABLE_NAME` | Field geometry/type/assignment keyed by packet. |
| Signature packet events | `SIGNATURE_PACKET_EVENTS_TABLE_NAME` | Append-only audit timeline per packet. |
| Signature packet artifacts | `SIGNATURE_PACKET_ARTIFACTS_TABLE_NAME` | Immutable draft/final artifact references per packet. |
| Newsfeed (single-table) | `APP_TABLE` | Required for the newsfeed demo endpoints; default: `app_single_table`. |

## Table schema overview
Most tables use a partition key (PK) and optional sort key (SK). The services store JSON-like items that include timestamps (`created_at`, `updated_at`) and user identifiers (`user_sub`, `user_id`).

### Newsfeed single-table layout
The newsfeed router uses a single-table design with `pk`/`sk` keys and a few item families:

- **Posts**: `pk = POST#<post_id>`, `sk = META` with body, attachments, visibility, and unlock price.
- **Post comments**: `pk = POST#<post_id>#COMMENTS`, `sk = COMMENT#<created_at>#<comment_id>`.
- **User feeds**: `pk = USER#<user_id>`, `sk = FEED#<created_at>#<post_id>`.
- **Notifications**: `pk = NOTIF#<user_id>`, `sk = NOTIF#<created_at>#<notification_id>`.
- **Hidden posts**: `pk = HIDE#<user_id>`, `sk = POST#<post_id>`.
- **Unlock records**: `pk = UNLOCK#<user_id>`, `sk = POST#<post_id>`.

### Billing table
The billing table is a single-table design storing:
- **Balance**: `sk = BALANCE`
- **Settings**: `sk = BILLING`
- **Payment methods**: `sk = PM#<payment_method_id>`
- **Payments**: `sk = PAY#<payment_intent_id>`
- **Ledger entries**: `sk = LEDGER#<ts>#<id>`

### API keys table
API keys are stored by user and often rely on a secondary index for user lookup (`API_KEYS_USER_INDEX`).

## Provisioning checklist
1. Create the DynamoDB tables in the target AWS region.
2. Configure table names in your environment (`.env` or secrets manager).
3. Ensure the runtime AWS credentials have read/write access to each table.
4. (Optional) Enable TTL where relevant for expiring records like sessions or event dedupe markers.

## Local development tips
- For local testing, you can use DynamoDB Local and point your AWS SDK config at the local endpoint.
- Keep table name env vars in the same `.env` used for other secrets.
- Use `DDB_ENDPOINT_URL` (or `AWS_ENDPOINT_URL`) to force all DynamoDB calls to the local emulator.


### API usage events table
- **Primary key**: `PK` / `SK` (`USER#<user_sub>` + `API_USAGE#EVENT#<event_id>`).
- **GSI_PERIOD**: query by billing period.
- **GSI_API_KEY**: query by API key across period windows.
- **GSI_ROUTE**: query by route-level usage.
- **TTL**: event rows carry `ttl_epoch`; configure `API_USAGE_EVENT_RETENTION_DAYS` and enable TTL on `DDB_TTL_ATTR` (default `ttl_epoch`).


### Commercialization and entitlement tables (CCE-010)
The local/bootstrap migration script (`scripts/local-ddb-init.py`) provisions the following tables for checkout + entitlement workflows:

- `CATALOG_PRODUCTS_TABLE_NAME` (`catalog_products`): product metadata (`PK`/`SK`) with `GSI_PRODUCT_TYPE` for product-family browsing.
- `CATALOG_PRODUCT_VERSIONS_TABLE_NAME` (`catalog_product_versions`): versioned product snapshots keyed by `sku` + `effective_at`.
- `ORDERS_TABLE_NAME` (`orders`): order headers keyed by `order_id`, with `GSI_USER` and `GSI_STATUS` for support and ops queries.
- `ORDER_ITEMS_TABLE_NAME` (`order_items`): line items keyed by `order_id` + `item_id`.
- `PAYMENTS_TABLE_NAME` (`payments`): provider payment events keyed by `payment_id` + `event_id`, with:
  - `GSI_ORDER` for order reconciliation,
  - `GSI_PROVIDER_EVENT_IDEMPOTENCY` for webhook idempotency lookups.
- `ENTITLEMENTS_TABLE_NAME` (`entitlements`): entitlement records keyed by `user_id` + `entitlement_id`, with:
  - `GSI_STATUS` for lifecycle scans,
  - `GSI_SKU` for catalog-impact analysis.
- `ENTITLEMENT_USAGE_EVENTS_TABLE_NAME` (`entitlement_usage_events`): append-only usage events keyed by `entitlement_id` + `event_id`, with:
  - `GSI_IDEMPOTENCY` for usage consume idempotency,
  - `GSI_TIMESTAMP` for period/time-window reads.

#### Migration safety notes
- Bootstrap is **forward/backward safe** for local/staging because table creation is idempotent and missing GSIs are added in place.
- Uniqueness/idempotency is enforced via write-path conditional expressions using `provider_event_idempotency_key` and `idempotency_key` lookup indexes.
- Validate critical-path query latency in staging against `GSI_USER`, `GSI_STATUS`, `GSI_ORDER`, `GSI_IDEMPOTENCY`, and `GSI_TIMESTAMP` before production cutover.

### Signature packet tables
- **signature_packets**: `packet_id` PK with `OWNER_CREATED_INDEX` (`owner_user_id` + `created_at`) for sender list queries.
- **signature_packet_signers**: `packet_id` + `signer_id` with `SIGNER_STATUS_INDEX` (`signer_id` + `status_key`) for signer inbox/status queries.
- **signature_packet_fields**: `packet_id` + `field_id` for packet field placement/fill state.
- **signature_packet_events**: `packet_id` + `event_id` append-only audit log.
- **signature_packet_artifacts**: `packet_id` PK for draft/final PDF artifact references.

### Ticketing schema and access patterns
- See [Ticketing DynamoDB schema](ticketing-dynamodb-schema.md) for `pk`/`sk` item families (`META`, `MSG`, `ACT`), owner/status/assignee GSIs, and optimistic concurrency (`version` + conditional updates).
