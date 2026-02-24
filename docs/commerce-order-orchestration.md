# Commerce Order Orchestration Service (CCE-061)

`app/services/commerce_order_service.py` introduces `CommerceOrderService` to persist canonical `orders` + `order_items` for all purchase sources.

## Methods

- `create_order(...)`
- `create_order_from_line_items(...)`

Both methods:

- validate line items via the CCE-060 canonical validator,
- enforce source consistency (`shopping_cart`, `commercial_direct`, `subscription_cycle`),
- persist one canonical order row and N order-item rows,
- persist source metadata and `correlation_id`,
- emit `commerce_order_created` audit events,
- return compatibility fields for existing consumers (including `checkout_session_id` passthrough if provided in metadata).

## Canonical persistence fields

Order fields include:

- `order_id`, `user_id`, `status`, `created_at`, `updated_at`
- `source_system`, `correlation_id`
- `currency`, `amount_cents`, `line_item_count`
- `metadata`

Order item fields include:

- `order_id`, `item_id`, `sku`, `product_type`, `billing_model`
- `source_system`, `quantity`, `scope`, `pricing_ref`
- `amount_cents`, `created_at`, `correlation_id`
