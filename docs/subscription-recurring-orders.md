# Subscription Recurring Orders (CCE-066 / CCE-069 hard-wiring)

Subscription charge/renewal events now emit canonical commercialization orders using `source_system=subscription_cycle`.

## Behavior

- `emit_subscription_cycle_order(...)` creates canonical `orders` + `order_items` via `CommerceOrderService`.
- Order metadata links recurring charge context:
  - `subscription_id`
  - `invoice_id`
  - `provider_invoice_id`
- Invoice records persist `recurring_order_id` for traceability.

## Reconciliation + dead-letter behavior

- The runtime path is hard-wired: recurring order emit invokes reconciliation with normalized identity:
  - `provider=subscription_system`
  - `event_id=subscription_charge:<invoice_id>`
- Failed recurring grant attempts are dead-lettered and surfaced with ownership metadata (`owner_team=commerce_platform`) and remediation hint (`replay_recurring_grants_for_invoice_range`).

## Runbook: replay recurring order grants by invoice range

Use the subscription-cycle reconciliation gateway replay helper for targeted reruns in staging/prod operations:

```python
from app.services.subscription_cycle_orders import default_reconciliation_gateway

result = default_reconciliation_gateway.replay_dead_letters_for_invoice_range(
    invoice_start="inv_2026_01_0001",
    invoice_end="inv_2026_01_0100",
)
print(result)
```

Expected output fields:

- `replayed`: dead-letter rows selected in range
- `processed`: successfully replayed rows (`processed` or `duplicate`)
- `failed`: rows that remained non-terminal after replay
- `remaining_dead_letters`: queue depth after replay
