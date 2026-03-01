# Subscription Plan → Entitlement Template Mapping (CCE-065)

This contract standardizes how subscription plans produce entitlement templates.

## Mapping outputs

`map_plan_to_entitlement_template(plan)` returns a canonical template with:

- `access`
- `limits`
- `credits`
- `window` (`starts_at`, `ends_at`, `interval`, `renewal_policy`, pause/resumption policy)
- `plan_version` compatibility metadata

## Version compatibility

`assert_plan_version_compatible(plan)` enforces:

- `plan_version >= min_supported_version`
- `plan_version <= max_supported_version`

## Lifecycle policy mapping

`map_subscription_state_to_entitlement(subscription, template)` maps subscription states to entitlement states:

- `active` / `trialing` → `active` (until period end)
- `paused` / `past_due` / `unpaid` → `pending_payment`
- `canceled` / `expired` / ended states → `expired`
- `cancel_at_period_end=true` expires after `current_period_end`

## Plan changes

`project_plan_change_templates(current_plan, next_plan, effective_at)` emits current/future templates so plan changes update future entitlement behavior deterministically at the effective boundary.
