# Messaging Drafts Deployment & Migration Runbook (MSGD-017)

Date: 2026-04-05

## Scope

This runbook defines the deployment sequencing, compatibility windows, and verification steps for messaging drafts.

## Preflight checks (T-60 to T-15 min)

1. Confirm release gate status:
   - Backend: `MESSAGING_DRAFTS_MODE=disabled` (or `internal`) before migration.
   - Frontend: `VITE_MESSAGING_DRAFTS_ENABLED=false` for production rollout start.
2. Validate infrastructure prerequisites:
   - AWS credentials and target account/region are correct.
   - DynamoDB service quotas healthy (table + GSI limits).
3. Backward compatibility review:
   - API consumers tolerate `403` on draft endpoints while feature is disabled.
   - Frontend draft UI remains hidden/no-op when flag is disabled.
4. On-call readiness:
   - Messaging primary + platform secondary on-call acknowledged in release channel.
   - Rollback owner assigned.

## Migration sequencing

> Principle: **schema first, feature enablement second**.

1. Apply DynamoDB migration:

```bash
python scripts/migrations/20260405_messaging_drafts_schema.py
```

2. Verify migration outcome:
   - Table exists: `MessageDrafts` (or `DDB_MESSAGE_DRAFTS` override).
   - GSIs exist: `ByConversationUpdatedAt`, `ByOwnerUpdatedAt`.
   - TTL enabled on `ttl_epoch` (or `DRAFTS_TTL_ATTR`).
3. Deploy backend application version with draft endpoints + guards.
4. Deploy frontend application version with draft feature flags.
5. Keep feature disabled for a compatibility window (recommended 30–60 minutes) while validating baseline health.

## Compatibility window checks

While feature remains disabled:

- Request volume/error baselines unchanged on core messaging endpoints.
- No elevated 5xx rates on `/messaging/*`.
- Draft endpoint requests return expected disabled behavior (`403`) instead of 5xx.

## Feature enablement phases

1. Internal tenants only
2. Selective beta tenants/users
3. Full GA

Gate transitions should be performed by changing runtime configuration values (no binary rebuild required).

## Smoke tests (post-enable)

Run automated smoke sequence with:

```bash
bash scripts/ops/messaging_drafts_smoke.sh
```

Required env vars:

- `API_BASE` (e.g. `https://api.example.com`)
- `AUTH_TOKEN` (bearer token)
- `CONVERSATION_ID`

The smoke script validates: create -> list -> get -> update -> delete and prints pass/fail details.

## Post-deploy verification commands

### API-level checks

```bash
# draft operation volume
curl -s "$PROM_URL/api/v1/query" --data-urlencode 'query=sum(rate(messaging_draft_operations_total[5m])) by (operation,result)'

# draft latency p95
curl -s "$PROM_URL/api/v1/query" --data-urlencode 'query=histogram_quantile(0.95,sum(rate(messaging_draft_operation_duration_seconds_bucket[5m])) by (le,operation))'

# fallback trend
curl -s "$PROM_URL/api/v1/query" --data-urlencode 'query=sum(rate(messaging_draft_fallback_total[5m])) by (reason)'
```

### Functional checks

- Save draft from composer and confirm visibility after refresh.
- Switch conversations and confirm no draft leakage.
- Remove draft and confirm disappearance after refresh.

## Rollback procedure

1. Set `MESSAGING_DRAFTS_KILL_SWITCH=true`.
2. Set `VITE_MESSAGING_DRAFTS_KILL_SWITCH=true`.
3. Validate:
   - Draft UI hidden.
   - Draft endpoints reject with controlled `403`.
4. If required, roll back app version after kill-switch mitigation.

## Execution record template

- Release ID:
- Operator:
- Start time:
- Migration applied at:
- Compatibility window start/end:
- Smoke script result:
- Metrics check result:
- Incidents/data-loss observed: **None / Details**
- Final gate mode:
- End time:
