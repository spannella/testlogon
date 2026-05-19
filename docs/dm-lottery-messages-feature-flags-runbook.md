# DM Lottery Messages Feature Flags Runbook (LOT-003)

## Flags
- `MESSAGING_DM_LOTTERY_ENABLED`
  - Default: `false`
  - Purpose: Primary rollout gate for DM lottery create/unlock/render surfaces.
- `MESSAGING_DM_LOTTERY_KILL_SWITCH`
  - Default: `false`
  - Purpose: Immediate hard disable even when rollout flag is enabled.

Effective enablement rule used by the API:
- `enabled = MESSAGING_DM_LOTTERY_ENABLED && !MESSAGING_DM_LOTTERY_KILL_SWITCH`

## Emergency Disable Procedure
1. Set `MESSAGING_DM_LOTTERY_KILL_SWITCH=true` in the target environment.
2. Roll/reload application configuration.
3. Verify `/messaging/config` reports `messaging_dm_lottery_enabled=false`.
4. Verify API behavior:
   - `POST /messaging/messages/lottery` returns `403` with `code=feature-disabled`.
   - `POST /messaging/messages/{message_id}/lottery/unlock` returns `403` with `code=feature-disabled`.
5. Keep kill switch enabled until incident is mitigated.

## Controlled Enable Procedure
1. Ensure kill switch is `false`.
2. Set `MESSAGING_DM_LOTTERY_ENABLED=true` for target cohort environment.
3. Roll/reload application configuration.
4. Verify `/messaging/config` returns `messaging_dm_lottery_enabled=true`.
5. Monitor error rates and latency before broader rollout.
