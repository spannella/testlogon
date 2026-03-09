# Moderation Feature Flags and Staged Rollout (MOD-028)

This rollout plan is backed by runtime feature flags stored server-side and editable via admin API (root-only updates), so moderation behavior can be toggled without redeploy.

## Runtime flags

- `enabled`
- `report_feed_enabled`
- `report_messages_enabled`
- `report_profile_enabled`
- `admin_board_enabled`
- `admin_actions_enabled`
- `enforcement_enabled`
- `min_scope_for_board` (`content_moderation` | `content_moderation_senior`)
- `min_scope_for_actions` (`content_moderation` | `content_moderation_senior`)
- `min_scope_for_permanent_ban` (`content_moderation` | `content_moderation_senior`)

## API

- `GET /v1/admin/moderation/feature-flags`
- `PUT /v1/admin/moderation/feature-flags` (root only)

## Suggested staged rollout

1. **Dark launch**
   - `enabled=true`
   - `report_*_enabled=true`
   - `admin_board_enabled=true`
   - `admin_actions_enabled=false`
2. **Board-only for senior admins**
   - `min_scope_for_board=content_moderation_senior`
3. **Operational rollout**
   - `admin_actions_enabled=true`
   - `min_scope_for_actions=content_moderation_senior`
4. **Broaden to moderators**
   - `min_scope_for_board=content_moderation`
   - `min_scope_for_actions=content_moderation`
5. **Permanent-ban control**
   - Keep `min_scope_for_permanent_ban=content_moderation_senior`

## Behavior summary

- Report intake checks per-surface flags before persistence.
- Admin board/ticket reads check board flag + minimum scope.
- Admin actions (claim/decision/resolve/KPI alert evaluation) check actions flag + minimum scope.
- Permanent-ban flow also checks `min_scope_for_permanent_ban`.
