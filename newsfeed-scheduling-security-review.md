# NFS-029 Security & Authorization Review — Scheduled Newsfeed Posts

## Review scope

- Endpoints reviewed:
  - `GET /posts/scheduled`
  - `PATCH /posts/{post_id}` (schedule update path)
  - `POST /posts/{post_id}/cancel`
- Data paths reviewed:
  - owner-scoped scheduled ref listing
  - post ownership checks for edit/cancel
  - scheduler publish transition writes

## Threat considerations

1. **Cross-user scheduled list disclosure**
   - Risk: attacker reads another creator's scheduled posts.
   - Control: list query is bound to caller partition (`pk_user(user_id)`), and fetched posts are filtered by `post.user_id == user_id` and `status == scheduled`.

2. **Cross-user schedule mutation (edit/cancel)**
   - Risk: attacker modifies/cancels another creator's scheduled post.
   - Control: edit/cancel fetch `POST#{id}/META` and enforce `post.user_id == caller_user_id`; non-owner returns `403 Not your post`.

3. **State-confusion writes**
   - Risk: changing lifecycle from unexpected state (`published`, `cancelled`, malformed rows).
   - Control: transactional conditions require expected `status` transitions and deterministic conflict handling (`409` conflict codes).

4. **Feature-flag bypass during rollout/incident**
   - Risk: scheduling paths remain usable while flagged off.
   - Control: API-level gate (`schedule_feature_disabled`) blocks scheduling payload/paths; worker gate returns no-op summary with `worker_enabled=false`; UI gate hides scheduling controls.

5. **Worker privilege misuse**
   - Risk: worker publishes unauthorized/incorrect records.
   - Control: due-index query targets schedule rows; publish transaction conditioned on `status=scheduled` and `publish_at<=now`, plus idempotent handling for already-published/cancelled rows.

## Security test sign-off checklist

- [x] Cross-user list denial: scheduled posts with non-matching `user_id` are filtered out.
- [x] Cross-user edit denial: non-owner receives `403`.
- [x] Cross-user cancel denial: non-owner receives `403`.
- [x] API feature-flag disabled path verified (`schedule_feature_disabled`).
- [x] Worker feature-flag disabled no-op verified.

## Added/updated tests

- `tests/test_newsfeed_content_envelope.py`
  - `test_list_scheduled_posts_filters_cross_user_posts`
  - `test_edit_post_schedule_update_rejects_non_owner`
  - `test_cancel_scheduled_post_rejects_non_owner`
- Existing flag tests retained for disabled-path protection.

## Residual risk and mitigations

- **Residual:** compromised owner session can still access owner's schedule data.
  - **Mitigation:** existing auth/session controls, CSRF enforcement, audit logs.
- **Residual:** operational misconfiguration of flags may expose/disable features unexpectedly.
  - **Mitigation:** staged rollout runbook, explicit rollback sequence, metrics/alerts monitoring.

## Reviewer sign-off

- Security reviewer: ____________________
- Date: ____________________
- Decision: **Approved / Approved with Conditions / Rejected**
- Notes: ______________________________________________
