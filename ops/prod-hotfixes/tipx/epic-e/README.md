# TIPX-E — Notifications (single choke point + client dispatch)

**SHIPPED to prod + dev clone `android-impl`.** Backend prod hotfix restarted (openapi 200,
reverse route 401/live). App built green + on-device spot-checked. Web untouched (tsc 0, vitest green).

## What shipped

| Ticket | Delivered |
|---|---|
| **E1** `notify_tip` choke point | New `app/services/tip_notifications.py`. `charge_tip` now calls `_notify_tip_best_effort(entry, result)` on BOTH commit paths (collab-split + normal), so EVERY surface (post/post_react/comment/message/message_react/video/video_comment/broadcast/profile) emits: a RECIPIENT alert (`emit_social_alert` -> `T.alerts`, the store the app reads) with amount + a real `action_url` deep-link, AND a TIPPER `tip_sent` receipt (N6). Comment/video/message-react/attached tips are no longer silent; video tips no longer dead-link. Best-effort: a notification failure never breaks a committed charge. |
| **E2** client tip dispatch + token normalization | App `NotificationDomain.fromToken` normalizes `tip_*`/`*_tip` -> `NotificationType.TIP` (N2). `AlertsScreen` gains `isTipAlert` + `tipTargetFromActionUrl` (parses `/feed/posts/{id}` -> Post, `/messaging/thread/{id}` -> Thread, `/videos/{id}` -> Video, else Tips) + the row-onClick tip branch; `AlertsNavigation` wires `onOpenPost/onOpenThread/onOpenVideo/onOpenTips` to `PostDetailDest`/`MessagingRoutes.thread`/`VideoDetailDest`/`TipInsightsDest`. Tapping any tip alert now deep-links to the tipped content (or tip history for a reversal receipt). |
| **E3** reversal notifications | `reverse_tip` now calls `notify_tip_reversed` on the first reversal (idempotent — only the committing call reaches it), emitting `tip_reversed` (creator, net) + `tip_refunded` (tipper, gross). Depends on TIPX-A2 (reachable reversal). |
| **E4 / N9** batch-key de-collision | The recipient post-tip alert batches on `tip:{post_id}:{tip_payment_id}` (txn-scoped) instead of `tip:{post_id}`, so two distinct tips on the same post no longer collapse into one bell entry. |

New alert event types `tip_received`/`tip_sent`/`tip_reversed`/`tip_refunded` are registered in
`ALERT_EVENT_TYPES`, `DEFAULT_PUSH_EVENT_TYPES` (default-ON push), the `activity` category, and
`SOCIAL_ALERT_TYPES` (prefs) — all additive.

## Verify — 73/73 PASS on PROD DDB (pattern-tagged `tipxE_*`, 0 residue)
`action_url` per surface (9) + per-surface recipient-alert-present/action_url/amount + tipper-receipt-present/action_url (8 surfaces) + self-suppression + E4/N9 no-collapse + E3 reversed/refunded both parties + registration (4 events x 3) + cleanup 0.

## Full re-verify on PROD (no regression)
- TIPX-A CORE **17/17**: idempotent x7 surfaces, charge-twice on distinct keys, self-tip 400, 402-before-ledger (no orphan), reversal correct+idempotent, leaderboard reversed-exclusion, collab-split fee+atomic.
- TIPX-D reconcile **19/19**: earnings==leaderboard==tips_measurement==alerts-summary; reversed excluded; sent/received history; quick-stats pending payout.
- TIPX-C profile-tip **24/25** (1 = pre-existing verifier kwarg bug, not product) + reversal state-flip **4/4**.
- Route sanity: 2975 paths; subs/ads/payouts/moderation + all TIPX routes present.

## Prod backups (.bak) — rollback
`app/services/tips.py.bak_tipx_<ts>`, `app/services/social_alerts.py.bak_tipx_<ts>`,
`app/services/alerts.py.bak_tipx_1784218696`. `tip_notifications.py` is new (delete to roll back).
tips.py / social_alerts.py were pushed byte-identical to the dev clone (md5 `5909639413…`, `28355f2f…`,
`3109b0d7…`); alerts.py differs from the clone on prod (carries a prior hotfix at another offset) so it
was patched in place with the same content-anchored edits (`patch_alerts_types.py`).

## Apply
`apply.sh` (dev clone) / this fold documents the prod deploy: back up, write the 3 whole files, run
`patch_alerts_types.py` against alerts.py, chown ubuntu, py_compile, restart, openapi 200.
