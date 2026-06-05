# PRIVACY-001 gaps

- [HIGH] Export runs synchronously inline (no background worker) — `app/routers/privacy.py:71-73` — `process_export()` is called in the request handler with a comment "Process inline for MVP"; large exports (many messages, files) will time out the HTTP request and return a misleading 500 — Fix: queue the export as a background `asyncio` task or use an `add_event_handler("startup", …)` loop; return 201 immediately and let the worker update status — Effort: M

- [HIGH] `process_deletion()` in `gdpr_service.py` does not delete Messages, Conversations, or Participants — `app/services/gdpr_service.py:672-827` — User messages remain in DynamoDB after "full account deletion"; GDPR Article 17 compliance breach — Fix: add deletion steps for Messages/Conversations (DM handling) and Participants tables mirroring the ticket §7 design — Effort: M

- [HIGH] S3 files not deleted during account deletion — `app/services/gdpr_service.py:672-827` (no S3 `delete_object` calls) — Files the user uploaded persist in the `filemgr_bucket` S3 bucket; file manager DDB records are also not deleted — Fix: add S3 `delete_objects` batch call and file-manager DDB cleanup step to `process_deletion()` — Effort: M

- [HIGH] Cognito user is not disabled/deleted on account deletion — `app/services/gdpr_service.py:672-827` (no Cognito API calls) — Deleted users can still authenticate via their Cognito credentials; SEC-018 cross-ref: token revocation does not propagate — Fix: call `cognito_client.admin_disable_user` then `admin_delete_user` guarded by `_cognito_available()` check, matching the pattern in `app/core/aws.py` — Effort: S

- [MED] Newsfeed posts and comments not deleted — `app/services/gdpr_service.py:672-827` (no `app_single_table` queries) — User-authored posts and comments remain visible after account deletion — Fix: add step querying `app_single_table` for `POST#{user_sub}#*` items and deleting them — Effort: S

- [MED] Signature packets not deleted — `app/services/gdpr_service.py:672-827` (no `T.signature_packets` access) — Signed documents owned by the user remain in the system — Fix: add deletion step for `T.signature_packets` items owned by `user_sub` — Effort: S

- [MED] `AdminPrivacyPage.tsx` frontend page not built — `frontend/src/pages/admin/` (file absent); no `/admin/privacy` route in `frontend/src/App.tsx` — Admins can only manage deletion requests via raw API calls; no UI for approval/hold/release workflow — Fix: create `AdminPrivacyPage.tsx` per ticket §8 design and add route — Effort: M

- [MED] `DeleteAccountDialog.tsx` standalone component not built — `frontend/src/pages/settings/` (file absent) — Delete-account flow is presumably embedded in `PrivacyPage.tsx` without the multi-step dialog design (warn → password → reason) — Fix: extract into dedicated `DeleteAccountDialog.tsx` as specified — Effort: S

- [MED] `ExportStatusBanner.tsx` component not built — `frontend/src/pages/settings/` (file absent) — Export status polling and download link are not separately componentised, making reuse harder — Fix: extract `ExportStatusBanner` from `PrivacyPage.tsx` — Effort: S

- [LOW] Export worker polls for pending requests but there is no separate polling loop — `app/main.py:527` registers only `start_deletion_scheduler_task`; no export scanner task — If the inline export fails silently, the request stays in `pending` state with no retry mechanism — Fix: add `start_export_scanner_task` background loop that retries failed/stuck export requests — Effort: M
