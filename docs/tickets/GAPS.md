# GAPS — Consolidated Second-Pass Remediation Plan

Generated from the as-built gap audit of every ticket (`docs/tickets/gaps/<TICKET>.md`).
Each CRIT/HIGH item also has its own actionable ticket in `docs/tickets/gap-tickets/GAP-NNNN-*.md`.
Security findings are tracked separately as SEC-001..025; the detection/response build-out as SECOPS-001..007.

## Tally

- **CRIT**: 34  ·  **HIGH**: 350  ·  **MED**: 572  ·  **LOW**: 454
- **Actionable GAP tickets created (CRIT+HIGH)**: 384  (GAP-0001 … GAP-0384)
- **Unbuilt features** (full write-ups in `writeups/`): 18 — ADS-009, ADS-019, BILLING-004, BOT-003, BOT-004, DEVTOOLS-001, FIN-005, FIN-007, HELP-001, HELP-002, KYC-007, KYC-025, LCOM-003, LEGAL-001, MSG-012, PLATFORM-017, QST-001, ROOT-AUTH-001

## CRITICAL — fix first

| GAP | Source | Title | Location | Fix |
|-----|--------|-------|----------|-----|
| GAP-0001 | ADS-004 | no daily spent_today_cents reset task | `app/services/ad_serving.py:_has_budget` | add startup background task that resets spent_today_cents=0 at midnight UTC for budget_type=daily campaigns |
| GAP-0002 | ADS-006 | serve_broadcast_ad stub not wired to ADS-004 engine | `app/services/broadcast_ads.py:55–83` | replace stub body with delegation to app.services.ad_serving.serve_ad with graceful degradation |
| GAP-0003 | ADS-007 | internal charge endpoints lack access control | `app/routers/ads.py:447,460,473` | add account ownership verification before each charge handler, or move to require_admin_or_root |
| GAP-0004 | ADS-010 | revenue-share PUT endpoint allows any user to self-set share to 100% | `app/routers/content_ad_controls.py:116` | gate PUT /revenue-share on require_admin_or_root; add creator_sub to request body |
| GAP-0005 | ADS-012 | elevate_feed_items() not called from newsfeed router | `app/routers/newsfeed.py` | call elevate_feed_items(posts, viewer_id) in GET /feed handler after organic post fetch |
| GAP-0006 | ADS-014 | legacy record_ad_impression() in ad_placement.py has no fraud check | `app/services/ad_placement.py:233` | add check_fraud() call at start of record_ad_impression(); pass ip_address, user_agent, view_time_ms, campaign_id |
| GAP-0007 | ADS-020 | serve_broadcast_ad not wired to real ad serving engine | `app/services/broadcast_ads.py:55–83` | replace stub with serve_ad() delegation; fall back to house creative on engine error |
| GAP-0008 | AFFILIATE-001 | Commission replay | `put_item` | write dedup sentinel `COMMISSION_DEDUP#{transaction_id}` with `attribute_not_exists(pk)` before commission put, or drop `ts` from SK and add |
| GAP-0009 | AGENT-001 | custom base_url SSRF | `app/services/llm_provider_keys.py:173` | validate https:// scheme only, reject RFC-1918/link-local/loopback ranges in field_validator |
| GAP-0010 | AGENT-003 | agent loop not running as background task | `app/services/agent_orchestrator.py:705` | add _running_loops registry, create asyncio.create_task(run_agent_loop(...)) in start_agent_loop |
| GAP-0011 | AGENT-006 | respond_to_feedback does not inject response or resume agent | `app/services/terminal_monitor.py:233` | call _inject_into_terminal(sanitized_response) and transition_agent_state(user_id, worker_id, "working") inside respond_to_feedback |
| GAP-0012 | AGENT-006 | WebSocket hook not wired | `app/routers/browser_ssh_terminal.py` | tap terminal data in WebSocket forwarding loop, call process_terminal_output and dispatch on returned signal |
| GAP-0013 | AUTH-001 | abandoned registration permanently blocks email re-use | `app/services/registration.py:79` | set DDB TTL (registration_expires_at) on T.users and T.account_state items when verification_required=True; add REGISTRATION_PENDING_TTL_DAY |
| GAP-0014 | BOT-001 | `_message_out_from_item` never populates bot fields | `_message_out_from_item` | add `sender_type=merged_item.get("sender_type")`, `bot_id=...`, `bot_name=...`, `bot_avatar_url=...`, `quick_replies=...` to the `return Mes |
| GAP-0015 | BOT-001 | `send_bot_message()` returns a dict but never writes to DynamoDB | `send_bot_message()` | implement `create_internal_bot_message()` helper in `messaging.py` and call it from `send_bot_message()` |
| GAP-0016 | CALL-011 | `useCallBillingHeartbeat.ts` hook does not exist | `useCallBillingHeartbeat.ts` | implement hook with `setInterval` at `heartbeat_interval_seconds`, dispatch `end_call` action on `action==="end_call"` response per §4.1 |
| GAP-0017 | CALL-012 | `useGroupCall.ts` hook does not exist | `useGroupCall.ts` | implement hook with mesh/SFU mode selection driven by join response per §4.1 |
| GAP-0018 | ENTERPRISE-002 | Unvalidated `RelayState` redirect | `RelayState` | Parse the RelayState URL; reject any value whose host differs from the platform's own origin; default to `/` on rejection. |
| GAP-0019 | FIN-004 | Implementation aggregates creator EARNINGS (credits) but spec requires consumer SPENDING (debits) | `app/services/consumer_tax_documents.py:4,107-163` | rewrite `_query_credit_entries` to query `type="debit"` entries and replace `classify_entry` with a `classify_category` function mapping deb |
| GAP-0020 | FIN-008 | TIN/SSN collection and KMS-encrypted storage absent | `app/services/tax_form_1099.py:55` | implement `submit_tax_info()` with `kms_encrypt(tin)` before storage, replace placeholder with real recipient TIN in `_render_1099_pdf` |
| GAP-0021 | GROUP-004 | `dissolve_group()` never calls `dissolve_treasury()` | `dissolve_group()` | add `from app.services import group_treasury as treasury_svc` to `user_groups.py` and call `treasury_svc.dissolve_treasury(group_id)` before |
| GAP-0022 | INFRA-011 | SSRF via SEC-020 | `app/services/ssh_bastion.py:65-83` | after normalising the IP, call `addr.is_private() or addr.is_loopback() or addr.is_link_local()` and raise `InvalidHop` if true; also reject |
| GAP-0023 | KYC-009 | Users table key schema mismatch | `app/services/kyc_tiers.py` | audit `scripts/local-ddb-init.py` for the users table key schema; correct all `GetItem`/`UpdateItem` calls in `kyc_tiers.py` to use the cano |
| GAP-0024 | KYC-010 | `ByCase` GSI fallback performs full table scan | `ByCase` | replace fallback with `logger.exception(...); return []` to return an empty list safely |
| GAP-0025 | KYC-021 | Webhook `secret` is stored in plaintext in DynamoDB | `secret` | encrypt the secret with KMS (reuse `app/core/crypto.py`'s `kms_encrypt` / `kms_decrypt`) before storing and decrypt on read in `_emit_callba |
| GAP-0026 | LICENSE-003 | Revenue split hooks absent from all qualifying billing flows | `app/routers/messaging.py` | add `process_revenue_split(...)` call after the primary ledger entry in each qualifying billing handler (messaging tip/unlock, newsfeed post |
| GAP-0027 | MOD-002 | DMCA waiting-period background timer not wired to startup | `app/main.py:482-483` | add `_dmca_timer_loop` async background task registered on startup per section 3.7 |
| GAP-0028 | PLATFORM-012 | `POST /feed/record` accepts arbitrary `user_id` from request body (SEC-005 cross-ref) | `POST /feed/record` | replace `user_id=body.user_id` with `user_id=session["user_sub"]` at `activity_feed.py:159`; if an admin injection path is needed for test/d |
| GAP-0029 | PLATFORM-018 | Old `POST /ui/delete-account` endpoint skips production password verification | `POST /ui/delete-account` | remove or redirect the old endpoint, or add `verify_user_password` call matching `account_deletion.py:67` |
| GAP-0030 | ROOTCTL-001 | No break-glass secret or KMS gate on CLI mutations | `app/cli/rootctl.py:2006-2018` | add `_require_break_glass_auth()` gate reading `ROOTCTL_BREAK_GLASS_SECRET` env var (or KMS) before any write in `_dispatch_mutation_gate()` |
| GAP-0031 | SIGN-001 | No `POST /{packet_id}/signers` API endpoint | `POST /{packet_id}/signers` | add `POST /{packet_id}/signers` and `DELETE /{packet_id}/signers/{signer_id}` per ticket §2.1 |
| GAP-0032 | SYND-004 | Admin can disburse treasury funds to their own wallet, violating the core no-admin-withdrawal constraint | `app/services/syndicate_treasury.py:240-339` | add `if admin_sub == recipient_user_id: raise HTTPException(400, "Admin cannot disburse to themselves")` at the start of `disburse()` |
| GAP-0033 | VOD-004 | FFmpeg receives s3:// URI directly; most builds lack S3 protocol support | `app/services/transcode_worker.py:234` | create `app/services/vod_s3_downloader.py`; download source to `scratch_dir/source.<ext>` before rendition loop and pass local path as input |
| GAP-0034 | VOD-005 | VideoMetadata.hls_manifest_url never populated after transcoding | `app/services/transcode_worker.py:195` | after `complete_job_with_outputs`, fetch the VideoMetadata record and update `hls_manifest_url`, `thumbnail_url`, and renditions via `put_it |

## HIGH — by area


### ADMIN

- **GAP-0035** [ADMIN-002] missing CSRF on template mutation endpoints — `app/routers/admin_notifications.py:1` — Fix: switch PATCH and POST endpoints to require_admin_or_root_csrf dependency
- **GAP-0036** [ADMIN-003] removeFromBlocklist and removeFromAllowlist use wrong /v1/ URL prefix — `frontend/src/api/endpoints/adminRateLimits.ts:67` — Fix: change both calls to use /ui/admin/rate-limits/ prefix

### ADMIN-PERMS

- **GAP-0037** [ADMIN-PERMS-001] admin_capabilities system is dead code — `app/cli/rootctl.py:51` — Fix: repoint _admin_capabilities_set_command to write admin_profile.scopes (Option A in §4.1)
- **GAP-0038** [ADMIN-PERMS-001] CLI admin grant produces implicit full admin — `app/cli/rootctl.py:1303` — Fix: add --scope and --profile-type args to grant command; write admin_profile in UpdateExpression

### ADS

- **GAP-0039** [ADS-001] no max-5-accounts-per-user rate limit — `app/services/ad_accounts.py:create_ad_account` — Fix: count `list_accounts_by_owner` before put_item, raise ValueError if >= 5
- **GAP-0040** [ADS-002] no server-side MIME magic-byte validation on asset upload — `app/routers/ads.py:_validate_asset` — Fix: add imghdr/magic-bytes check on raw file data before S3 upload
- **GAP-0041** [ADS-003] update_creator_ad_settings is full PutItem, not partial update — `app/services/creator_ad_prefs.py:update_creator_ad_settings` — Fix: replace PutItem with UpdateExpression SET using only non-None fields
- **GAP-0042** [ADS-003] allowed_ad_categories enforcement missing in serving engine — `app/services/ad_serving.py` — Fix: read allowed_ad_categories from creator_settings in serve_ad campaign loop and skip non-matching campaigns
- **GAP-0043** [ADS-004] list_campaigns_by_status does not use ByStatusCreatedAt GSI — `app/services/ad_campaigns.py:list_campaigns_by_status` — Fix: use Query(IndexName="ByStatusCreatedAt", KeyConditionExpression=Key("status").eq(status))
- **GAP-0044** [ADS-004] bid_cpm_cents not a campaign field — `app/models.py:CampaignCreateIn` — Fix: add bid_cpm_cents to CampaignCreateIn/CampaignOut (coordinate with ADS-001 model)
- **GAP-0045** [ADS-005] ad_feedback records accumulate without TTL — `app/services/ad_feedback.py:record_ad_feedback` — Fix: add expires_at = now_ts() + 90*86400 to every feedback item; enable TTL on billing table
- **GAP-0046** [ADS-006] role-type comparison bug in ad-break authorization — `app/routers/broadcast_ads.py:127` — Fix: change comparison to {Role.ADMIN, Role.ROOT} using imported Role enum
- **GAP-0047** [ADS-006] BROADCAST_PREROLL_ENABLED and BROADCAST_MIDROLL_ENABLED flags absent — `app/core/settings.py` — Fix: add both flags to settings.py and gate in build_pre_roll and trigger_ad_break_route
- **GAP-0048** [ADS-007] no daily spent_today_cents reset background task — `app/services/ad_billing.py:_process_charge` — Fix: add startup background task resetting spent_today_cents=0 at midnight UTC with last_reset_date guard
- **GAP-0049** [ADS-007] platform revenue (30% share) not written to any ledger — `app/services/ad_billing.py:_split_revenue` — Fix: write platform_revenue entry to ad_billing table with PK=PLATFORM#revenue after each split
- **GAP-0050** [ADS-008] compute_hourly_rollup never called by anything — `app/services/ad_analytics.py:compute_hourly_rollup` — Fix: register hourly background task in app/main.py startup that calls compute_hourly_rollup for all active campaigns
- **GAP-0051** [ADS-008] by_creative, by_surface, by_targeting maps written as empty dicts — `app/services/ad_analytics.py:compute_hourly_rollup:201–203` — Fix: compute breakdown maps from billing ledger entries grouped by creative_id and surface
- **GAP-0052** [ADS-010] min-CPM floor never checked in ad serving engine — `app/services/ad_serving.py:serve_ad` — Fix: read get_full_ad_settings(creator_id) in campaign loop and skip campaigns with bid_cpm < min_cpm
- **GAP-0053** [ADS-010] record_transparency() never called from billing pipeline — `app/services/content_ad_controls.py:243` — Fix: call record_transparency from ad_billing._split_revenue after writing creator credit
- **GAP-0054** [ADS-010] dynamic per-creator revenue share not connected to billing engine — `app/services/ad_billing.py:_split_revenue` — Fix: call get_creator_revenue_share_bps(creator_id) and convert bps to pct in _split_revenue
- **GAP-0055** [ADS-011] webhook system entirely absent — `app/services/` — Fix: implement app/services/ad_webhooks.py + ad_webhooks DDB table + POST/GET/DELETE/test endpoints in advertiser_api_router
- **GAP-0056** [ADS-011] no per-API-key rate limiting — `app/routers/advertiser_api.py` — Fix: add check_rate_limit middleware on advertiser_api_router at 1000 req/min per key
- **GAP-0057** [ADS-011] ads:* scopes not surfaced in frontend API key creation UI — `frontend/src/pages/security/` — Fix: add ads:manage, ads:read, ads:serve to the capability selector component
- **GAP-0058** [ADS-012] no content ownership validation at boost creation — `app/services/content_boost.py:create_boost` — Fix: call _verify_content_ownership(owner_sub, content_type, content_id) before wallet charge
- **GAP-0059** [ADS-012] no duplicate-active-boost guard — `app/services/content_boost.py:create_boost` — Fix: query GSI2 for active boosts before write; raise ValueError if one exists
- **GAP-0060** [ADS-013] FTC labeling limited to post content_type only — `app/services/sponsorship_deals.py:_add_ftc_label:272` — Fix: extend _add_ftc_label to update T.video_metadata and T.broadcasts for respective content types
- **GAP-0061** [ADS-013] brand name fallback exposes advertiser user sub as PII — `app/services/sponsorship_deals.py:submit_content:521` — Fix: fall back to "a verified brand partner" rather than the user sub string
- **GAP-0062** [ADS-015] ROAS calculation service not implemented — `app/services/` — Fix: create app/services/ad_roas.py with calculate_campaign_roas and wire GET endpoint in ad_creative_affiliate.py router
- **GAP-0063** [ADS-015] E2E spec absent — `frontend/e2e/` — Fix: create spec with 18 tests covering sections 405-408
- **GAP-0064** [ADS-016] E2E spec absent — `frontend/e2e/` — Fix: create spec covering dayparting CRUD, flight scheduling, eligibility and pacing endpoints
- **GAP-0065** [ADS-016] unit tests absent — `tests/` — Fix: create test_ad_scheduling.py with 9 tests covering validation, eligibility, flight resolution, and pacing
- **GAP-0066** [ADS-017] frontend components entirely absent — `frontend/src/pages/ads/` — Fix: create all four files per ticket spec sections 3.8-3.9
- **GAP-0067** [ADS-017] creative_weights written by apply_recommendation but not consumed by serving engine — `app/services/ad_serving.py:serve_ad` — Fix: read campaign.get("creative_weights") in serve_ad and pass to random.choices as weights
- **GAP-0068** [ADS-018] global ad kill switch absent — `app/services/admin_ad_platform.py` — Fix: implement toggle_kill_switch service + POST /ui/admin/ad-platform/kill-switch endpoint + serve_ad check at startup
- **GAP-0069** [ADS-018] account suspension does not cascade to pause active campaigns — `app/services/admin_ad_platform.py:moderate_account` — Fix: in moderate_account for action=suspend, update all active campaigns for the account to status=paused
- **GAP-0070** [ADS-018] frontend AdminAdDashboard absent — `frontend/src/pages/admin/ads/` — Fix: create AdminAdDashboard.tsx and frontend/src/api/endpoints/adminAds.ts
- **GAP-0071** [ADS-020] record_ad_event does not write to ad_billing, ad_fraud_prevention, or ad_analytics — `app/services/broadcast_ads.py:record_ad_event:185–216` — Fix: wire charge_ad_event, check_impression_fraud, and record_impression_event into record_ad_event gated by BROADCAST_ADS_BILLING_ENABLED flag
- **GAP-0072** [ADS-020] BROADCAST_ADS_BILLING_ENABLED feature flag missing — `app/core/settings.py` — Fix: add broadcast_ads_billing_enabled bool to settings.py; add to .env.local.example
- **GAP-0073** [ADS-020] LivePlayer.tsx adJoinMutation triggered by session state instead of sessionId — `frontend/src/pages/broadcast/LivePlayer.tsx:138–142` — Fix: change useEffect dependency from [session] to [sessionId, isAuthenticated] to decouple ad join from playback resolution

### AFFILIATE

- **GAP-0074** [AFFILIATE-001] Attribution race — `put_item` — Fix: add `ConditionExpression="attribute_not_exists(pk)"` and catch `ConditionalCheckFailedException` (cross-ref SEC-013)
- **GAP-0075** [AFFILIATE-001] Withdrawal endpoint absent — `POST /ui/referrals/withdraw` — Fix: implement `withdraw(user_id, amount_cents)` in service and add router endpoint per ticket §8 spec

### AGENT

- **GAP-0076** [AGENT-001] budget bypass via race condition — `app/services/llm_provider_keys.py:310` — Fix: replace with single atomic UpdateItem or DDB transaction
- **GAP-0077** [AGENT-001] monthly usage reset not automated — `app/services/llm_provider_keys.py:310` — Fix: add daily startup task scanning for expired usage_reset_at and resetting
- **GAP-0078** [AGENT-002] custom_install_commands shell injection latent — `app/models.py:5276` — Fix: either remove the fields or validate against an allowlist of named steps; exec via argv with shell=False only
- **GAP-0079** [AGENT-002] repo_url shell injection latent — `app/services/agent_worker_provisioner.py` — Fix: subprocess(["git","clone","--",repo_url,...], shell=False) after validating https:// or git@ only, no shell metacharacters
- **GAP-0080** [AGENT-002] idle-worker auto-shutdown stub not implemented — `app/services/agent_worker_provisioner.py:462` — Fix: query ByStatus GSI for ready workers, filter by last_activity_at < now-idle_timeout, call stop_worker
- **GAP-0081** [AGENT-003] double-write claim race — `app/services/agent_orchestrator.py:255` — Fix: wrap both writes in TransactWriteItems
- **GAP-0082** [AGENT-003] inject_ticket_context prompt injection — `app/services/agent_orchestrator.py:598` — Fix: apply _sanitize_ticket_field to escape signal tokens before interpolation
- **GAP-0083** [AGENT-004] eligible ticket count pagination incomplete — `app/services/agent_fleet.py:288` — Fix: add pagination loop over LastEvaluatedKey collecting COUNT
- **GAP-0084** [AGENT-005] memory content prompt injection — `app/services/agent_memory.py:400` — Fix: apply _sanitize_ticket_field signal-token escaping to all memory content and title fields before assembly
- **GAP-0085** [AGENT-005] summarization LLM call not implemented for prod — `app/services/agent_memory.py:535` — Fix: implement SummarizationClient interface with MockSummarizationClient (dev) and AnthropicSummarizationClient (prod) gated by S.dev_mode
- **GAP-0086** [AGENT-006] create_feedback_request does not pause agent — `app/services/terminal_monitor.py:191` — Fix: add transition_agent_state(user_id, worker_id, "awaiting_feedback") inside create_feedback_request
- **GAP-0087** [AGENT-006] ReDoS via user-provided patterns — `app/services/terminal_monitor.py:410` — Fix: probe compiled pattern on 1000-char string with signal.setitimer timeout; reject on timeout
- **GAP-0088** [AGENT-007] live GitHub API not wired — `app/services/agent_pr_integration.py:380` — Fix: implement httpx POST to GitHub REST API /repos/{owner}/{repo}/pulls with parsed owner/repo from repo_url
- **GAP-0089** [AGENT-008] command injection in build_coder_workflow coding_cmd — `app/services/agent_coder.py:559` — Fix: store as structured argv field; exec via subprocess(argv, shell=False)
- **GAP-0090** [AGENT-008] build_pr_command double-quote injection — `app/services/agent_coder.py:482` — Fix: apply single-quote escaping _sq(v) = "'" + v.replace("'","'\\''"+"'") + "'"
- **GAP-0091** [AGENT-009] PR review command injection — `app/services/agent_qa.py:890` — Fix: apply single-quote escaping _sq(v) to report body
- **GAP-0092** [AGENT-010] health check URL shell injection latent — `app/services/agent_devops.py:1217` — Fix: use subprocess.run(["curl","--silent","--fail",url], shell=False)
- **GAP-0093** [AGENT-010] auto_deploy_on_qa_approved trigger not wired — `app/services/agent_devops.py` — Fix: add qa_approved filter in AGENT-003 worker loop when this flag is set
- **GAP-0094** [AGENT-011] repo_branch shell injection latent — `app/services/agent_architect.py:1153` — Fix: add _sanitize_branch() in _normalize_config and validate repo_branch in validate_architect_config
- **GAP-0095** [AGENT-011] analysis prompt command injection latent — `app/services/agent_architect.py:1144` — Fix: store as argv field, exec via subprocess(argv, shell=False)
- **GAP-0096** [AGENT-011] absolute path not rejected in scan_paths — `app/services/agent_architect.py:204` — Fix: add str(path).startswith("/") check to reject absolute paths
- **GAP-0097** [AGENT-012] backlog scan misses sparse tickets — `app/services/agent_project.py:685` — Fix: add pagination loop collecting up to limit matching results
- **GAP-0098** [AGENT-013] trigger_review in-memory lock not distributed — `app/services/agent_pm.py:714` — Fix: replace with DDB conditional put_item on LOCK# item with TTL
- **GAP-0099** [AGENT-014] backend computes source hashes directly from filesystem — `app/services/agent_docs.py:198` — Fix: gate local hash computation on S.dev_mode; accept externally-provided source_hashes dict from agent via API payload
- **GAP-0100** [AGENT-015] concurrent audit trigger race condition — `app/services/agent_compliance.py:788` — Fix: add conditional put_item on RUNNING_LOCK item in start_audit with attribute_not_exists ConditionExpression
- **GAP-0101** [AGENT-015] SEC-021 latent: no repo_url validation before real execution — `app/services/agent_compliance.py:1041` — Fix: validate repo_url against allowed_repo_hosts allowlist before dispatching
- **GAP-0102** [AGENT-015] SEC-022: GitHub token must not be stored in DDB config — `app/services/agent_compliance.py` — Fix: add github_token_secret_name (reference only) to config; resolve via KMS at execution time, expose only has_github_token: bool
- **GAP-0103** [AGENT-016] app credentials injection not implemented — `app/services/agent_stylist.py:721` — Fix: add app_auth_credentials_secret_name to config; resolve via KMS at trigger time, expose only has_app_credentials: bool
- **GAP-0104** [AGENT-017] no scheduled-publish background loop — `app/services/agent_marketing.py:507` — Fix: add asyncio background task in app/main.py calling publish_due_scheduled_content every 30s
- **GAP-0105** [AGENT-018] no automatic cost collection schedule — `app/main.py` — Fix: add hourly asyncio background task calling run_cost_collection_if_enabled gated by S.accountant_agent_execute_commands

### ANALYTICS

- **GAP-0106** [ANALYTICS-001] top_content view attribution bug — `app/services/creator_analytics.py:432` — Fix: store per-content view counts as a DDB map in rollup rows, or use _resolve_content_details live view counts from T.video_metadata (Option B already available vi

### AUTH

- **GAP-0107** [AUTH-001] /check endpoint leaks no unverified hint to frontend — `app/routers/register.py:153` — Fix: implement check_email_status returning {"available": bool, "unverified": bool}; update RegisterEmailCheckResp model and /check response
- **GAP-0108** [AUTH-001] /register/start has no resume path for pending_verification accounts — `app/routers/register.py:114` — Fix: add resume branch before create_user_record that detects pending_verification and re-issues challenge; gate on REGISTRATION_ALLOW_RESUME_UNVERIFIED setting
- **GAP-0109** [AUTH-001] frontend shows hard dead-end with no recovery UI — `frontend/src/pages/Register.tsx:616` — Fix: split into unavailable_verified (keep error) and unavailable_unverified (show resend + start-over options); wire to POST /register/resend

### BCAST

- **GAP-0110** [BCAST-001] SEC-025 IDOR on lifecycle routes — `broadcast.py:360,402,453` — Fix: add `_require_operator_and_owner(session_id, ctx)` helper before lifecycle operations
- **GAP-0111** [BCAST-001] Status-filter list exposes all creators' sessions — `broadcast.py:316` — Fix: scope `list_sessions_by_status` to `creator_id=ctx["user_sub"]` for non-admin callers
- **GAP-0112** [BCAST-002] SEC-010 IDOR — `broadcast.py:717` — Fix: call `check_viewer_access(session_id, ctx["user_sub"], ...)` before subscribing
- **GAP-0113** [BCAST-002] SEC-010 IDOR — `broadcast.py:1763` — Fix: call `check_viewer_access` and pass `viewer_user_id=ctx["user_sub"]` to `_chat_msg_out`
- **GAP-0114** [BCAST-002] SEC-010 — `_chat_msg_out` — Fix: pass `viewer_user_id=ctx["user_sub"]` to `_chat_msg_out(msg, viewer_user_id=ctx["user_sub"])`
- **GAP-0115** [BCAST-004] SEC-010 IDOR — `broadcast.py:717` — Fix: call `check_viewer_access(session_id, ctx["user_sub"], ...)` before queue subscription
- **GAP-0116** [BCAST-005] SEC-010 IDOR — `check_viewer_access` — Fix: call `check_viewer_access` + pass `viewer_user_id=ctx["user_sub"]` to `_chat_msg_out`
- **GAP-0117** [BCAST-005] SEC-010 — `check_viewer_access` — Fix: add `check_viewer_access` call after `session.status` check in `send_chat_message_route`
- **GAP-0118** [BCAST-005] SEC-010 — `_chat_msg_out` — Fix: pass `viewer_user_id=ctx["user_sub"]` to `_chat_msg_out(msg, ...)` in the chat stream generator
- **GAP-0119** [BCAST-006] `inventory_segments` production path is a stub — `inventory_segments` — Fix: implement paginated `s3.get_paginator("list_objects_v2")` with moto endpoint in dev
- **GAP-0120** [BCAST-006] `concatenate_segments` production path is a stub — `concatenate_segments` — Fix: implement FFmpeg concat demuxer subprocess + S3 upload via new `_upload_to_s3` helper
- **GAP-0121** [BCAST-006] `_upload_to_s3` helper missing — `_upload_to_s3` — Fix: create `_upload_to_s3(local_path, *, bucket, key)` using `boto3.client("s3", endpoint_url=...)`
- **GAP-0122** [BCAST-008] MP4 never uploaded to S3 in production path — `broadcast_recording_worker.py:130` — Fix: implement `_upload_to_s3(local_path, bucket, key)` and call it after FFmpeg in `generate_mp4`
- **GAP-0123** [BCAST-011] Billing atomicity gap in `_write_private_billing()` — `_write_private_billing()` — Fix: use `TransactWriteItems` for atomic debit+credit; raise 500 on failure instead of silently swallowing
- **GAP-0124** [BCAST-011] `behavior="end"` not fully wired in accept handler — `behavior="end"` — Fix: call `stop_session_with_provider(session_id, actor, reason="go_private_end")` when `body.behavior == "end"`
- **GAP-0125** [BCAST-012] Private chat messages exposed in public chat history — `broadcast_chat_store.py:296` — Fix: add `FilterExpression=Attr("kind").ne("private_chat")` to `get_chat_history()` by default
- **GAP-0126** [BCAST-012] Billing atomicity gap in `_write_private_chat_billing()` — `_write_private_chat_billing()` — Fix: use `TransactWriteItems` for atomic debit+credit
- **GAP-0127** [BCAST-014] Self-entry check executes after fee charge — `broadcast_lottery.py:~420` — Fix: move `user_id == config["broadcaster_id"]` check before `_charge_entry_fee()`
- **GAP-0128** [BCAST-014] Entry fee billing atomicity gap — `broadcast_lottery.py:484` — Fix: use `TransactWriteItems` for atomic debit+credit (same pattern as BCAST-011/012)
- **GAP-0129** [BCAST-015] Billing atomicity gap in `_write_chat_billing()` — `_write_chat_billing()` — Fix: use `TransactWriteItems`; consolidate into shared `write_billing_pair()` utility in `app/services/billing_utils.py`
- **GAP-0130** [BCAST-015] `_find_sort_key()` is O(n) scan for reactions/unlocks — `_find_sort_key()` — Fix: add `MessageIdIndex` GSI to `BroadcastChatMessages` (pk=`message_id`) or accept `sort_key` from caller
- **GAP-0131** [BCAST-016] Expired invite not checked in `accept_guest_invite()` — `accept_guest_invite()` — Fix: add `if now_ts() > int(invite.expires_at): raise HTTPException(410, "Invite has expired")`

### BILLING

- **GAP-0132** [BILLING-001] Marketplace refund missing seller-side debit — `app/routers/billing.py:1164-1179` — Fix: write paired seller-DEBIT ledger entry via `new_ledger_entry()` when `reason` indicates tip/unlock

### BOT

- **GAP-0133** [BOT-001] No post-send trigger hook in `send_text_message()` — `send_text_message()` — Fix: spawn `asyncio.create_task(_run_bot_trigger_evaluation(...))` after the message write at line ~8053
- **GAP-0134** [BOT-001] Wildcard scope assignments never resolved in `get_bots_for_conversation()` — `get_bots_for_conversation()` — Fix: add a secondary lookup for wildcard-scoped bot assignments per creator
- **GAP-0135** [BOT-002] `_next_run_from_cron()` is a stub — `_next_run_from_cron()` — Fix: add `croniter` to `requirements.txt` and replace stub with real cron-next calculation
- **GAP-0136** [BOT-002] Wildcard target dispatch silently skips sends — `app/services/bot_scheduler.py:276` — Fix: implement `_resolve_target_conversations()` to fan out wildcard targets (cap at 500)
- **GAP-0137** [BOT-002] `start_bot_scheduler_task` may raise RuntimeError at startup — `start_bot_scheduler_task` — Fix: convert to `async def` and register with `@app.on_event("startup")`
- **GAP-0138** [BOT-003] Orphaned auto-reply rules on bot deletion — `app/services/chat_bot.py:167` — Fix: extend cascade to query and delete `SK begins_with RULE#` items in `T.chat_bots`
- **GAP-0139** [BOT-004] SSRF via creator-supplied `provider_url` — `provider_url` — Fix: validate URL against a private-IP blocklist in `configure_ai_bot()` mirroring `app/services/webhook_ssrf.py`
- **GAP-0140** [BOT-004] Prompt injection via user message role confusion — `app/services/bot_ai.py` — Fix: run `_check_forbidden_topics()` on both user message and LLM output before delivering response
- **GAP-0141** [BOT-004] API key ciphertext must never appear in API responses — `app/services/bot_ai.py` — Fix: `AiConfigOut` excludes `ai_api_key_encrypted`; service returns `api_key_masked = "..."+key[-3:]`

### CALL

- **GAP-0142** [CALL-007] Missing SSE fanout for `call.missed` — `call.missed` — Fix: add `fanout_event_to_conversation(...)` call after `timeout_call()` in both the endpoint and the backstop per §4.1
- **GAP-0143** [CALL-007] No callee-side local timer to auto-dismiss ringing overlay — `frontend/src/pages/messages/ConversationView.tsx` — Fix: add `useEffect` firing `REMOTE_DECLINE` at `ringing_timeout + 2000ms` on `incoming_ringing` phase per §4.2
- **GAP-0144** [CALL-008] No automatic `call.end` signal sent to remote peer on `failure` phase — `call.end` — Fix: add `useEffect` on `phase === "failure"` to call `callActionMutation.mutate({action:"end", callId, reason:"reconnect_failed"})` per §4.1
- **GAP-0145** [CALL-009] Missing timeline system message on recording completion — `app/routers/call_recording.py:322` — Fix: call `emit_call_timeline_event` with `event_type="call.recording_available"` after status update per §4.1
- **GAP-0146** [CALL-010] `RecordingsPanel.tsx` frontend component not implemented — `RecordingsPanel.tsx` — Fix: create `RecordingsPanel` component querying `GET /messages/recordings?conversation_id={id}` per §4.1
- **GAP-0147** [CALL-011] No billing props wired into `ConversationView.tsx` or `CallSessionOverlay.tsx` — `ConversationView.tsx` — Fix: wire hook in ConversationView and pass billing props to overlay per §4.2/4.3
- **GAP-0148** [CALL-011] No caller rate display before initiating call — `frontend/src/pages/messages/PaidCallRateBadge.tsx` — Fix: implement `PaidCallRateBadge` using `useQuery` on `GET /ui/calls/rates/{partner_user_id}` per §4.4
- **GAP-0149** [CALL-011] No creator rate settings UI — `frontend/src/pages/settings/CallRateSettings.tsx` — Fix: implement settings form at `/settings/call-rate` per §4.4
- **GAP-0150** [CALL-012] No pytest unit tests for group call service — `tests/test_group_calls.py` — Fix: create test file using moto + `monkeypatch` for `_get_conversation_participant_ids` per §4.3

### CREATOR

- **GAP-0151** [CREATOR-002] feature flag not enforced at router level — `app/routers/fan_club.py` — Fix: add _check_enabled() call in each handler matching collaborations.py:89 pattern
- **GAP-0152** [CREATOR-003] dashboard_sse_publish has no call sites — `app/services/dashboard_sse.py:39` — Fix: call dashboard_sse_publish from write_tip_ledger (earnings:update) and check_milestone (milestone:reached)
- **GAP-0153** [CREATOR-003] check_milestone has no call sites — `app/services/milestones.py:49` — Fix: call check_milestone from tip_ledger write, subscription signup, and analytics rollup completion
- **GAP-0154** [CREATOR-004] conversion attribution chain broken — `app/services/commerce_order_service.py:39` — Fix: extract afl_ref cookie in checkout endpoint and call record_conversion on order completion
- **GAP-0155** [CREATOR-004] afl_ref cookie set with Secure=True in dev — `app/routers/affiliate_links.py:~174` — Fix: set secure=not S.dev_mode when setting afl_ref cookie matching mock billing pattern

### DELEGATE

- **GAP-0156** [DELEGATE-001] /delegates route missing from App.tsx — `frontend/src/App.tsx:~346` — Fix: add <Route path="delegates" element={<DelegatesPage />} /> alongside delegation-api route
- **GAP-0157** [DELEGATE-004] banned viewer can still send chat messages — `app/services/broadcast_chat_store.py:158` — Fix: add _enforce_chat_ban(session_id, user_id) querying T.broadcast_moderation BAN# item before _enforce_chat_mute
- **GAP-0158** [DELEGATE-005] banned delegate bypasses account ban via API key path — `app/services/delegation_api.py:239` — Fix: add is_user_currently_banned(item["owner_sub"]) check after delegation relationship check at line 241

### DISC

- **GAP-0159** [DISC-001] background refresh job not registered — `app/main.py` — Fix: add refresh_all_users() function and register asyncio periodic loop via app.add_event_handler("startup", ...) at S.reco_refresh_interval_hours cadence
- **GAP-0160** [DISC-001] recordEngagement never called from frontend — `frontend/src/pages/videos/VideoPlayerPage.tsx` — Fix: call recordEngagement on video onEnded and at 30-second mark in VideoPlayerPage

### ENGAGE

- **GAP-0161** [ENGAGE-001] Admin advance-progress endpoint open to any authenticated user — `app/routers/achievements.py:278` — Fix: change `Depends(require_ui_session)` to `Depends(require_root_session)`
- **GAP-0162** [ENGAGE-001] Achievement progress hooks never wired into action handlers — `app/routers/newsfeed.py` — Fix: add try/except advance_progress calls at each listed integration point (see ticket section 3.7)
- **GAP-0163** [ENGAGE-002] Poll vote does not publish SSE events — `app/routers/newsfeed.py:6659` — Fix: after cast_vote, build a `poll:vote` payload and call `asyncio.get_event_loop().create_task(sse_hub.publish(post_owner_id, payload))` (or publish to all subscri
- **GAP-0164** [ENGAGE-002] Poll vote endpoint does not enforce post visibility/subscription gate — `app/routers/newsfeed.py:6659` — Fix: reuse the existing visibility/entitlement check from `_post_to_dict` or extract a shared `_check_post_access(post, user_id)` guard and call it before `cast_vote
- **GAP-0165** [ENGAGE-003] `display_name` always falls back to `user_sub` for question submitters — `display_name` — Fix: fetch the user's profile display name from the profiles/account service using `ctx["user_sub"]` before calling `submit_question`, or add `display_name` to the s
- **GAP-0166** [ENGAGE-004] Watch party SSE reuses broadcast session namespace — `app/routers/watch_party.py:266` — Fix: prefix party SSE keys with a watch-party namespace (`wp_sse:{party_id}`) or create a separate `_WATCH_PARTY_SUBSCRIBERS` dict in a dedicated `watch_party_sse.py
- **GAP-0167** [ENGAGE-004] `participant_count` can go negative and has no floor — `participant_count` — Fix: use `ConditionExpression="participant_count > :zero"` with `:zero=0` on decrement calls, or use `SET participant_count = :max(participant_count + :d, :zero)` vi
- **GAP-0168** [ENGAGE-005] `_count_user_clips_for_session` uses `FilterExpression` with `Select=COUNT` but no pagination — `_count_user_clips_for_session` — Fix: loop on `LastEvaluatedKey` to aggregate the full count across all pages
- **GAP-0169** [ENGAGE-005] `delete_clip` does not check admin/moderator role — `delete_clip` — Fix: pass `role` into `delete_clip` and add `or role in (Role.ADMIN, Role.ROOT)` to the authorization check

### ENTERPRISE

- **GAP-0170** [ENTERPRISE-001] `tenant_pk()` helper defined but never called — `tenant_pk()` — Fix: Systematically migrate service layer PK construction to use `tenant_pk()`; add a lint rule/grep CI check to block raw PK construction.
- **GAP-0171** [ENTERPRISE-001] `AuthenticatedUser` lacks `tenant_id` field — `AuthenticatedUser` — Fix: Add `tenant_id: str = "default"` to `AuthenticatedUser`, populate it from the JWT, validate it against `request.state.tenant_id` in `require_ui_session`.
- **GAP-0172** [ENTERPRISE-001] `TenantMiddleware` blocks root admin from accessing suspended tenants — `TenantMiddleware` — Fix: Check the `Authorization` header / cookie role before returning 503; bypass for authenticated ROOT sessions.
- **GAP-0173** [ENTERPRISE-002] SSO-only enforcement not wired into login endpoint — `app/routers/ui_session.py` — Fix: Call `is_sso_only_tenant(tenant_id)` at the top of `ui_session_start` and raise HTTP 403 when it returns True.
- **GAP-0174** [ENTERPRISE-002] `MockSamlAuth` used in production path — `MockSamlAuth` — Fix: Conditionally use the real `OneLogin_Saml2_Auth` when `not S.dev_mode`; restrict `MockSamlAuth` to `S.dev_mode` only.
- **GAP-0175** [ENTERPRISE-002] `relay_state` carries attacker-controlled form field not sanitised — `relay_state` — Fix: Limit RelayState to ≤2 KB, restrict to printable ASCII, and validate the URL before use.
- **GAP-0176** [ENTERPRISE-003] `_find_invite` does a full table scan — `_find_invite` — Fix: Add an `invite-id-index` GSI to the `organizations` table (PK: `invite_id`) in `scripts/local-ddb-init.py` and use `query()` in `_find_invite`.
- **GAP-0177** [ENTERPRISE-003] `list_user_orgs` GSI query returns raw membership items, not org metadata — `list_user_orgs` — Fix: Project `org_id`, `org_role` and `status` from the GSI; do a `batch_get_item` for the `#META` records.
- **GAP-0178** [ENTERPRISE-004] Background async export worker not implemented — `app/services/` — Fix: Create `app/services/audit_export_worker.py`, register its startup coroutine in `app/main.py`, and wire S3 upload in `process_export_job`.
- **GAP-0179** [ENTERPRISE-004] S3 upload path dead in current pipeline — `app/services/audit_export_pipeline.py:110-116` — Fix: Implement `process_export_job()` in the pipeline file (or the worker) with real S3 upload via `boto3`.
- **GAP-0180** [ENTERPRISE-005] Circuit breaker not integrated into dispatcher loop — `app/services/webhook_dispatcher.py:44-71` — Fix: Import `should_attempt_delivery` and `record_delivery_result` in `webhook_dispatcher.py` and call them around each delivery attempt (mirroring the dispatcher sn
- **GAP-0181** [ENTERPRISE-005] Per-delivery stats (`webhook_stats`) not recorded — `webhook_stats` — Fix: Call `record_delivery_stat(endpoint_id, result)` after `mark_delivery_success` and `handle_delivery_failure` in the dispatcher loop.

### FEED

- **GAP-0182** [FEED-004] gif_url accepts arbitrary URL schemes with no domain allowlist — `app/routers/newsfeed.py:1585` — Fix: validate gif_url is http/https and restrict to an allowlist of known GIF CDN domains (e.g. media.giphy.com, media.tenor.com)
- **GAP-0183** [FEED-004] sticker_url accepts arbitrary external URLs with no platform-only enforcement — `app/routers/newsfeed.py:1591` — Fix: validate sticker_url matches platform S3/CDN origin (e.g. begins with /mock/s3/ in dev, or configured CDN_BASE_URL)

### FILES

- **GAP-0184** [FILES-001] no IP-based rate limiting on public download endpoint — `app/routers/file_share_links.py:96` — Fix: add rate-limit middleware or a per-request in-memory / DDB counter keyed on `(link_id, client_ip)` for password attempts; apply general IP rate limit via existi
- **GAP-0185** [FILES-001] TOCTOU window between status check and atomic increment — `app/services/file_share_links.py:297-317` — Fix: fold the `is_revoked` and `expires_at` checks into the `ConditionExpression` (add `& Attr("is_revoked").ne(True) & Attr("expires_at").gt(now_ts())`

### FIN

- **GAP-0186** [FIN-002] `PromoValidateOut` missing FIN-002 extended fields — `PromoValidateOut` — Fix: extend `PromoValidateOut` with the new optional fields and populate them in `validate_promo_code`
- **GAP-0187** [FIN-002] `validate_promo_code` returns generic `message` strings with no machine-readable `error_code` — `validate_promo_code` — Fix: add `error_code` to each `fail` dict return: `not_found`, `deactivated`, `expired`, `usage_limit`, `already_used`, `min_order`, `product_mismatch`, `checkout_ty
- **GAP-0188** [FIN-002] `"tip"` and `"unlock"` checkout types not in `VALID_CHECKOUT_TYPES` — `"tip"` — Fix: add `"tip"` and `"unlock"` to `VALID_CHECKOUT_TYPES` and implement corresponding endpoint hooks in `app/routers/messaging.py` and `app/routers/newsfeed.py`
- **GAP-0189** [FIN-003] Multi-stage reminder schedule not implemented — `app/services/shoppingcart.py:781-846` — Fix: create `app/services/cart_reminders.py` with `process_abandoned_carts()` that reads from a `cart_reminder_config` DDB table and advances each cart through numbe
- **GAP-0190** [FIN-003] Cart recovery links not generated or included in reminder emails — `app/services/shoppingcart.py:824-835` — Fix: add `generate_recovery_link()` and `recover_cart()` in `cart_reminders.py`; add `GET /ui/shoppingcart/recover/{token}` public endpoint; embed the recovery URL i
- **GAP-0191** [FIN-003] No user opt-out preference for cart reminders — `app/routers/shoppingcart.py` — Fix: add opt-out storage in `cart_reminder_config` table (`OPTOUT/USER#{sub}` row), `is_user_opted_out()`, and preference endpoints
- **GAP-0192** [FIN-004] `/receipts/zip` bulk export endpoint not implemented — `/receipts/zip` — Fix: add `export_receipts_zip()` in the service and a `/receipts/zip` router endpoint using Python stdlib `zipfile` and S3 invoice fetches
- **GAP-0193** [FIN-008] No W-9/TIN collection endpoints or frontend form — `app/routers/tax_form_1099.py` — Fix: add W-9 submission router endpoints, `W9SubmissionIn`/`TaxInfoOut` models, `TaxInfoPage.tsx`
- **GAP-0194** [FIN-008] Admin TIN reveal endpoint missing — `app/routers/tax_form_1099.py` — Fix: add admin TIN reveal endpoint with `kms_decrypt` + `_write_tax_audit(action="tin_viewed", actor, target, ip)`
- **GAP-0195** [FIN-009] Payout methods CRUD not implemented — `app/services/creator_payouts.py` — Fix: add payout method service functions, router endpoints, `PayoutMethodIn`/Out models, and "Payout Methods" tab in dashboard
- **GAP-0196** [FIN-009] Admin queue tab absent from PayoutDashboard — `frontend/src/pages/payouts/PayoutDashboard.tsx` — Fix: add "Admin Queue" tab visible to role >= ADMIN, with approve/reject actions and reject-reason dialog
- **GAP-0197** [FIN-010] Affiliate summary, time-series, earnings, and top-products backend endpoints absent — `app/services/affiliate_links.py` — Fix: add four service functions + router endpoints + `AffiliateSummaryOut`/`AffiliateClickTimeSeriesOut`/`AffiliateEarningsBreakdownOut`/`AffiliateTopProductsOut` mo
- **GAP-0198** [FIN-010] AffiliateDashboard.tsx is still the 204-line stub — `frontend/src/pages/affiliates/AffiliateDashboard.tsx` — Fix: rewrite dashboard with tabs, add `getAffiliateSummary`/`getAffiliateEarnings`/`getLinkClickTimeSeries`/`getTopProducts` wrappers, add TypeScript types
- **GAP-0199** [FIN-011] No admin-global dispute arbitration endpoint — `GET /ui/admin/collaboration-disputes` — Fix: add `require_admin_session`-gated list-all-disputes and arbitrate endpoints using `cr.list_disputes(collaboration_id=None)` from `app/services/collaboration_rev
- **GAP-0200** [FIN-011] Content ownership not validated on assign — `app/services/collaboration_revenue.py:115` — Fix: add content-metadata ownership check before `put_item` (cross-ref SEC-004)
- **GAP-0201** [FIN-012] Platform benchmarks endpoint absent — `GET /ui/analytics/engagement/benchmarks` — Fix: implement `compute_platform_benchmarks(date_str)` in `engagement_rate.py` and add the router endpoint; add daily job call from main startup
- **GAP-0202** [FIN-013] Full billing table scan on every rollup — `app/services/platform_financial_dashboard.py:136` — Fix: add the `GSI_LEDGER_DATE` GSI to the `billing` table as specified in the ticket (`scripts/local-ddb-init.py:59`) and replace the scan with a GSI query keyed by 
- **GAP-0203** [FIN-013] `provider` field unreliable on ledger entries — `provider` — Fix: pass `provider` through `new_ledger_entry`'s `extra` dict at all call sites (Stripe, PayPal, CCBill paths) (cross-ref SEC-004)
- **GAP-0204** [FIN-014] `check_and_alert` never called — `check_and_alert` — Fix: wire a background task (e.g. every 5 min per provider) in `app/main.py` startup that calls `check_and_alert(provider)` for each of `["stripe", "paypal", "ccbill
- **GAP-0205** [FIN-014] `check_and_alert` returns alert details but never sends email or notification — `check_and_alert` — Fix: call the platform email or in-app notification service from `check_and_alert` (or from the background task caller) when `breaches` is non-empty
- **GAP-0206** [FIN-014] `toggle_provider` does not enforce payment initiation gate — `toggle_provider` — Fix: add `is_provider_enabled(provider)` guard at the start of each billing router's charge path (cross-ref SEC-004)
- **GAP-0207** [FIN-015] Billing router never calls fraud evaluation — `app/routers/billing.py` — Fix: 
- **GAP-0208** [FIN-015] Chargeback not auto-recorded from Stripe webhook — `app/routers/billing.py:687` — Fix: 
- **GAP-0209** [FIN-016] No PDF export format — `app/routers/audit_export.py:78` — Fix: 
- **GAP-0210** [FIN-016] No scheduled report system — `audit_export_pipeline.py` — Fix: 
- **GAP-0211** [FIN-016] No accounting-software column mapping — `audit_export.py` — Fix: 
- **GAP-0212** [FIN-017] No undo window — `app/services/bulk_payout_tools.py` — Fix: 
- **GAP-0213** [FIN-017] No CSV import endpoint — `app/routers/bulk_payout_tools.py` — Fix: 
- **GAP-0214** [FIN-018] Fee BPS settings are not wired to live billing fee calculations — `app/services/billing_config.py` — Fix: 
- **GAP-0215** [FIN-018] `call_billing_timer.py` reads platform fee from `S.call_billing_platform_fee_percent` (env var) — `call_billing_timer.py` — Fix: 

### GEO

- **GAP-0216** [GEO-001] Catalog item detail (`GET /ui/catalog/categories/{cat_id}/items` and item search) does not enforce `geo_mode`/`geo_countries` — `GET /ui/catalog/categories/{cat_id}/items` — Fix: 
- **GAP-0217** [GEO-001] Platform-level country block list is env-var only — `app/services/geo_check.py:53` — Fix: 

### GROUP

- **GAP-0218** [GROUP-003] `_AUTO_CONFIRM_DONATIONS = True` is a hardcoded module-level constant, not gated on `S.dev_mode` — `_AUTO_CONFIRM_DONATIONS = True` — Fix: change to `_AUTO_CONFIRM_DONATIONS = S.dev_mode` so prod requires Stripe webhook confirmation; implement a `POST /internal/fundraisers/{id}/donations/{id}/confi
- **GAP-0219** [GROUP-004] Two-phase treasury dissolution is not atomic — `app/services/group_treasury.py:487-635` — Fix: use DDB `TransactWriteItems` for batches of up to 25; for larger contributor counts use a saga pattern with a `dissolution_state` marker to enable idempotent re

### INFRA

- **GAP-0220** [INFRA-002] `stored_key` auth type NOT wired into SSH terminal — `stored_key` — Fix: add `"stored_key"` to the `authType` allowlist; in the connect handler, if `authType == "stored_key"` fetch `keyId` from payload, call `get_decrypted_private_ke
- **GAP-0221** [INFRA-002] No audit events emitted by SSH key manager service — `app/services/ssh_key_manager.py` — Fix: import `audit_event` from `app.services.alerts` and call it in `generate_key`, `upload_key`, `delete_key`, `get_decrypted_private_key`, `associate_key_with_host
- **GAP-0222** [INFRA-003] Real EC2 launch path raises `NotImplementedError` — `NotImplementedError` — Fix: implement `_real_ec2_launch()` using `boto3.client("ec2").run_instances(...)`, add EC2 client to `app/core/aws.py` following the existing `sns_client()` pattern
- **GAP-0223** [INFRA-003] Auto-registration in host inventory never happens — `app/services/ec2_launcher.py:196-202` — Fix: after storing the instance, call `host_inventory.create_host(user_sub, label=f"{label} (EC2)", hostname=result["public_ip"], port=22, protocol="ssh", source="ec
- **GAP-0224** [INFRA-003] Host inventory not cleaned up on instance termination — `app/services/ec2_launcher.py:320-357` — Fix: retrieve `item["host_id"]`, call `host_inventory.delete_host(user_sub, host_id)` inside `terminate_instance()`
- **GAP-0225** [INFRA-004] Real K8s launch path raises `NotImplementedError` — `NotImplementedError` — Fix: add `kubernetes` client to dependencies; implement `_real_k8s_launch()` using `kubernetes.client.CoreV1Api().create_namespaced_pod()`; implement real log fetch 
- **GAP-0226** [INFRA-004] Auto-registration in host inventory never happens — `app/services/k8s_launcher.py:196-197` — Fix: after storing the pod record, call `host_inventory.create_host(user_sub, label=f"{label} (K8s)", hostname=result["service_hostname"], port=22, protocol="ssh", s
- **GAP-0227** [INFRA-004] Host inventory not cleaned up on pod termination — `app/services/k8s_launcher.py:260-286` — Fix: call `host_inventory.delete_host(user_sub, item["host_id"])` inside `terminate_pod()` if `host_id` is non-empty
- **GAP-0228** [INFRA-005] Background billing timer not wired — `app/main.py:740-741` — Fix: register `asyncio.create_task(run_compute_billing_timer())` in the `startup` lifespan event and add `run_compute_billing_timer` to `app/services/compute_billing
- **GAP-0229** [INFRA-006] VNC password / SSH password not stored (SEC-022 surface) — `app/services/connection_profiles.py:50,171-252` — Fix: add optional `vnc_password` / `ssh_password` fields with KMS-encrypt on write (using `app/core/crypto.kms_encrypt`) and `has_password: bool` on read; never retu
- **GAP-0230** [INFRA-008] Auto-restart policy not implemented — `_check_restart_policy` — Fix: add `auto_restart_enabled` + `max_restarts` + `restart_count` fields to EC2/K8s instance items; implement `_check_restart_policy()`; add `PATCH /ui/compute/moni
- **GAP-0231** [INFRA-008] Event timeline not implemented — `TIMELINE#{instance_id}#{ts}#{event_id}` — Fix: implement `record_timeline_event()` service function; wire it into ec2/k8s launch, stop, terminate paths; add `GET /ui/compute/monitoring/instances/{id}/timelin
- **GAP-0232** [INFRA-009] Dangerous-rule block covers only SSH port 22; VNC (5900-5999), RDP (3389), and IPv6 (::/0) are not blocked — `app/services/security_groups.py:145-157` — Fix: extend `is_dangerous_rule` to also flag port ranges covering 3389, 5900-5999, and source `::/0`; or generalise to a configurable blocklist of (port-range, sourc
- **GAP-0233** [INFRA-010] SSH terminal does not hook into session recorder — `app/routers/browser_ssh_terminal.py:452-488` — Fix: in the WebSocket output handler call `append_events(user_sub, recording_id, [[elapsed, "o", data]])` for each received SSH output chunk; requires wiring `Sessio
- **GAP-0234** [INFRA-010] no per-host `record_sessions` flag (INFRA-001 dependency) — `record_sessions` — Fix: add `record_sessions: bool` to the host schema and call `start_recording()` automatically in the WebSocket `connect` handler when the flag is set
- **GAP-0235** [INFRA-011] `MultiHopSshBridge` class not implemented — `MultiHopSshBridge` — Fix: implement `MultiHopSshBridge` as designed in the ticket (section 3.3) and wire it into the WebSocket `connect` handler
- **GAP-0236** [INFRA-011] `resolve_connection_chain` function missing — `resolve_connection_chain` — Fix: add `resolve_connection_chain(user_sub, path_id)` that fetches each hop's SSH key via `ssh_key_manager.get_decrypted_private_key()` and returns a ready-to-conne
- **GAP-0237** [INFRA-012] `ByGlobalStatus` GSI never added to `ec2_instances` or `k8s_pods` — `ByGlobalStatus` — Fix: add `ByGlobalStatus` GSI with `partition_key="status"`, `sort_key="created_at"` to both tables in `local-ddb-init.py` and update `list_all_instances()` / `list_
- **GAP-0238** [INFRA-012] quota not enforced in `k8s_launcher.py` — `k8s_launcher.py` — Fix: add `enforce_k8s_quota(user_sub, preset)` call in `k8s_launcher.py` matching the pattern in `ec2_launcher.py`

### INTEG

- **GAP-0239** [INTEG-001] "Connect Google Drive" UI section absent from `FilesPage.tsx` — `FilesPage.tsx` — Fix: add the Google Drive integration section (connection badge, Connect/Disconnect/Browse buttons) to `FilesPage.tsx` as described in ticket section 4.6 and render 
- **GAP-0240** [INTEG-001] `GoogleDrivePickerDialog` not used anywhere in the frontend — `GoogleDrivePickerDialog` — Fix: import and render the dialog from `FilesPage.tsx` with `drivePickerOpen` state controlled by the Browse button
- **GAP-0241** [INTEG-001] OAuth state parameter not HMAC-signed — `app/routers/google_drive_integration.py:122-131` — Fix: implement `_sign_oauth_state(user_sub)` using `S.google_oauth_state_signing_secret` + timestamp, verify in `complete_google_drive_connect`, and reject stale sta
- **GAP-0242** [INTEG-001] real OAuth token exchange not implemented — `app/routers/google_drive_integration.py:155` — Fix: implement token exchange POST to `S.google_oauth_token_url` with code, redirect_uri, client_id, client_secret; store access_token, refresh_token, expires_at

### KYC

- **GAP-0243** [KYC-001] KycQueuePage missing — `frontend/src/pages/admin/KycQueuePage.tsx` — Fix: create page using `useQuery(["kyc","admin","queue",filters])` with cursor-based pagination and shadcn/ui filter bar
- **GAP-0244** [KYC-001] KycCaseDetailPage missing — `frontend/src/pages/admin/KycCaseDetailPage.tsx` — Fix: create two-column page with CaseInfoPanel, CaseActionPanel (all three dialogs), CaseTimeline
- **GAP-0245** [KYC-001] KycMetricsDashboard missing — `frontend/src/pages/admin/KycMetricsDashboard.tsx` — Fix: create page with FunnelChart, ApprovalRateCard, LatencyCards, StaleQueueAlert
- **GAP-0246** [KYC-001] DocumentViewer component missing — `frontend/src/components/shared/DocumentViewer.tsx` — Fix: create component with tab bar, zoom/rotation controls, VerificationStateBadge overlay, presigned-URL caching
- **GAP-0247** [KYC-002] ExtractionResultsPanel not integrated into admin case detail — `frontend/src/pages/admin/KycCaseDetailPage.tsx` — Fix: add "Document Extraction" tab with per-document ExtractionResultsPanel calling `GET /ui/kyc/documents/admin/by-status?case_id=`
- **GAP-0248** [KYC-002] No `case_id` filter on admin by-status endpoint — `case_id` — Fix: add optional `case_id: str | None = Query(default=None)` with client-side `FilterExpression` on GSI result
- **GAP-0249** [KYC-003] `expire_stale_calls` not wired as background task — `expire_stale_calls` — Fix: wire `expire_stale_calls` as a periodic asyncio task at startup, matching `start_kyc_sla_checker_task` pattern at `app/main.py:528`
- **GAP-0250** [KYC-003] VerificationCallPanel missing from admin case detail — `frontend/src/pages/admin/KycCaseDetailPage.tsx` — Fix: add collapsible `VerificationCallPanel` section with schedule/conduct/result states and a "Schedule Call" dialog
- **GAP-0251** [KYC-003] No `GET /admin/case/{case_id}` endpoint — `GET /admin/case/{case_id}` — Fix: add `GET /admin/case/{case_id}` backed by `STORE.get_call_for_case(case_id)` querying ByStatus GSI and filtering by `case_id`
- **GAP-0252** [KYC-004] Readiness gate not extended for enhanced/high_risk profiles — `app/routers/kyc_cases.py:244` — Fix: add residency check block using `RESIDENCY_STORE.get_verified_docs_for_case(case_id)` gated on `intake_profile in ("enhanced","high_risk")`
- **GAP-0253** [KYC-004] `get_verified_docs_for_case` helper missing — `get_verified_docs_for_case` — Fix: add `get_verified_docs_for_case(case_id)` querying the ByStatus GSI with `status=verified` and `FilterExpression: case_id`
- **GAP-0254** [KYC-004] ResidencyVerificationTab missing from admin case detail — `frontend/src/pages/admin/KycCaseDetailPage.tsx` — Fix: add "Residency" tab with two-column address comparison and per-field match badges
- **GAP-0255** [KYC-005] Submission expiry background task missing — `app/main.py` — Fix: add `expire_stale_submissions()` to the service and wire as a periodic asyncio task in `app/main.py` every 6 hours
- **GAP-0256** [KYC-005] Admin reviewer queue page missing — `frontend/src/pages/kyc/KycProofOfFundsReviewQueue.tsx` — Fix: create page with status filter, DataTable, and adjudicate dialog; add `admin/kyc/proof-of-funds` route
- **GAP-0257** [KYC-005] FinancialVerificationPanel missing from admin case detail — `frontend/src/pages/admin/KycCaseDetailPage.tsx` — Fix: add "Financial Verification" tab fetching `GET /ui/kyc/proof-of-funds/admin/submissions?user_sub=`
- **GAP-0258** [KYC-006] Submission hook wiring unverified — `app/routers/kyc_cases.py:830` — Fix: verify the hook exists; if absent, add `SCREENING_STORE.screen_case(case_id, user_sub, trigger="submission")` wrapped in try/except so screening failure does no
- **GAP-0259** [KYC-006] Profile-change re-screening not wired — `app/routers/settings.py` — Fix: add hook in profile update endpoint to call `SCREENING_STORE.rescreen_user()` when sensitive fields change
- **GAP-0260** [KYC-006] `attr_types={"created_at":"N"}` must be verified on `kyc_screening_results` table — `attr_types={"created_at":"N"}` — Fix: confirm `attr_types={"created_at": "N"}` is present in the `TableDef`; add if missing
- **GAP-0261** [KYC-007] `app/services/kyc_signature_templates.py` does not exist — `app/services/kyc_signature_templates.py` — Fix: create service with `KYC_TEMPLATE_TYPES` dict, `create_packets_for_case()`, `check_version_migration()`, and `auto_populate_fields()` calling `signature_packet_
- **GAP-0262** [KYC-007] Five template/witness router endpoints missing — `app/routers/kyc_cases.py` — Fix: add all five endpoints after creating the service
- **GAP-0263** [KYC-007] `notary_stamp` field type not valid — `notary_stamp` — Fix: extend valid field-type set in `signature_packet_store.py` to include `notary_stamp`; add S3-backed stamp image ref (moto in dev)
- **GAP-0264** [KYC-007] `case["signature"]` stores single packet; template packets require a list — `case["signature"]` — Fix: extend case META to store `signature.template_packets = [{template_type, packet_id, version}]` using `list_append`
- **GAP-0265** [KYC-008] Auto-escalate does not write escalation flag to case — `app/services/kyc_risk_scoring.py` — Fix: add DDB `update_item` writing `review.escalated`, `review.escalation_reason`, `review.escalated_at` in the critical-tier branch
- **GAP-0266** [KYC-008] Submission hook calling `compute_score()` unverified — `compute_score()` — Fix: verify hook exists; if absent, add `KycRiskScoringService().compute_score(...)` in try/except after KYC-006 screening call
- **GAP-0267** [KYC-009] `ByKycTier` GSI not declared in DDB init — `ByKycTier` — Fix: add the GSI and `attr_types` to the users `TableDef`
- **GAP-0268** [KYC-009] Feature gating not applied to endpoints — `require_kyc_tier` — Fix: apply `Depends(require_kyc_tier(N))` to each endpoint in priority order per Phase 2–4 rollout plan
- **GAP-0269** [KYC-009] Auto-upgrade triggers not wired — `app/routers/register.py` — Fix: add `auto_evaluate_tier(user_sub)` in try/except at each of the three trigger points
- **GAP-0270** [KYC-010] Profile field name misalignment causes zero match score — `app/services/kyc_id_scanner.py` — Fix: add fallback to split `display_name` when `first_name`/`last_name` are absent
- **GAP-0271** [KYC-010] Default passport mock MRZ is expired — `app/services/kyc_id_scanner.py` — Fix: update `_MOCK_MRZ` passport expiry to a future date (e.g., `361231` → 2036-12-31) with recomputed check digits; or document required `mrz_lines` test fixture
- **GAP-0272** [KYC-011] `kyc.case.approved` and `kyc.case.rejected` events never dispatched — `kyc.case.approved` — Fix: add `_emit_kyc_event_safe(event="kyc.case.approved", user_sub=..., case_id=...)` / `kyc.case.rejected` at the end of `apply_admin_decision()` after a successful
- **GAP-0273** [KYC-011] `kyc.case.needs_info` event never dispatched — `kyc.case.needs_info` — Fix: add `_emit_kyc_event_safe(event="kyc.case.needs_info", user_sub=case["user_sub"], case_id=case_id, requested_items=..., note=...)` after the successful DDB upda
- **GAP-0274** [KYC-011] `kyc.case.created` event not dispatched from the router — `kyc.case.created` — Fix: add `_emit_kyc_event_safe(event="kyc.case.created", ...)` in `create_kyc_case()` in the router or in `STORE.create_case()` in the service
- **GAP-0275** [KYC-014] Production comparison raises `KycFacialComparisonError("comparison_service_error")` unconditionally — `KycFacialComparisonError("comparison_service_error")` — Fix: implement `_production_compare()` to call `boto3.client("rekognition").compare_faces()` with the S3 object references, or gate with a feature flag that routes t
- **GAP-0276** [KYC-016] Background review-checker and re-screening loops are never started — `app/main.py` — Fix: create `app/services/kyc_monitoring_scheduler.py` with `_kyc_review_checker_loop` / `_kyc_rescreening_loop` asyncio tasks and register via `app.add_event_handle
- **GAP-0277** [KYC-016] Profile country/name change and large billing transactions never create trigger events — `app/routers/profile.py` — Fix: add `create_trigger_event(user_sub, "country_change", ...)` in the profile update handler and `create_trigger_event(user_sub, "large_transaction", ...)` in the 
- **GAP-0278** [KYC-017] `list_templates` uses a full-table Scan instead of the `status-updated-index` GSI — `list_templates` — Fix: replace the `scan()` loop in `list_templates` with a `query()` on `status-updated-index` when `status` is supplied, and a parallel query over all statuses other
- **GAP-0279** [KYC-017] `_readiness_for_case` in `app/routers/kyc_cases.py` (line 244) does not include template-signing completeness check — `_readiness_for_case` — Fix: add a `KYC_TEMPLATE_READINESS_GATE`-gated call to `SERVICE.get_required_templates_for_tier(target_tier)` in `_readiness_for_case` and append any missing slugs t
- **GAP-0280** [KYC-018] Address-change detection hook is NOT wired into `app/services/profile.py` — `app/services/profile.py` — Fix: in `profile.py`'s `update_profile` function, after a successful DDB write, check if `address_line_1`, `city`, `state`, `postal_code`, or `country` changed and c
- **GAP-0281** [KYC-018] `_readiness_for_case` in `app/routers/kyc_cases.py` (line 244) does not gate tier_2/tier_3 cases on address verification status — `_readiness_for_case` — Fix: add a `KYC_ADDRESS_VERIFICATION_ENABLED`-gated check inside `_readiness_for_case` that queries `STORE.get_latest(case_id)` and appends `"address_not_verified"` 
- **GAP-0282** [KYC-019] `_scan_availability_items` uses a full-table Scan with a `begins_with` filter on PK — `_scan_availability_items` — Fix: move admin availability records to a GSI-friendly PK/SK layout (e.g., query `entity_type = "kyc_admin_availability"`) or add a dedicated `admin_availability` ta
- **GAP-0283** [KYC-019] `_active_case_counts` calls `_scan_active_cases` which runs three separate GSI queries (one per status) and returns all active cases to count assignments in Python — `_active_case_counts` — Fix: add an `assigned_admin_sub` GSI to `kyc_cases` and count per-admin via direct GSI queries instead of loading all active cases into memory
- **GAP-0284** [KYC-020] `_bulk_fetch` fetches translations one-by-one with individual `GetItem` calls instead of using DynamoDB `BatchGetItem` — `_bulk_fetch` — Fix: replace the loop in `_bulk_fetch` with DDB `batch_get_item` (chunked in batches of 100), then fall back to individual `GetItem` only for cache-missed items
- **GAP-0285** [KYC-020] KYC questionnaire endpoint `start_kyc_questionnaire` (line 625) and email notifications do NOT call `kyc_translation_service.localize_questionnaire()` / `localize_email()` — `start_kyc_questionnaire` — Fix: add `lang: str = Query(default=None)` to `start_kyc_questionnaire`, resolve locale via `kyc_translation_service.resolve_locale_for_user()`, and call `localize_q
- **GAP-0286** [KYC-021] Per-API-key rate limiting is completely absent from all partner API endpoints — `app/routers/kyc_partner_api.py` — Fix: add `rate_limit_or_429(user_sub=f"apikey:{api_key_id}", factor="kyc_api:applications")` etc. at the top of each endpoint handler
- **GAP-0287** [KYC-021] Document file bytes are read from the multipart upload but never stored in S3 — `app/routers/kyc_partner_api.py:196-204` — Fix: upload `contents` to S3 under `kyc-api-docs/{partner_id}/{application_id}/{document_id}` and pass the resulting S3 key to `upload_document()`; store the key on 
- **GAP-0288** [KYC-023] `KycPiiSection` component is never used in any page — `KycPiiSection` — Fix: import `KycPiiSection` into `KycCaseDetailPage.tsx` and render it in the case detail body with `caseId`, `isAssigned`, and `isRoot` props

### LCOM

- **GAP-0289** [LCOM-002] `ProductLinkCard.tsx` component does not exist — `ProductLinkCard.tsx` — Fix: create `ProductLinkCard.tsx` (per ticket spec §3.5) and add `kind === "product_link"` branch in `BroadcastChat.tsx` render loop
- **GAP-0290** [LCOM-002] `ShelfProductPicker.tsx` dialog does not exist — `ShelfProductPicker.tsx` — Fix: create `ShelfProductPicker.tsx` (per ticket spec §3.7) and wire "Share Product" button in `BroadcastChat.tsx`
- **GAP-0291** [LCOM-004] `ShelfItem` TypeScript interface missing broadcast pricing fields — `ShelfItem` — Fix: extend `ShelfItem` with optional pricing fields and add `setBroadcastPrice`/`clearBroadcastPrice` API functions
- **GAP-0292** [LCOM-004] `BroadcastPrice.tsx` component does not exist — `BroadcastPrice.tsx` — Fix: create `BroadcastPrice.tsx` per ticket spec §3.8 and integrate into `ProductShelf.tsx` `ProductShelfCard`
- **GAP-0293** [LCOM-004] `BroadcastPriceEditor.tsx` component does not exist — `BroadcastPriceEditor.tsx` — Fix: create `BroadcastPriceEditor.tsx` per ticket spec §3.9 and add it to each shelf item row in `ProductShelfManager.tsx`

### LICENSE

- **GAP-0294** [LICENSE-002] No content ownership enforcement on issue_license — `app/services/issued_licenses.py:25` — Fix: add `_validate_content_ownership(licensor_sub, content_id, content_type)` against the relevant content table before writing any license record
- **GAP-0295** [LICENSE-003] `/ui/licenses/revenue/register-license` endpoint allows spoofing `licensor_id` — `/ui/licenses/revenue/register-license` — Fix: remove `licensor_id` from the request body; always use `ctx["user_sub"]` as the licensor, or restrict this endpoint to admin/internal use only
- **GAP-0296** [LICENSE-003] `/ui/licenses/revenue/process-split` endpoint allows any user to trigger arbitrary splits — `/ui/licenses/revenue/process-split` — Fix: gate behind `require_admin_or_root` or `S.dev_mode` flag; remove from production router
- **GAP-0297** [LICENSE-005] `syndicate_content` table described in ticket is renamed `syndicate_open_licensing` in implementation, with only GSI1 (not the ticket-specified single GSI) — `syndicate_content` — Fix: naming divergence is acceptable if consistent; verify the `CREATOR_SYND#` pattern used by `list_syndicate_content` with `creator_id` filter is implemented
- **GAP-0298** [LICENSE-006] `GET /ui/licenses/compliance/content/{content_id}` blocks admin access — `GET /ui/licenses/compliance/content/{content_id}` — Fix: add a role check

### MEDIA

- **GAP-0299** [MEDIA-001] DRM support reduced to AES-128 flag only — `frontend/src/components/shared/MediaPlayer.tsx:79,321-323` — Fix: add `DrmConfig` interface with `licenseUrl`/`token`/`fairplayCertificateUrl`; set `drmSystems` on Hls config and add `licenseXhrSetup` callback; add Safari nati
- **GAP-0300** [MEDIA-001] token refresh callback absent — `frontend/src/components/shared/MediaPlayer.tsx:1` — Fix: add `onTokenExpiring?: () => Promise<string>` prop; schedule refresh 30s before JWT `exp` claim; update `hls.config.xhrSetup` with new token
- **GAP-0301** [MEDIA-002] `/internal/dev-tools/ffmpeg-health` endpoint absent — `/internal/dev-tools/ffmpeg-health` — Fix: add `GET /internal/dev-tools/ffmpeg-health` to `internal_devtools.py` calling `validate_ffmpeg()` from `ffmpeg_manager`

### MOD

- **GAP-0302** [MOD-001] `thumbnail_url` / `hls_manifest_url` not populated in dev — `thumbnail_url` — Fix: in dev mode, synthesize a mock `hls_manifest_url` from S3 mock path (same pattern used in `_message_out_from_item` for file messages)
- **GAP-0303** [MOD-002] SEC-012 cross-ref: content_url not validated against SSRF or internal network targets — `app/services/dmca_content_operations.py:35-62` — Fix: reject non-relative URLs or validate against platform hostname allowlist in `DmcaClaimIn._validate_content_url`; the existing `javascript:`/`data:` check in the
- **GAP-0304** [MOD-002] claimant rate-limit not enforced — `app/services/dmca_claims.py:443` — Fix: query `ByClaimantCreatedAt` before inserting; reject with 429 if claimant has N claims in the last 24h (configurable)
- **GAP-0305** [MOD-003] frontend entirely absent — `frontend/src/` — Fix: create the four files listed in section 4.6-4.7 and add routes per section 4.8
- **GAP-0306** [MOD-003] `enforcement_id` absent from warning and ban alert details — `enforcement_id` — Fix: pass `enforcement_id` kwarg through `_persist_enforcement_if_needed()` in `admin_moderation.py:482` to both notification functions per section 3.3

### MON

- **GAP-0307** [MON-003] Subscription revenue is invisible to the creator earnings dashboard — `PK=CREATOR#{creator_id}` — Fix: update `record_billing_payment` / `save_ledger_entry` to also write a `type=credit` LEDGER entry under `PK=USER#{creator_id}` in `T.billing`; or update `_query_
- **GAP-0308** [MON-004] Payout balance calculation (`get_available_balance`) does not exclude `state=reversed` credit entries — `get_available_balance` — Fix: add `Attr("state").ne("reversed")` to the FilterExpression on the billing query; also exclude `amount_cents=0` subscription-access entitlement records
- **GAP-0309** [MON-004] `request_payout` performs balance check then write as two separate non-atomic operations without any conditional write — `request_payout` — Fix: use a DDB conditional write with `ConditionExpression="attribute_not_exists(payout_id)"` on the payout record and a version counter on the user's payout state r

### MSG

- **GAP-0310** [MSG-001] no time-window enforcement on edit — `app/routers/messaging.py:11003` — Fix: add `if now_ts() - int(msg.get("created_at",0)) > S.message_edit_window_seconds: raise HTTPException(400, ...)` and add `message_edit_window_seconds: int` to `a
- **GAP-0311** [MSG-001] platform-level admin/root cannot delete any message — `app/routers/messaging.py:10762,10801` — Fix: check `ctx["role"] in {Role.ADMIN, Role.ROOT}` in `revoke_message_for_all` (or add a separate moderation endpoint) to allow platform admins to remove harmful co
- **GAP-0312** [MSG-002] presign endpoint does not validate that `s3_key` submitted to create endpoint matches the presigned key — `s3_key` — Fix: store the presigned `(message_id → s3_key)` mapping in DDB or a short-TTL cache and verify it matches in `create_voice_message`
- **GAP-0313** [MSG-004] `_presence_event_cache` is an in-process dict that will not persist across worker restarts or scale to multiple processes — `_presence_event_cache` — Fix: store cooldown timestamps in DynamoDB (TTL-based) or Redis rather than in-process dict
- **GAP-0314** [MSG-005] `message:viewed` SSE handler uses `invalidateQueries` (triggers a full refetch) instead of `setQueriesData` for the messages cache — `message:viewed` — Fix: replace `queryClient.invalidateQueries({ queryKey: ["messages", conversationId] })` with `queryClient.setQueriesData(...)` that surgically increments `read_by_c
- **GAP-0315** [MSG-007] sticker upload in `sticker_collections.py` validates MIME only from declared `content_type` header, not magic bytes — `sticker_collections.py` — Fix: add a `_detect_content_type(data)` helper to `sticker_collections.py` (mirrors `custom_emojis.py:72`) and reject if sniffed MIME doesn't match declared or allow
- **GAP-0316** [MSG-008] GIF `gif_url` is accepted without domain allowlist validation — `gif_url` — Fix: add `gif_allowed_domains: list[str]` setting (default `[""]` to allow `/mock/*` in dev); validate `urllib.parse.urlparse(inp.gif_url).netloc` against the list i

### NOTIFY

- **GAP-0317** [NOTIFY-001] No dedicated VAPID web-push subscribe/unsubscribe endpoint — `app/routers/push.py:32-48` — Fix: add `POST /ui/push/subscribe` and `DELETE /ui/push/subscribe` endpoints that accept and store proper web-push subscription objects; update `send_push_for_alert`

### PLATFORM

- **GAP-0318** [PLATFORM-001] IP spoofing via untrusted X-Forwarded-For header — `app/core/normalize.py:9` — Fix: only honour XFF when `request.client.host` falls within configured `TRUSTED_PROXY_CIDRS`; default to empty (direct IP only) in dev
- **GAP-0319** [PLATFORM-002] SNS notification endpoint unauthenticated and reachable without network restriction — `app/routers/ses_notifications.py` — Fix: restrict endpoint to VPC-only traffic via security group; document required network controls in ops runbook
- **GAP-0320** [PLATFORM-003] Frontend i18n packages not installed; no t() calls exist — `frontend/package.json` — Fix: install packages; create `frontend/src/i18n/config.ts`; wrap App in `I18nextProvider`; migrate component strings to `t()` calls
- **GAP-0321** [PLATFORM-003] `locale` field absent from user profile model — `locale` — Fix: add `locale: Optional[str]` to profile, validated against `I18N_SUPPORTED_LOCALES` before storage
- **GAP-0322** [PLATFORM-005] Backend meta endpoint not yet created — `app/routers/meta.py` — Fix: create `app/routers/meta.py` with `GET /api/meta?url=...`; register in `main.py`; implement `_profile_meta`, `_event_meta`, `_post_meta`, `_video_meta` helpers
- **GAP-0323** [PLATFORM-005] Crawler-detection middleware not implemented — `frontend/vite.config.ts` — Fix: implement crawler UA detection + meta injection in production proxy and as a Vite plugin for dev
- **GAP-0324** [PLATFORM-006] send_alert_email() still uses silent bare except — `app/services/alerts.py:458` — Fix: replace with logged version that calls `logger.exception()`, increments `EMAIL_FAILED`, calls `record_email_failure()`, and returns None explicitly
- **GAP-0325** [PLATFORM-006] Double silent-failure envelope around email fanout — `app/services/alerts.py:670` — Fix: remove the outer `except Exception: pass` from the email fanout section; let exceptions surface to the caller
- **GAP-0326** [PLATFORM-007] No toll-fraud global spending cap (SEC-014) — `app/services/sms_delivery.py` — Fix: add `sms_daily_cost_cap_usd` setting; in `send_sms()` at `sms_delivery.py:174`, check cumulative daily segment count * cost-per-segment before publishing and re
- **GAP-0327** [PLATFORM-009] No rate limiting on `GET /ui/export/csv` (SEC-007 cross-ref) — `GET /ui/export/csv` — Fix: add a call to `_check_rate_limit(user_sub, "csv_export", max_n=5, window=60)` (or reuse the existing `rate_limit.py` bucket pattern) at the top of `export_csv()
- **GAP-0328** [PLATFORM-010] Auto-revoke fires on any delivery failure, not only definitive 410/404 — `app/services/push.py:300-310` — Fix: have `web_push_send()` return a 3-value enum or raise a distinct `StaleSubscriptionError` on 410/404 so the caller can distinguish permanent from transient fail
- **GAP-0329** [PLATFORM-011] `_search_messages` authorization check loads only first 500 conversations — `_search_messages` — Fix: paginate `list_user_conversations` until exhausted (or use a participant-indexed GSI query) to build the complete `allowed_conv_ids` set before filtering
- **GAP-0330** [PLATFORM-016] Auto-revoke fires on ALL web_push_send failures, not only 410 Gone — `app/services/push.py:300-312` — Fix: have `web_push_send` return a typed result distinguishing `(True, None)` / `(False, "410")` / `(False, "other")`; only revoke on `"410"`
- **GAP-0331** [PLATFORM-018] `finalize_deletion` does not anonymize messages or posts — `finalize_deletion` — Fix: add `_anonymize_messages(user_sub)` and `_anonymize_posts(user_sub)` steps in `finalize_deletion` that overwrite `sender_display_name`/`text` and `author_id`/`c
- **GAP-0332** [PLATFORM-018] `finalize_deletion` does not cancel active subscriptions before deletion — `finalize_deletion` — Fix: add a `_cancel_active_subscriptions(user_sub)` step in `finalize_deletion` before DDB delete that calls the subscription cancellation service
- **GAP-0333** [PLATFORM-019] Analytics events table not created — `scripts/local-ddb-init.py` — Fix: add `TableDef("analytics_events", "pk", "sk", gsis=[{"name":"GSI1","pk":"GSI1PK","sk":"GSI1SK"}], ttl_field="ttl_epoch")` in local-ddb-init.py
- **GAP-0334** [PLATFORM-019] `analytics_events.py` service not implemented — `analytics_events.py` — Fix: create `app/services/analytics_events.py` with the four recording functions writing to `T.analytics_events`
- **GAP-0335** [PLATFORM-019] `analytics_rollup_engine.py` not implemented — `analytics_rollup_engine.py` — Fix: create `app/services/analytics_rollup_engine.py` and register `run_rollup_loop` as a startup background task in `app/main.py`
- **GAP-0336** [PLATFORM-019] Refresh endpoint is still a no-op placeholder — `app/routers/creator_analytics.py:324` — Fix: import and call `compute_daily_rollups(today, yesterday)` from the new rollup engine before returning
- **GAP-0337** [PLATFORM-019] Zero event instrumentation in any router — `app/routers/newsfeed.py` — Fix: add `record_*()` calls at each instrumentation point listed in ticket §5.3

### PRIVACY

- **GAP-0338** [PRIVACY-001] Export runs synchronously inline (no background worker) — `app/routers/privacy.py:71-73` — Fix: queue the export as a background `asyncio` task or use an `add_event_handler("startup", …)` loop; return 201 immediately and let the worker update status
- **GAP-0339** [PRIVACY-001] `process_deletion()` in `gdpr_service.py` does not delete Messages, Conversations, or Participants — `process_deletion()` — Fix: add deletion steps for Messages/Conversations (DM handling) and Participants tables mirroring the ticket §7 design
- **GAP-0340** [PRIVACY-001] S3 files not deleted during account deletion — `app/services/gdpr_service.py:672-827` — Fix: add S3 `delete_objects` batch call and file-manager DDB cleanup step to `process_deletion()`
- **GAP-0341** [PRIVACY-001] Cognito user is not disabled/deleted on account deletion — `app/services/gdpr_service.py:672-827` — Fix: call `cognito_client.admin_disable_user` then `admin_delete_user` guarded by `_cognito_available()` check, matching the pattern in `app/core/aws.py`

### PROMO

- **GAP-0342** [PROMO-001] Promo codes not integrated into subscription checkout — `app/routers/subscription_server.py` — Fix: add optional `promo_code: str | None` to `SubscribeIn` and call `promo_codes.validate_promo_code` + `redeem_promo_code` inside the subscribe handler, re-using t
- **GAP-0343** [PROMO-001] Promo codes not integrated into shop checkout — `app/routers/catalog.py` — Fix: either build a catalog checkout endpoint (larger effort) or gate `applies_to: ["shop"]` behind a future-ticket flag

### PWA

- **GAP-0344** [PWA-004] No message idempotency — `app/routers/messaging.py` — Fix: add optional `client_request_id` to `SendTextMessageReq` and backend create-message handler; use the offline action `id` as the key

### ROOTCTL

- **GAP-0345** [ROOTCTL-001] `rotate-secrets` is still a placeholder — `rotate-secrets` — Fix: implement real key rotation (re-generate `UI_ACCESS_TOKEN_SECRET`, `API_KEY_PEPPER`, KMS break-glass key) with audit trail
- **GAP-0346** [ROOTCTL-001] No `user reactivate` or `user undelete` commands — `user reactivate` — Fix: add `reactivate` and `undelete` sub-parsers mirroring `deactivate`/`delete` guard patterns (`--ticket`, `--confirm`)

### SHOP

- **GAP-0347** [SHOP-001] Low-stock alert has no throttle/dedup — `app/routers/catalog.py:611-634` — Fix: add a sentinel check (DDB `put_item` with `ConditionExpression=attribute_not_exists` + TTL) before calling `write_alert`
- **GAP-0348** [SHOP-001] `adjust_stock` uses a full-table scan to find item by `item_id` — `adjust_stock` — Fix: change route to `PATCH /ui/catalog/categories/{category_id}/items/{item_id}/stock` to accept the PK directly, or add a `ByItemId` GSI on the catalog table
- **GAP-0349** [SHOP-002] `add_catalog_item` does not store `creator_user_id` on the cart item record — `add_catalog_item` — Fix: add `"creator_user_id": item.get("creator_id")` to the payload dict in `add_catalog_item`
- **GAP-0350** [SHOP-004] UPS webhook has no timestamp-tolerance or replay-protection check — `app/routers/ups.py:91` — Fix: store processed event IDs in DDB and reject duplicates; add X-UPS-Timestamp window check

### SIGN

- **GAP-0351** [SIGN-001] No visual PDF viewer — `frontend/src/pages/files/SignaturePacketComposer.tsx:609-629` — Fix: install react-pdf, render source PDF pages, overlay field boxes per ticket §1b
- **GAP-0352** [SIGN-001] No signature drawing canvas — `SignaturePacketComposer.tsx:565` — Fix: add an HTML5 canvas component for freehand drawing per ticket §1c

### SOC

- **GAP-0353** [SOC-003] Discovery index not populated on profile update — `app/services/profile.py:apply_profile_update()` — Fix: add `index_user_for_discovery(user_sub)` (non-fatal try/except) at end of `apply_profile_update()` per ticket §4.6
- **GAP-0354** [SOC-003] `POST /ui/discover/reindex` is self-only — `POST /ui/discover/reindex` — Fix: add an admin/root-gated `POST /ui/discover/admin/reindex-all` endpoint backed by `reindex_all_users()`
- **GAP-0355** [SOC-004] `emit_social_alert()` never called from social event triggers — `emit_social_alert()` — Fix: add `emit_social_alert()` calls after each event: reaction handler (post_reaction/post_liked), comment handler (post_comment/comment_reply), tip_post handler (p
- **GAP-0356** [SOC-004] `emit_mention_alerts()` never called from post/comment creation — `emit_mention_alerts()` — Fix: call `emit_mention_alerts(text=body, author_user_id=user_id, ...)` at end of create_post and create_comment handlers

### SOCIAL

- **GAP-0357** [SOCIAL-001] Overlap with FEED-009 (post bookmarks): same feature, separate tickets — `docs/tickets/gaps/FEED-009.md` — Fix: 
- **GAP-0358** [SOCIAL-002] No `post_shared` notification emitted to original author on repost — `post_shared` — Fix: add `put_notification(recipient_user_id=author_id, notif_type="post_shared", payload={"post_id": post_id, "repost_id": repost_id, "from_user_id": user_id})` aft
- **GAP-0359** [SOCIAL-003] No rate limiting on `GET /ui/search` — `GET /ui/search` — Fix: add `check_rate_limit(user_id, "global_search", max=30, window=60)` at the top of the aggregator endpoint
- **GAP-0360** [SOCIAL-004] Block/Unblock UI is absent from `PublicUserProfilePage` — `PublicUserProfilePage` — Fix: create `BlockButton.tsx` shared component; import `getBlockStatus`/`blockUser`/`unblockUser` in `PublicUserProfilePage`; add a "Block" option in a `DropdownMenu

### SYND

- **GAP-0361** [SYND-001] list_pending_requests exposes join requests to any authenticated user — `app/routers/syndicates.py:267-280` — Fix: add `svc._require_admin(syndicate_id, session["user_sub"])` before service call in the `list_requests` router handler
- **GAP-0362** [SYND-003] execute_split uses Python `assert` for financial integrity invariant — `assert` — Fix: replace both `assert` statements with `if ... raise HTTPException(500, ...)` or `raise RuntimeError(...)` that will always execute regardless of optimization fl
- **GAP-0363** [SYND-003] execute_split writes ledger credit entries for each member but never calls `apply_wallet_delta` — `apply_wallet_delta` — Fix: add `apply_wallet_delta(T.billing, f"USER#{dist['user_id']}", dist["amount_cents"])` for each distribution entry
- **GAP-0364** [SYND-004] leave_syndicate does NOT trigger treasury refund-on-leave — `app/services/syndicates.py:393-426` — Fix: import `syndicate_treasury.refund_on_member_leave` (and `refund_on_dissolution`) and call them inside `leave_syndicate` before `_remove_member`, mirroring the d

### UX

- **GAP-0365** [UX-002] Ctrl+Enter send not wired in ComposeBar — `frontend/src/pages/messages/ComposeBar.tsx:690-694` — Fix: add `if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); void handleSubmit(); }` to `handleKeyDown` in `ComposeBar.tsx:694`

### VOD

- **GAP-0366** [VOD-001] "queued" status bug silently swallowed — `app/routers/transcode_jobs.py:103` — Fix: change `to_status="queued"` to `to_status="pending_encoding"`
- **GAP-0367** [VOD-002] Title length mismatch causes unhandled 500 — `app/routers/vod.py:72` — Fix: change `max_length=500` to `max_length=256` in `VideoUploadPresignIn.title`
- **GAP-0368** [VOD-003] "queued" status transition silently fails on job submission — `app/routers/transcode_jobs.py:103` — Fix: change `to_status="queued"` to `to_status="pending_encoding"`
- **GAP-0369** [VOD-003] Worker completes job then tries illegal "published" transition — `app/services/transcode_worker.py:202` — Fix: change to `to_status="pending_review"` and add explicit "encoding" transition after claim
- **GAP-0370** [VOD-008] No client-side forensic watermark overlay — `frontend/src/pages/videos/VideoPlayerPage.tsx:479-504` — Fix: Add `<WatermarkOverlay sessionId={video.playback_token?.slice(0,12)} tenantId={video.owner_user_id} />` absolutely positioned over the player container
- **GAP-0371** [VOD-008] No automatic playback token refresh — `frontend/src/pages/videos/VideoPlayerPage.tsx:375-378` — Fix: Add `usePlaybackEntitlement` hook with `refetchInterval: 90_000` to rotate the token before expiry and update the `playbackUrl` ref without tearing down the HLS
- **GAP-0372** [VOD-010] tenant_id absent from HKDF key derivation — `app/services/vod_drm_keys.py:57-78` — Fix: include tenant_id in HKDF salt or info string (salt = sha256(f"{tenant_id}|{asset_id}")) and require tenant_id query param in GET /v1/vod/drm/key/{key_id} valid
- **GAP-0373** [VOD-010] tenant_id not validated at key serve time — `app/routers/vod_drm.py:67-71` — Fix: extract and compare token tenant_id against a required tenant_id query parameter (matches spec §6.1)
- **GAP-0374** [VOD-010] admin key revocation endpoints missing — `app/routers/vod_drm.py` — Fix: add admin endpoints with require_admin_session dependency; write to a ContentKeys DynamoDB table revocation record
- **GAP-0375** [VOD-012] download rate limiting not enforced — `app/routers/video_listing.py:772-824` — Fix: add a Redis/DynamoDB rate-limit check keyed by user_sub+video_id before minting the presigned URL; return 429 if limit exceeded
- **GAP-0376** [VOD-014] frontend UI for VOD bridge entirely absent — `frontend/src/pages/files/FileTable.tsx` — Fix: add FileEntry.vod_* fields to types.ts, add bridge API functions, add VOD context menu items to FileTable.tsx, and add "In Files" badge to video cards
- **GAP-0377** [VOD-015] Clip job exception never calls fail_job — `app/services/video_clipper.py:305` — Fix: catch exception, call `fail_job(job_id, str(e), attempt)` before re-raise
- **GAP-0378** [VOD-016] `concat -safe 0` allows arbitrary file:// entries in filelist.txt — `concat -safe 0` — Fix: use `-safe 1` and validate every entry is inside the owned scratch_dir before writing it to filelist.txt (i.e., assert `p.is_relative_to(scratch_dir)` per SEC-0
- **GAP-0379** [VOD-016] Concat job exception never calls fail_job — `app/services/video_concatenator.py:308` — Fix: catch exception, call `fail_job(job_id, str(e), attempt)` before re-raise
- **GAP-0380** [VOD-017] Comments are stored in the VideoViews table using a `VCOMMENT#` prefix instead of the newsfeed `app_single_table` — `VCOMMENT#` — Fix: store comments in a dedicated table or in `app_single_table` with the `POST#{video_id}` shadow-record pattern described in the ticket
- **GAP-0381** [VOD-018] `static/ads/` directory and placeholder creative files do not exist — `static/ads/` — Fix: create `app/static/ads/` and add placeholder files (e.g., generated with ffmpeg for the MP4s and a solid-color PNG)
- **GAP-0382** [VOD-018] Ad impression recording has no deduplication — `app/services/ad_placement.py:253-271` — Fix: add a DDB conditional write using key `AD_IMP#{date}#USER#{user_id}#VIDEO#{video_id}#SLOT#{slot_index}` with `attribute_not_exists(pk)` to cap one complete even
- **GAP-0383** [VOD-020] watermarked-download endpoint does not enforce VOD-019 download-tier entitlement — `app/routers/watermark.py:106-110` — Fix: before the cache lookup in `request_watermarked_download`, add the same entitlement check used in `video_listing.py:800-804`
- **GAP-0384** [VOD-021] SEC-012 cross-ref: VTT sanitizer uses a denylist instead of an allowlist — `app/services/vod_subtitle_manager.py:123-138` — Fix: replace the denylist with an allowlist parser that strips all tags except `<b>`, `<i>`, `<u>`, `<v NAME>`, `<ruby>`, `<rt>` and removes all attributes from perm

## MED / LOW backlog (by ticket)

Counts per ticket; details in each `docs/tickets/gaps/<TICKET>.md`.

| Area | CRIT | HIGH | MED | LOW |
|------|------|------|-----|-----|
| ADMIN | 0 | 2 | 10 | 6 |
| ADMIN-PERMS | 0 | 2 | 2 | 1 |
| ADS | 7 | 35 | 41 | 17 |
| AFFILIATE | 1 | 2 | 3 | 1 |
| AGENT | 4 | 30 | 40 | 19 |
| ANALYTICS | 0 | 1 | 5 | 4 |
| AUTH | 1 | 3 | 2 | 1 |
| BCAST | 0 | 22 | 31 | 30 |
| BILLING | 0 | 1 | 6 | 8 |
| BOT | 2 | 9 | 5 | 3 |
| CALL | 2 | 9 | 25 | 31 |
| CREATOR | 0 | 5 | 14 | 22 |
| DELEGATE | 0 | 3 | 9 | 13 |
| DISC | 0 | 2 | 0 | 2 |
| ENGAGE | 0 | 9 | 16 | 10 |
| ENTERPRISE | 1 | 12 | 14 | 8 |
| FEED | 0 | 2 | 15 | 14 |
| FILES | 0 | 2 | 1 | 2 |
| FIN | 2 | 30 | 29 | 21 |
| GEO | 0 | 2 | 2 | 1 |
| GROUP | 1 | 2 | 7 | 12 |
| INFRA | 1 | 19 | 26 | 18 |
| INTEG | 0 | 4 | 2 | 2 |
| KYC | 3 | 46 | 55 | 31 |
| LCOM | 0 | 5 | 4 | 4 |
| LICENSE | 1 | 5 | 15 | 10 |
| MEDIA | 0 | 3 | 7 | 4 |
| MOD | 1 | 5 | 9 | 4 |
| MON | 0 | 3 | 8 | 8 |
| MSG | 0 | 7 | 18 | 19 |
| NOTIFY | 0 | 1 | 1 | 2 |
| PLATFORM | 2 | 20 | 37 | 32 |
| PRIVACY | 0 | 4 | 5 | 1 |
| PROMO | 0 | 2 | 3 | 2 |
| PWA | 0 | 1 | 9 | 10 |
| ROOTCTL | 1 | 2 | 2 | 1 |
| SCHED | 0 | 0 | 3 | 1 |
| SHOP | 0 | 4 | 7 | 6 |
| SIGN | 1 | 2 | 4 | 2 |
| SOC | 0 | 4 | 11 | 11 |
| SOCIAL | 0 | 4 | 14 | 9 |
| SYND | 1 | 4 | 9 | 9 |
| TEST | 0 | 0 | 1 | 2 |
| UX | 0 | 1 | 6 | 10 |
| VOD | 2 | 19 | 39 | 30 |

## Unbuilt features (greenfield — design write-ups ready)

- **ADS-009** — see `docs/tickets/writeups/ADS-009.md`
- **ADS-019** — see `docs/tickets/writeups/ADS-019.md`
- **BILLING-004** — see `docs/tickets/writeups/BILLING-004.md`
- **BOT-003** — see `docs/tickets/writeups/BOT-003.md`
- **BOT-004** — see `docs/tickets/writeups/BOT-004.md`
- **DEVTOOLS-001** — see `docs/tickets/writeups/DEVTOOLS-001.md`
- **FIN-005** — see `docs/tickets/writeups/FIN-005.md`
- **FIN-007** — see `docs/tickets/writeups/FIN-007.md`
- **HELP-001** — see `docs/tickets/writeups/HELP-001.md`
- **HELP-002** — see `docs/tickets/writeups/HELP-002.md`
- **KYC-007** — see `docs/tickets/writeups/KYC-007.md`
- **KYC-025** — see `docs/tickets/writeups/KYC-025.md`
- **LCOM-003** — see `docs/tickets/writeups/LCOM-003.md`
- **LEGAL-001** — see `docs/tickets/writeups/LEGAL-001.md`
- **MSG-012** — see `docs/tickets/writeups/MSG-012.md`
- **PLATFORM-017** — see `docs/tickets/writeups/PLATFORM-017.md`
- **QST-001** — see `docs/tickets/writeups/QST-001.md`
- **ROOT-AUTH-001** — see `docs/tickets/writeups/ROOT-AUTH-001.md`
