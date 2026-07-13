# TestLogon — API-KEY PARITY Implementation Plan & Ticket Breakdown (#118)

Status: PLAN (no product/app/backend code changed by this document). Grounded in the live
`~/dev/testlogon` dev clone on host `192.168.0.249`, branch `android-impl` @ `66f3b33d`
(source-of-truth for the read). **Prod diverges from this clone in one load-bearing way** —
see §1.1 — which flips the answer for groups/video and adds an admin-only escape hatch;
every such divergence is flagged inline. Read-only audit; the only write is this doc + tickets.

Cross-refs: prior pass **#93** "API-key actions" left its residue *as the code itself*
(the whole `app/services/api_key_*` layer + `/ui/api_keys*` management router + Android
`feature/apikeys` console) — there was no plan doc; this is the first. Sibling plans:
`ops/plans/{tipping-implementation-plan,advertising-v2-implementation-plan,subscriptions-plan,payouts-plan,content-moderation-plan}.md`.
Prod hotfix artifact of record: `ops/prod-hotfixes/app_apikey_admin_wildcard.patch`
(git `a103e50a`, "Applied+verified live on prod 2026-07-02", **committed as an artifact only,
NOT applied to the dev branch source**).

---

## 1. HEADLINE VERDICT

**We are NOT at API-key parity. Of the five audited domains, only messaging and filemanager
are partially keyed (a small registered subset works; most capabilities 403); newsfeed is
broken to zero by a phantom registry mapping; and groups and video are entirely outside the
API-key model — no capability, no route registry, no rollout product, no policy dependency.**

Two structural facts govern everything:

1. **A router only admits an API key if it wires `Depends(maybe_enforce_api_key_route_policy)`.**
   Exactly ~8 routers do (`messaging`, `newsfeed`, `filemanager`, `tickets`, `shoppingcart`,
   `catalog`, `purchase_history`, `kb_articles`). On these, `request.state.api_key_principal`
   is set and `get_authenticated_user`/`require_ui_session` bridge the key to its owner
   (`app/auth/deps.py:236-256`, `app/services/sessions.py:330-350`). **Groups and video wire
   no such dep**, so on the dev clone an `apikey`/`X-API-Key` header matches no auth branch →
   **401 for every groups/video capability.**

2. **Within a policy-gated router, a route is invocable by a key ONLY if it is registered in
   `API_KEY_ROUTE_SCOPE_REGISTRY` with the key's scope.** Enforcement (`api_key_policy_enforcement.py`)
   reads ONLY the registry — it never consults `API_KEY_ROUTE_EXEMPTIONS`. So an *exempt* route
   and an *absent* route behave **identically: 403 `api_key_scope_denied` / reason `unmapped_route`**
   (`api_key_authorization.py:34-46`). The exemption list is drift-monitor bookkeeping only; it
   grants nothing. **This is the single most misunderstood fact in the codebase** and the reason
   "we exempted it" ≠ "a key can call it."

Load-bearing holes, in order:

- **H1 — Newsfeed is a phantom mapping → 0% parity, silently.** The registry maps
  `GET/POST/DELETE:/v1/newsfeed*` (`api_key_route_scope_registry.py:30-32`) — paths that exist
  **nowhere**. The real router has NO prefix; real routes are `/feed`, `/posts/*`. Every real
  route is unmapped → hard 403 even for a valid `newsfeed:read` key doing a plain `GET /feed`.
  Compounded: 3 permanent stale-drift entries, and `/feed`+`/posts` are absent from the rollout
  prefix list so the drift monitor never flags the live breakage.
- **H2 — Groups and video are un-modeled.** No `groups:*` / `video:*` capability
  (`api_key_capabilities.py`, 26 scopes, zero for either), no registry entries, no rollout
  product (`ROLLOUT_PRODUCTS = filemanager,newsfeed,tickets,shopping,messager`), no policy dep.
- **H3 — PROD is simultaneously too closed AND too open.** The prod hotfix injects a **global**
  `_api_key_principal_middleware` for ALL routers. Result on prod: groups, video, and the
  out-of-router feeds (group/syndicate/delegate) resolve the key owner on **every** route with
  **no scope check** (scope checks only run inside the policy dep, which those routers lack). So
  **any valid key — even `messager:read` — acts as full owner** on all non-gated routers,
  including **money movement** (group treasury spend, fundraiser CRUD, video re-pricing, post
  tips). This is a security/over-scope hole, not just a parity hole. Meanwhile normal keys still
  403 on `/feed`, `/posts`, and all exempt messaging/filemanager routes → too closed where it
  should work, too open where it should be gated.
- **H4 — Messaging/filemanager registered subsets are minimal and contract-broken in spots.**
  Messaging: read + send-text (with encrypted/scheduled/tip/lock/view-once inline) + file +
  delete/revoke/edit work; you **cannot even create a conversation**, and image-send is
  registered but its only upload path (`images/presign`) is exempt→403. Filemanager: list,
  mkdir, multipart-upload, download, share work; but the **UI's actual upload flow
  (presign→PUT→complete) is exempt→403**, so a key cannot upload the way every client does, and
  rename/move/copy/delete are all 403.
- **H5 — The `admin:all` prod escape hatch masks all of the above for admin owners only.**
  BATCH2 of the prod hotfix adds `admin:all`, which short-circuits ALLOW on every route incl.
  unmapped. So today "full parity via key" exists **only** as an admin/root-owned prod wildcard,
  not as real per-scope parity — and the Android app already ships `admin:all` in its catalog
  while the **dev backend rejects it** (`400 unknown api key capability: admin:all`).

**Bottom line:** parity coverage across the 5 domains is roughly **2 of 5 partial, 3 of 5
absent/broken**, and the one place where "everything" works (prod `admin:all`) is an
unscoped admin backdoor rather than the intended capability model. Closing this is mostly a
**registry + capability-taxonomy + router-wiring** effort — the identity bridge already works
everywhere; almost no handler code needs to change.

### 1.1 Which spec is authoritative — and the prod divergence

| Layer | DEV clone `66f3b33d` | PROD live (hotfix `a103e50a`) |
|---|---|---|
| Principal injection | Only on the ~8 policy-gated routers | **GLOBAL** `_api_key_principal_middleware` on ALL routers (`main.py`, after `_playback_entitlement_middleware`) |
| Groups / video / group-syndicate-delegate feeds | **401** (key never resolved) | **200 as owner, UNSCOPED** (over-scope hole) |
| Messaging / filemanager / newsfeed enforcement | Registry-gated (as documented) | **Identical** (these keep their policy dep) |
| `admin:all` wildcard | **Absent** — `400 unknown capability` | Present; ALLOW-all for admin/root-owned keys |

**Recommendation:** treat the **dev clone as the spec-of-record for the fix** (it is the clean
capability model), but treat the **prod over-scope (groups/video/feeds unscoped) as the higher
SECURITY priority**. This plan's foundation epic folds the prod hotfix into dev source so the
two specs converge, then closes the gaps under one enforcement model. A READ-ONLY prod probe
(SSM `/tmp/ssm_run.py`, no writes) to confirm the live state is listed in §5.

---

## 2. COVERAGE MATRIX (all 5 domains)

Status legend: **OK** = key-invocable at intended scope · **GAP-rejects-key** = live UI
capability that only accepts a UI session (401, dev) · **GAP-unmapped/exempt** = live route
under a policy-gated router, absent-or-exempt → 403 `unmapped_route` · **GAP-contract** = works
by key but a required companion step is blocked or the contract differs from the UI ·
**GAP-misscoped(over-open)** = reachable by key with NO/insufficient scope check (prod) ·
**INTENTIONAL** = genuinely should not be a key op · **N/A** = public / machine-webhook (not a
key surface). Citations are `file:line` in `~/dev/testlogon`.

### 2.1 MESSAGING — router `messaging.py:248` (policy-gated; dev==prod enforcement)

| Capability | Route @ line | Status | Cite |
|---|---|---|---|
| List / get conversation(s) | `GET /conversations` 6803, `/{id}` 6880 | **OK** `messager:read` | registry:74-75 |
| Get messages | `GET /conversations/{id}/messages` | **OK** `messager:read` | registry:76 |
| Send text (+ encrypted / scheduled / tip / lock / view-once inline) | `POST .../messages` 8793 | **OK** `messager:write` | registry:77 |
| Send file (from VFS) | `POST .../messages/file` 11438 | **OK** `messager:write` (needs filemanager too) | registry:79 |
| Edit / delete / revoke message | `PATCH .../{mid}` 12305, `DELETE` 11904, `/revoke` 12018 | **OK** `messager:manage` | registry:80-82 |
| Send image | `POST .../messages/image` 9123 | **GAP-contract** (send registered but `images/presign` 9104 exempt→403) | registry:78 vs :214 |
| Create DM / group / find-or-create / accept | 6406 / 6591 / 6729 / 6775 | **GAP-exempt** 403 | registry:209/211/210/212 |
| Rich sends: gallery / lottery / calendar-event / meeting-poll / file-share | 9756 / 14097 / 10369 / 10484 / 9950 | **GAP-exempt** 403 | registry:221/243/218/222/220 |
| Rich sends: countdown / gif / sticker / video-share / voice / voicemail / tts / find-datetime | 10596/10734/10809/10068/9402/9609/16242/11123 | **GAP-unmapped** 403 + drift | absent from registry |
| Reactions (add / details) | `POST .../reactions` 12068 | **GAP-exempt** 403 | registry:227/144 |
| Mark read / realtime events (poll/stream) | `/read` 11856, `/events*` 13970-14028 | **GAP-exempt/unmapped** 403 | registry:236/151/152 |
| Pins / forward / search / threads / gallery-browse | 12896 / 12451 / 8466 / 8313 / 8545 | **GAP-exempt** 403 | registry:226/238/141/160/137 |
| Scheduled-msg manage (list/cancel/edit) | 14605 / 14630 / 14689 | **GAP-exempt** 403 (create works, manage blocked) | registry:140/114 |
| Mass-messaging (create/list/get/cancel) | 809 / 933 / 1053 / 1105 | **GAP-exempt** 403 | registry:240/155/156/241 |
| Calls (invite/accept/decline/end/signal/turn-creds) | 15597-15898 / 15505 | **GAP-unmapped/exempt** 403 | absent / registry:242 |
| Drafts CRUD | 7908-8001 | **INTENTIONAL** (UI-local scratch) | registry:135/136/213/202/111 |
| Mute (per-user pref) | `/mute` 6892 | **INTENTIONAL** | registry:232 |
| Compliance / legal-hold / archive-export | 13270-13736 | **INTENTIONAL** (operator-role gated) | registry:128-133/208/216/217 |
| Chat-delegate `/delegate/*` | 15962-16018 | **INTENTIONAL** (UI-session delegates / separate `dak_` system) | absent |

### 2.2 NEWSFEED — router `newsfeed.py:78` (policy-gated, NO prefix; phantom registry)

**Net: 0 of ~30 capabilities are key-invocable on dev.** Every in-router route 403s
`unmapped_route`; every out-of-router feed 401s. Representative rows:

| Capability | Route @ line | Status | Cite |
|---|---|---|---|
| Feed read (main) | `GET /feed` 5504 | **GAP-unmapped** 403 even w/ `newsfeed:read` | registry:30-32 phantom |
| Create post (all media/gallery/video/gated/lock variants, one body) | `POST /posts` 3523 | **GAP-unmapped** 403 | phantom |
| Draft CRUD + publish | `/posts/drafts*` 3375-3480 | **GAP-unmapped** 403 | phantom |
| Edit / delete post | `PATCH /posts/{id}` 4059, `DELETE` 4869 | **GAP-unmapped** 403 | phantom |
| Comment / like / react / vote / poll / repost / bookmark | 6220 / 4905 / 5156 / 7926 / 8033 / 7219 / 7503 | **GAP-unmapped** 403 | phantom |
| Upload post image | `POST /uploads/image` 3282 | **GAP-unmapped** 403 | phantom |
| Feed read (For-You) | `GET /feed/for-you` 5919 | **GAP-unmapped** 403 (exempt = drift-silence only) | registry:87 |
| Group feed read / post / pin / delete | `group_feed.py` 24-106 | **GAP-rejects-key** 401 (dev) · **GAP-misscoped over-open** (prod) | group_feed.py:13 (no policy dep) |
| Syndicate feed read/post | `syndicate_feed.py:30` | **GAP-rejects-key** 401 · over-open (prod) | no policy dep |
| Delegated newsfeed (post/edit/approve/moderate/analytics) | `delegate_feed.py:27` | **GAP-rejects-key** 401 · over-open (prod) | no policy dep; NOT reachable by `dak_` (DM-only) |
| Tip on post / reaction-tip / comment-tip / paid-unlock | 4986 / 5209 / 6622 / 6771 | **GAP-unmapped** 403 (dev) · **SECURITY** if folded into `newsfeed:write` | money movement |

### 2.3 GROUPS — routers `user_groups.py` / `group_feed.py` / `group_calls.py` / `group_treasury.py` / `group_fundraising.py` (NO policy dep on any)

**Net: dev 401 for every op; prod 200-as-owner UNSCOPED for every op.** Representative rows:

| Capability | Route @ line | DEV | PROD | Class |
|---|---|---|---|---|
| Create / update / dissolve group | `POST /ui/groups` user_groups.py:65, `PATCH` :116, `DELETE` :129 | 401 | owner, unscoped | GAP-rejects-key · GAP-misscoped(over-open) |
| List / discover / get / members | :77 / :95 / :110 / :139 | 401 | owner, unscoped | same |
| Join / leave / invite / respond / review-request | :156 / :166 / :171 / :181 / :199 | 401 | owner, unscoped | same |
| Change member role / remove member / pending | :214 / :230 / :239 | 401 | owner, unscoped | same |
| Group post / feed / pin / delete-post | group_feed.py:24 / :49 / :74 / :105 | 401 | owner, unscoped | same |
| Group call create/join/leave/end/signal/media | group_calls.py:127-256 | 401 | owner, unscoped | same |
| Treasury read/ledger/contributors | group_treasury.py:32-103 | 401 | owner, unscoped | same |
| **Treasury contribute / spend / goal** | group_treasury.py:52 / :132 / :142 | 401 | owner, unscoped | **SECURITY** (money) |
| **Fundraising campaigns/fundraisers CRUD** | group_fundraising.py:54-184 | 401 | owner, unscoped | **SECURITY** (money) |
| Confirm donation | group_fundraising.py:281 | 401 | root-owner only | **INTENTIONAL** (`require_root_session`) |
| Public group feed / public fundraiser view/donate | group_feed.py:119, group_fundraising.py:198 | 200 | 200 | **N/A** (public) |
| Fundraising Stripe webhook | group_fundraising.py:235 | sig-gated | sig-gated | **N/A** (machine webhook) |

### 2.4 FILEMANAGER — router `filemanager.py:165` (policy-gated; dev==prod except `admin:all`)

| Capability | Route @ line | Status | Cite |
|---|---|---|---|
| List / download | `GET /v1/fs/list` 971, `/download` 2363 | **OK** `filemanager:read` | registry:24/27 |
| Create folder / multipart upload | `POST /v1/fs/folder` 1800, `/upload` 1817 | **OK** `filemanager:write` | registry:25/26 |
| Create share | `POST /v1/fs/share` 2927 | **OK** `filemanager:share` | registry:28 |
| **Upload — presign / complete (the UI's real flow)** | `/presign-upload` 1932, `/complete-upload` 1953 | **GAP-contract** 403 (UI never calls multipart `/upload`) | exempt registry:280/264 |
| Info / search / search-text / preview / thumbnail | 1118 / 1162 / 1171 / 2440 / 2503 | **GAP-exempt** 403 | registry:183/188/189/187/197 |
| Rename-file / rename-folder / move / copy | 2761 / 2803 / 2651 / 2699 | **GAP-exempt/unmapped** 403 (copy unmapped + drift) | registry:282/283/277 / absent |
| Delete file / folder / generic | 2575 / 2617 / 2563 | **GAP-exempt** 403 | registry:123/124/122 |
| Unshare / list-shares / shared-with-me / consume-shared | 2964 / 2988 / 2996 / 3099 | **GAP-exempt** 403 | registry:292/195/196/190 |
| Batch-upload / crm-metadata / crm-search | 1892 / 3778 / 3815 | **GAP-unmapped** 403 + drift | absent |
| Zip/archive bulk / usage-quota | 2882 / 3704 | **GAP-exempt** 403 (low) | registry:265/198 |
| Mount CRUD + credentials (icloud/sftp/s3 create/rotate/revoke/validate) | 884-2363 | **INTENTIONAL** (credential-bearing) | registry:125/185/266-276 |
| Admin/* (list/search/audit/reconcile) | 1180-3704 | **INTENTIONAL** (admin session) | registry:178-182/261 |

Cross-user isolation: **OK** — `_current_user` (filemanager.py:249) pins every op to the key
owner's `user_sub`; no leak. Dead scope: `filemanager:admin` is grantable but maps to zero
routes (config hygiene).

### 2.5 VIDEO-PUBLISHING — routers `video_listing.py` / `vod.py` / `video_subtitles.py` / `transcode_jobs.py` / `vod_bridge.py` etc. (NO policy dep on any)

**Net: dev 401 for every op; prod 200-as-owner UNSCOPED for every op.** Representative rows:

| Capability | Route @ line | DEV | PROD | Should-key |
|---|---|---|---|---|
| Presign upload / complete-upload | vod.py:136 / :228 | 401 | over-open | `video:write` |
| Submit transcode / status / list | transcode_jobs.py:67 / :115 / :128 | 401 | over-open | `video:write` / `read` |
| List / detail own videos | video_listing.py:1332 / :978 | 401 | over-open | `video:read` |
| **Edit metadata/visibility / delete / pricing / ad-config** | :1031 / :1318 / :1569 / :1868 | 401 | over-open | **SECURITY** (`video:write`, revenue/destructive) |
| Publish / unpublish to gallery | :604 / :627 | 401 | over-open | `video:write` |
| Subtitles add/list/delete/patch | video_subtitles.py:62-154 | 401 | over-open | `video:write`/`read` |
| Clip / combine | :1189 / :1296 | 401 | over-open | `video:write` |
| Import external → VOD / bridge status | vod_bridge.py:41 / :48 | 401 | over-open | `video:write`/`read` |
| Admin list-by-status / moderation queue | video_listing.py:346 | 401 | admin-owner only, unscoped | `video:moderate` |
| Purchase / rental / ad-supported / watermark / engagement | 1466 / vod_rental.py / vod_ad_supported.py | 401 | over-open | low-prio `video:read` |
| DRM key serve | vod_drm.py:40/149 | N/A | N/A | **INTENTIONAL** (public, entitlement-token gated) |
| DRM key revoke | vod_drm.py:233/300 | 401 | admin+CSRF | **INTENTIONAL** (`require_admin_or_root_csrf`; key has no CSRF) |

---

## 3. PRIORITIZED GAP LIST (real parity holes only)

Ranked by severity × value. Intentional blocks are excluded here and listed in §4. Items
marked **[SECURITY]** are cases where the current state grants (prod) or a naive fix would
grant a key a capability it should NOT have unscoped — treat these as security-gating, not
just parity.

**P0 — H1 · Newsfeed phantom registry breaks 100% of newsfeed parity, silently.**
`api_key_route_scope_registry.py:30-32` maps nonexistent `/v1/newsfeed*`; real `/feed`+`/posts/*`
are unmapped → hard 403 for every request incl. a plain `newsfeed:read` `GET /feed`. Also: 3
permanent stale-drift entries + real routes absent from the rollout-prefix list so drift alerting
is blind + the `api_key_newsfeed_phase` flag is inert for real traffic.
*Fix shape:* re-point the 3 registry entries at real route_ids and enumerate the ~40 live routes
(reads→`newsfeed:read`, author mutations→`newsfeed:write`, cross-owner delete/moderation→`newsfeed:moderate`);
add `/feed` and `/posts` to `API_KEY_INITIAL_ROLLOUT_PATH_PREFIXES`. Registry-only change; handlers
already bridge the principal. **[SECURITY sub-note]** do NOT fold tips/paid-unlock into
`newsfeed:write` (see P2-b).

**P0 — H3 · [SECURITY] Prod global-injection makes groups/video/feeds unscoped-owner for ANY key.**
On prod, `_api_key_principal_middleware` resolves the owner on ALL routers, but scope checks only
run inside the policy dep, which groups/video/group-syndicate-delegate feeds lack → a `messager:read`
key can create/dissolve groups, change roles, **spend group treasury, run fundraiser CRUD, delete/re-price
videos, post to syndicates, drive the delegated-newsfeed surface** — all as full owner, no scope.
This is the biggest blast-radius finding. *Fix shape:* it is resolved by the same work as H2 —
either wire the policy dep + register routes under new `groups:*`/`video:*` scopes, or (if a domain
is meant to be session-only) have those routers **explicitly reject** a key principal on unregistered
routes instead of silently accepting it. Until then, prod is over-permitted.

**P1 — H2 · Groups & video are entirely un-modeled for API keys.**
No `groups:*`/`video:*` capability, no registry entries, no rollout product, no policy dep.
"Publish a video via API" (presign→complete→transcode→metadata/visibility/pricing→publish) and
"run a group via API" are the canonical "do everything via key" use cases and are impossible on dev
(401), wide-open on prod (P0). *Fix shape:* foundation epic APIK-E0 adds the scope families +
rollout products; domain epics wire the deps + register routes.

**P1 — S2(messaging) · Cannot create/bootstrap a conversation via key.**
`POST /conversations`, `/conversations/group`, `/conversations/dm/find-or-create` exempt→403
(registry:209/211/210). A key can send into an existing conversation but can never initiate outbound
DMs — a bot integration is dead on arrival. *Fix:* register the 3 create routes under `messager:write`.

**P1 — S1(messaging) · ~15 live rich-type/call routes are unmapped → 403 + "critical" drift.**
`countdown, gif, sticker, video-share, voice-message(+presign), voicemail(+presign), tts-voice,
find-datetime(+availability/close/get), translate, transcribe, moderate-revoke, reactions/tip,
calls/{invite,accept,decline,end,timeout,signal}, privacy/message*` are neither registered nor
exempt under the `/messaging` rollout prefix → runtime 403 AND the drift monitor sits red "critical."
*Fix:* triage each into the registry (`messager:write`) or into exemptions with an explicit reason;
nothing should be implicitly unmapped under a rollout-prefix router.

**P1 — S1(filemanager) · [contract] The UI's real upload flow can't be done by a key.**
Android uploads via `presign-upload`→S3 PUT→`complete-upload` (`FilesApi.kt:122,126`); both exempt→403.
The only key-invocable upload is the multipart `/v1/fs/upload` the app never calls. So a
`filemanager:write` key effectively cannot upload a file the way every client does.
*Fix:* register `POST:/v1/fs/presign-upload` + `POST:/v1/fs/complete-upload` as
`filemanager:write, entitlement_required:True` (mirror `/upload`).

**P2 — S3(messaging) · Rich-message parity near-zero.**
Of media/gallery/video/voice/gif/sticker/countdown/lottery/calendar-event/meeting-poll/find-datetime/file-share,
only plain file (VFS) and — partially — image work; encrypted/scheduled/tip/lock/view-once work inline
on the text route. *Fix:* register the dedicated rich-type send routes under `messager:write` (registry
entries only; handlers already bridge).

**P2 — S4(messaging) · [contract] Image send is un-uploadable.**
`POST .../messages/image` is registered but `images/presign` is exempt→403 → registered route is dead
unless caller already holds a valid bucket/key. *Fix:* register `images/presign` under `messager:write`.

**P2 — S2(filemanager) · Core file mutations blocked.**
rename-file/rename-folder/move/copy/delete-file/delete-folder/generic-delete all 403 (copy also unmapped
+ drift). A write key can mkdir+upload but cannot rename/move/copy/delete — half a filesystem.
*Fix:* register under `filemanager:write`; `move-resume/rollback` follow `move`.

**P2 — S5(messaging) · No realtime, read-state, or reactions.**
`GET /events`/`/events/stream`/`/events/poll`, `POST /read`, `POST .../reactions` all 403 → a key can
send and read history but cannot poll for new messages, mark read, or react → cannot function as a live
agent. *Fix:* register events poll/stream (`messager:read`), read + reactions (`messager:write`).

**P2 — S3(filemanager) · Sharing surface asymmetric.**
Create-share works but revoke, list-my-shares, shared-with-me, consume-shared, shared mutations all 403 —
a key can create a share it can neither list, revoke, nor consume. *Fix:* register `shared-*` reads under
`filemanager:read`/`share`, `unshare`+shared mutations under `filemanager:share`/`write`.

**P2 — S4(filemanager) · Read-side gaps.** info/search/search-text/preview/thumbnail 403.
*Fix:* register under `filemanager:read`.

**P2 — [SECURITY] Money-movement routes must NOT inherit coarse write scopes.**
Newsfeed tips/reaction-tip/comment-tip/paid-unlock (newsfeed.py:4986/5209/6622/6771), group treasury
spend/contribute + fundraiser CRUD (group_treasury.py:132, group_fundraising.py:117), video pricing
(video_listing.py:1569). Today they 403 on dev but an `admin:all` key already spends owner funds on prod,
and a naive P0/P1 fix would grant them to any `*:write` key. *Fix:* leave INTENTIONAL-blocked OR gate
behind a distinct high-privilege scope (`newsfeed:tips`, `groups:treasury`, `fundraising:write`,
`video:monetize`) — never fold into generic `*:write`.

**P3 — S6(messaging) · Mass-messaging blocked despite being the canonical automation use case.**
`POST/GET /mass-messages*` exempt→403. *Fix:* decide intentional vs gate behind `messager:manage` +
entitlement (bulk send is exactly what a key is for).

**P3 — S7(messaging) · Scheduled-message manage asymmetry.** Key can create a scheduled send but not
list/cancel/edit it → orphaned schedules. *Fix:* register the 3 schedule-manage routes under `messager:manage`.

**P3 — S8(messaging) · Pins/forward/search/threads/gallery-browse** 403 → read/organize parity gaps.
*Fix:* register under `messager:read`/`write` as appropriate.

**P3 — S5(filemanager) · Registry drift / phantom + orphan routes.**
4 phantom `/v1/files*` entries (registry:19-22) point at nonexistent routes (real prefix `/v1/fs`) →
permanent stale drift; `copy`/`batch-upload`/`crm-metadata`/`crm-search` are live-but-unmapped → 403 +
`unregistered_live`. *Fix:* delete the 4 phantoms; register-or-exempt the 4 orphans.

**P3 — video G3/G4 · Transcode/ingest + admin-moderation key paths.**
Ingest→transcode is the automation-centric path (401 on dev); admin video queue has no *scoped* admin-key
path. *Fix:* covered by the video epic (`video:write` for ingest, `video:moderate` admin-owner-gated).

**P4 — misc low-value:** filemanager usage/quota + zip/archive; video consumption (purchase/rental/ad/
watermark/engagement) — include only if consumer-automation is in scope.

**Cross-cutting hygiene (not a per-route hole but must ship):**
- **Rollout phase audit.** If any of the 5 products' live `api_key_<product>_phase` is `shadow`, the
  registered routes pass **unscoped** (any key = owner) even on gated routers. Confirm all are `ga` on prod.
- **Dead scope `filemanager:admin`** maps to zero routes — either wire it to admin/* fs routes or remove
  it from the grantable set.
- **Exemption semantics are misleading.** Document that `API_KEY_ROUTE_EXEMPTIONS` = drift-silencing only,
  never a runtime allow; consider making the enforcement path consult it (explicit session-only pass-through)
  so "exempt" means what people think it means.

---

## 4. CONFIRMED-INTENTIONAL (correct blocks — NOT parity holes)

- **Messaging drafts** (registry:135/136/213/202/111) — UI-local scratch state.
- **Messaging mute** (registry:232) — per-user notification preference.
- **Messaging compliance / legal-hold / archive-export** (messaging.py:1166-1174,
  `require_legal_hold_operator`/`require_compliance_*_operator`) — operator-role, not a key op.
- **Chat-delegate `/delegate/*`** — served by UI-session delegates + the separate `dak_` Bearer system
  (`delegation_api.py`); not on the `ak_` capability model.
- **Filemanager mount CRUD + all credential ops** (icloud/sftp/s3 create/rotate/revoke/validate/test) —
  credential-bearing; session-only defensible.
- **Filemanager admin/*** (list/search/audit/reconcile), purge-deleted, client-telemetry — admin-session.
- **Group confirm-donation** (group_fundraising.py:286, `require_root_session`) — root-only. *Caveat:* under
  prod global-injection a root/admin-owned key would pass; add an explicit test that a non-root key 403s.
- **Public surfaces** (public group feed, public fundraiser view/donate/receipt, public video, DRM key serve)
  and **machine webhooks** (Stripe) — need no key; not parity holes.
- **DRM key revoke** (vod_drm.py:233/300, `require_admin_or_root_csrf`) — admin + CSRF; a key carries no CSRF
  token so it 403s even for admin owners. Defensible; flag only if key-driven DRM revocation is desired.
- **Delegation (`dak_`) keys** give NO newsfeed/groups/video/filemanager parity by design — only 3 DM/
  conversation routes (`delegation_api.py`), permissions `chat_read`/`chat_respond`, bound to one creator.
  Orthogonal to the capability model; no overlap expectations.

---

## 5. RECOMMENDED READ-ONLY PROD PROBES (no writes, no restarts)

Confirm the live spec before building. All via SSM `/tmp/ssm_run.py`, GET/known-safe only:
1. Confirm `_api_key_principal_middleware` is in the running `main.py` (documented live 2026-07-02).
2. `GET /ui/groups` and `GET /ui/videos` with a low-scope `ak_` key → expect **200** (proves P0/H3 over-scope).
3. `GET /feed` with a `newsfeed:read` key → expect **403 `{code:api_key_scope_denied, reason:unmapped_route}`**
   (proves H1).
4. `POST /messaging/messages/countdown` w/ `messager:write` key → 403; `POST /messaging/.../messages` → 200
   (proves the exempt==unmapped==403 model).
5. Confirm each `api_key_<product>_phase` (filemanager/newsfeed/tickets/shopping/messager) is `ga` in the
   running env — any `shadow` = silent unscoped pass-through on gated routes.
6. `GET /v1/fs/list?path=/` (200) vs `GET /v1/fs/info?path=/` (403) with a `filemanager:read` key.
Do NOT run any write-completing call (`upload/complete`, `PATCH /pricing`, `DELETE`, treasury `spend`).

---

## 6. TICKETED PLAN (APIK-* — dependency-ordered epics)

Mirrors the tips/ads/subs/payouts structure: a foundation epic first (the auth/scope layer itself
needs changes), then one epic per domain, then hardening. Every ticket is registry/capability/wiring
work unless noted — **the identity bridge already works, so handlers are largely untouched.**

### EPIC E0 — FOUNDATION: converge specs + extend the capability model  *(blocks everything)*

- **APIK-E0-1 — Fold the prod hotfix into dev source (spec convergence).**
  Apply `ops/prod-hotfixes/app_apikey_admin_wildcard.patch` semantics to `android-impl`: decide whether
  the **global** `_api_key_principal_middleware` stays global (then every non-gated router must explicitly
  reject unregistered key access — see E0-4) or is removed in favor of per-router policy deps. Add `admin:all`
  to `CANONICAL_API_KEY_CAPABILITIES` + `expand_api_key_capabilities` + create-gate
  (`api_key_wildcard_forbidden` for non-admin/root owners) so dev stops returning `400 unknown capability`
  and matches the Android catalog.
  *Accept:* dev and prod give the same answer for an `ak_` key on groups/video/newsfeed; `admin:all` key
  creatable only by admin/root; unit test asserts a non-admin `admin:all` create → 403.

- **APIK-E0-2 — Add `groups:*` and `video:*` capability families.**
  `api_key_capabilities.py`: add `groups:{read,write,manage,treasury}`, `video:{read,write,moderate,monetize}`
  (+ inheritance: `manage`⊇`write`⊇`read`, `moderate`⊇`read`, `treasury`/`monetize` standalone high-priv).
  Add money-scopes `newsfeed:tips`, `fundraising:write`. Update `expand_api_key_capabilities` closure +
  plan-gating allowlist derivation.
  *Accept:* new scopes grantable via `/ui/api_keys` (plan-permitting), appear in the Android multi-select,
  inheritance unit-tested.

- **APIK-E0-3 — Add `groups` and `video` rollout products.**
  `api_key_rollout.py`: `ROLLOUT_PRODUCTS += ("groups","video")`; `settings.py` phase flags
  `api_key_groups_phase`/`api_key_video_phase` default `shadow` (promote to `ga` after canary).
  *Accept:* phase flags resolvable; shadow = log-not-enforce path exercised in a test.

- **APIK-E0-4 — Make "session-only" explicit + fix exemption semantics.**
  Decide, per non-gated router, session-only vs keyed. For session-only routers, add an explicit guard that
  **rejects** a request whose `api_key_principal` is set on an unregistered route (close the prod over-scope
  for anything not intentionally keyed). Make the enforcement path optionally consult
  `API_KEY_ROUTE_EXEMPTIONS` as a real session-only pass-through, or delete the list and document that
  exempt≠allowed.
  *Accept:* on the converged build, a key hitting a session-only route gets a deterministic 403 (not a silent
  200-as-owner); drift monitor and runtime agree.

- **APIK-E0-5 — Drift cleanup + phase confirmation.**
  Delete phantom registry rows (`/v1/newsfeed*` :30-32, `/v1/files*` :19-22). Confirm live product phases
  are `ga` (probe §5.5). Fix dead scope `filemanager:admin` (wire to admin/* or drop from grantable set).
  *Accept:* `stale_route_count == 0`; drift monitor green; no grantable scope maps to zero routes.

### EPIC E1 — NEWSFEED (highest-signal; registry-only)  *(depends E0-5)*

- **APIK-E1-1 — Re-point registry at real newsfeed routes.** Enumerate ~40 live `/feed` + `/posts/*` +
  `/uploads/image` + bookmark routes; map reads→`newsfeed:read`, author mutations→`newsfeed:write`,
  cross-owner delete/moderation→`newsfeed:moderate`. Add `/feed`,`/posts` to
  `API_KEY_INITIAL_ROLLOUT_PATH_PREFIXES`.
  *Accept:* `newsfeed:read` key `GET /feed` → 200; `newsfeed:write` key `POST /posts` (all media/gallery/
  video/gated variants via the one `CreatePostRequest` body) → 200; unmapped newsfeed route count → 0.
- **APIK-E1-2 — [SECURITY] Gate newsfeed money routes.** Map tip/reaction-tip/comment-tip/paid-unlock to
  `newsfeed:tips` (NOT `newsfeed:write`). *Accept:* a `newsfeed:write`-only key → 403 on `POST /posts/{id}/tip`;
  a `newsfeed:tips` key → 200.
- **APIK-E1-3 — Group/syndicate/delegate feeds decision.** Per E0-4: if keyed, add policy dep to
  `group_feed.py`/`syndicate_feed.py`/`delegate_feed.py` + register under `newsfeed:write`/`moderate` (or
  `groups:write` for group feed); if session-only, explicit reject. *Accept:* no unscoped-owner path on prod.

### EPIC E2 — MESSAGING (registry-only)  *(depends E0)*

- **APIK-E2-1 — Conversation bootstrap.** Register `POST /conversations`, `/conversations/group`,
  `/conversations/dm/find-or-create`, `/accept` under `messager:write`. *Accept:* a `messager:write` key can
  create a DM and send into it end-to-end.
- **APIK-E2-2 — Rich sends + image-presign contract fix.** Register gallery/video-share/voice/voicemail/tts/
  gif/sticker/countdown/calendar-event/meeting-poll/find-datetime/file-share and `images/presign` under
  `messager:write`. *Accept:* each rich send returns 200; image send works end-to-end (presign→send); messaging
  unmapped-route drift → 0.
- **APIK-E2-3 — Realtime + read + reactions.** Register `/events`,`/events/stream`,`/events/poll`
  (`messager:read`), `/read` + `/reactions` (`messager:write`). *Accept:* a key can poll new messages, mark
  read, react.
- **APIK-E2-4 — Organize/read parity.** Register pins/forward/search/threads/gallery-browse
  (`messager:read`/`write`) + scheduled-message manage (list/cancel/edit → `messager:manage`).
  *Accept:* scheduled send created via key is retractable via key.
- **APIK-E2-5 — Mass-messaging decision.** Gate `/mass-messages*` behind `messager:manage` + entitlement, or
  confirm INTENTIONAL. *Accept:* documented decision + test.

### EPIC E3 — FILEMANAGER (registry-only)  *(depends E0)*

- **APIK-E3-1 — [flagship] Presigned upload flow.** Register `presign-upload` + `complete-upload` as
  `filemanager:write, entitlement_required:True`. *Accept:* a `filemanager:write` key completes
  presign→PUT→complete and the file appears in `GET /v1/fs/list`.
- **APIK-E3-2 — Core mutations.** Register rename-file/rename-folder/move/copy/delete-file/delete-folder/
  generic-delete (+ move-resume/rollback) under `filemanager:write`; clears copy drift.
  *Accept:* write key can rename/move/copy/delete; no fs unmapped-route.
- **APIK-E3-3 — Sharing symmetry.** Register unshare + shared-* reads/consume/mutations under
  `filemanager:share`/`read`/`write`. *Accept:* a key can create, list, consume, and revoke a share.
- **APIK-E3-4 — Read-side + orphans.** Register info/search/search-text/preview/thumbnail (`filemanager:read`)
  and batch-upload/crm-metadata/crm-search. *Accept:* stat/search/preview by key; drift → 0.

### EPIC E4 — GROUPS (wiring + registry; NEW scopes)  *(depends E0-2/E0-3)*

- **APIK-E4-1 — Admit keys on group routers.** Add `dependencies=[Depends(maybe_enforce_api_key_route_policy)]`
  to `user_groups.py`, `group_feed.py`, `group_calls.py`, `group_treasury.py`, `group_fundraising.py`.
  *Accept:* a scoped key resolves; an unscoped key 403s (not silent 200).
- **APIK-E4-2 — Register group CRUD/membership/feed/calls.** reads→`groups:read`, mutations→`groups:write`,
  role/remove/dissolve→`groups:manage`. *Accept:* full group lifecycle drivable by a `groups:manage` key;
  `groups:read` key cannot mutate.
- **APIK-E4-3 — [SECURITY] Gate group money.** Treasury contribute/spend/goal → `groups:treasury`; fundraiser
  CRUD → `fundraising:write`. Confirm-donation stays `require_root_session`. *Accept:* a `groups:write` key
  403s on treasury spend; a non-root key 403s on confirm-donation (explicit test).

### EPIC E5 — VIDEO-PUBLISHING (wiring + registry; NEW scopes)  *(depends E0-2/E0-3)*

- **APIK-E5-1 — Admit keys on video routers.** Add the policy dep to `video_listing.py`, `vod.py`,
  `video_subtitles.py`, `transcode_jobs.py`, `vod_bridge.py`. *Accept:* scoped key resolves; unscoped 403s.
- **APIK-E5-2 — Register ingest→publish pipeline.** presign/complete/transcode(+status)/list/detail/edit/
  subtitles/clip/combine/import/publish-unpublish: reads→`video:read`, mutations→`video:write`.
  *Accept:* a `video:write` key can ingest→transcode→set-metadata→publish end-to-end.
- **APIK-E5-3 — [SECURITY] Gate video money + moderation.** pricing/ad-config/monetize→`video:monetize`;
  admin by-status/moderation queue→`video:moderate` (admin-owner create-gated). DRM revoke stays CSRF/admin
  INTENTIONAL. *Accept:* `video:write`-only key 403s on `PATCH /pricing`; non-admin key 403s on moderation.

### EPIC E6 — HARDENING / VERIFY  *(depends E1-E5)*

- **APIK-E6-1 — Canary→GA promotion.** Move `groups`/`video` phases shadow→canary→ga with the drift monitor
  green. *Accept:* enforce=True live; no shadow silent-pass.
- **APIK-E6-2 — Parity regression suite.** One test per domain: a scoped key does the full UI flow; a
  wrong-scope key 403s; a money/admin route requires its high-priv scope. *Accept:* suite green on the
  converged build; re-run confirms dev==prod.
- **APIK-E6-3 — Android catalog alignment.** Ensure `ApiKeyCapabilities.kt` lists the new `groups:*`/`video:*`/
  money scopes with labels; no orphan `admin:all` mismatch. *Accept:* app create-key screen offers every new
  scope and matches backend canonical set.

---

## 7. RECOMMENDED BUILD SEQUENCE

1. **E0 (foundation) first — it blocks everything and closes the prod over-scope.** In order:
   E0-1 (converge specs + `admin:all`) → E0-2 (scopes) → E0-3 (rollout products) → E0-4 (explicit
   session-only / exemption semantics — this is what actually shuts the prod hole) → E0-5 (drift + phase).
2. **E1 Newsfeed next** — highest signal, lowest effort (registry re-point only), and it's currently 0%.
   Ship E1-1, then E1-2 (money gating) before any promotion, then E1-3 (feeds decision).
3. **E2 Messaging + E3 Filemanager in parallel** — both registry-only on already-gated routers, independent
   of each other. Prioritize the two contract-breakers (E2-2 image-presign, E3-1 upload flow) and E2-1
   conversation-bootstrap since those unblock real bot integrations.
4. **E4 Groups + E5 Video** — require router wiring + new scopes (depend on E0-2/E0-3). Do the money/moderation
   security tickets (E4-3, E5-3) in the same PR as the register tickets so a scoped key never briefly gets an
   ungated money route.
5. **E6 hardening** — canary→GA, regression suite, Android catalog — last, gating GA promotion on green drift.

Guiding principle: **close the security over-scope (E0-4) before opening any new parity** — never ship a
domain keyed-but-unscoped under the global-injection model. Prefer the dev-clone capability model as the
spec-of-record; the prod hotfix is folded in (E0-1), not extended.

---

## 8. KEY SOURCE FILES

Auth/scope layer: `app/services/api_key_{auth_dependency,keys,capabilities,authorization,policy_enforcement,route_scope_registry,rollout}.py`,
`app/auth/deps.py:236-256`, `app/services/sessions.py:330-350`, `app/core/settings.py:57-75`.
Routers: `app/routers/{messaging,newsfeed,filemanager,group_feed,user_groups,group_calls,group_treasury,group_fundraising,syndicate_feed,delegate_feed,video_listing,vod,video_subtitles,transcode_jobs,vod_bridge,vod_drm}.py`.
Delegation (separate system): `app/routers/delegation_api.py`, `app/services/delegation_api.py`.
Prod divergence: `ops/prod-hotfixes/app_apikey_admin_wildcard.patch` (git `a103e50a`).
Android console: `android/app/.../feature/apikeys/`, `android/core-network/.../apikeys/ApiKeysApi.kt`, `ApiKeyCapabilities.kt`.
