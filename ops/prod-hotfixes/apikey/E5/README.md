# APIK EPIC E5 — Video-publishing parity (#118)

Router-wiring + registry + rollout change. Before E5 the 5 video routers were un-gated, so
under the E0 fail-closed model every key hitting video (incl. pricing/moderation) got a 401
(the route never set the `api_key_route_authorized` marker, so the injected principal was
ignored). E5 admits keys on the video routers and models the publish pipeline so scoped keys
work, while video MONEY (pricing/ad-config) and MODERATION (admin by-status) stay gated by
distinct high-priv scopes that `video:write`/`video:manage` do NOT inherit.

## Changes
- **Router wiring (E5-1):** `dependencies=[Depends(maybe_enforce_api_key_route_policy)]`
  added to `video_listing.py`, `vod.py`, `video_subtitles.py`, `transcode_jobs.py`
  (BOTH `router` and `video_router`), `vod_bridge.py`. The DRM router (`vod_drm.py`,
  prefix `/v1/vod/drm`) is INTENTIONALLY NOT wired — public key-serve stays token-gated and
  `keys/revoke*` stays `require_admin_or_root_csrf`.
- **Registry (E5-2/E5-3):** 32 rows under `product="video"`:
  - reads → `video:read` (list/public/creator/by-creator/gallery/gallery-search/
    gallery-categories/detail, subtitle list, transcode-jobs list+detail, transcode status,
    vod-bridge status).
  - mutations → `video:write` (upload presign/complete + legacy complete, transcode submit
    (+/ui/transcode-jobs), metadata PATCH, delete own, clip, combine, subtitle post/patch/
    delete, vod-bridge import/unlink).
  - gallery publish/unpublish → `video:publish`.
  - **MONEY (SECURITY, E5-3):** pricing PATCH + ad-config PATCH → **`video:monetize`**
    (standalone — `manage` inherits write+publish but NOT monetize). A plain `video:write`
    key CANNOT re-price or change ad monetization.
  - **MODERATION (SECURITY, E5-3):** admin by-status → **`video:moderate`** (standalone —
    `manage` does NOT inherit it; also `require_admin_or_root`, so the key OWNER must be
    admin — "admin-owner create-gated").
  - **Intentionally UNREGISTERED → fail-closed (403 `unmapped_route`) to every key:** tip /
    comment-tip / purchase / access / playback-complete / purchases-list (money+entitlement),
    view / like / comments / reactions (social), GET ad-config / ad-impression / ad-stats
    (ad serve+analytics), download (DRM). UI sessions still reach these (policy is a no-op
    without an `X-API-Key`/`apikey` header).
- **Rollout:** `api_key_video_phase` default **shadow → ga** so scopes actually enforce.

## Publish-scope note
E0-2 created a distinct `video:publish` capability with inheritance `manage → (write,publish)`.
E5 honors that: gallery publish/unpublish require `video:publish` (a `video:write`-only key is
denied), so the publish grant is meaningful rather than dead code. The end-to-end pipeline is
exercised with a `video:write`+`video:publish` key and (independently) a `video:manage` key —
matching the task's "video:write/publish key runs presign→…→publish".

## Verify (in-process on PROD DDB, synthetic users/keys, auto-cleaned, 0 residue)
- BEFORE: video:read→GET /ui/videos 401, video:write→POST upload/presign 401,
  video:monetize→PATCH pricing 401 (all fail-closed pre-E5); messager:read→/messaging 200.
- AFTER: full positive pipeline (write presign→complete→transcode(seam)→status; metadata
  PATCH 200; publish via write+publish key; clip/combine/subtitles/transcode-jobs/vod-bridge
  past-gate; monetize prices + ad-config; moderate(admin) admin/by-status 200; manage inherits
  write+publish+read) + negative/security (read!=write, read/write!=publish, **write CANNOT
  re-price/ad-config**, manage!=monetize, manage/write!=moderate, monetize!=read/write,
  moderate!=monetize, wrong-scope 403, non-admin moderate owner 403 via require_admin_or_root,
  tip/purchase/ad-stats UNMAPPED 403 fail-closed, DRM serve untouched by policy) + regression
  (UI session 200, unmapped-but-session 200, no-cred 401, invalid key 401, admin:all wildcard
  200 incl. pricing, messager/filemanager/groups keyed intact, dak_ delegation intact).

## Apply / verify
    python ops/prod-hotfixes/apikey/E5/apply_apik_e5_patch.py    # idempotent; APIK_ROOT/APIK_REG/... override targets
    APIK_PHASE=AFTER APIK_REPO=<repo> python ops/prod-hotfixes/apikey/E5/verify_apik_e5.py
    python ops/prod-hotfixes/apikey/E5/gen_prod_deploy_e5.py {place|apply|verify_after}  # SSM probes

## .bak
- Prod (kept): `<file>.bak_apik_e5_<ts>` for all 7 patched files.
- Dev working tree: git is source-of-truth (no stray .bak committed).
