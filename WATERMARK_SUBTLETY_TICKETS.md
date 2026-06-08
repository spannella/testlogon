# Subtle Video Watermarking — Implementation Tickets

This ticket set reworks the VOD/broadcast watermarking pipeline so that each output carries exactly ONE clearly-visible branding mark in a corner, while the per-viewer forensic marks are pushed to near-imperceptible (low alpha, small, repeated) levels that a machine can still reliably decode. It is grounded in the existing watermark code: the policy contract (`app/contracts/watermark_policy.py`), the FFmpeg filter builders (`app/services/watermark_profile_renderers.py`, `app/services/ffmpeg_abr_pipeline.py`), the per-viewer forensic render path (`app/services/vod_watermark_download.py`, `app/services/watermark_generator.py`), the player overlay (`frontend/src/components/shared/WatermarkOverlay.tsx`), and the (currently orphaned) tuning settings in `app/core/settings.py:1915-1930`.

## Milestone 1 — Audit & Foundations

### WMK-001: Audit & spike of the current watermark pipeline
**Type:** Spike  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Map every place a mark is drawn today and its effective opacity/size/position:
  - Visible/forensic drawtext in ABR transcode: `app/services/ffmpeg_abr_pipeline.py:77-105` (`fontcolor=white@{watermark_policy.opacity}` with hardcoded `fontsize=24`; default `WatermarkPolicy.opacity=0.7`, `position="top_right"` per `app/contracts/watermark_policy.py:43-49`).
  - Shared filter builder: `app/services/watermark_profile_renderers.py:51-75` (`ffmpeg_watermark_filter`) and the MediaLive variant `medialive_watermark_settings` at `:78-116` (`Opacity = int(policy.opacity*100)`).
  - Per-viewer forensic render: `app/services/vod_watermark_download.py:133-150` (`_build_ffmpeg_filter` forces `position="bottom_right"`, `opacity=S.vod_watermark_download_opacity`, payload from `build_watermark_payload`).
  - Forensic payload codec: `app/services/watermark_generator.py:28-64` (`build_watermark_payload` / `decode_watermark_payload`, format `WM:v1:{user_hash}:{ts_hex}:{crc}`).
  - Player-side overlay (screen-record deterrent, NOT burned-in): `frontend/src/components/shared/WatermarkOverlay.tsx:30-60` (`opacity: 0.18`, `fontSize: 11px`, 12 repeated diagonal spans), consumed at `frontend/src/pages/videos/VideoPlayerPage.tsx:542-545`.
- Document that `S.watermark_opacity` (0.02), `S.watermark_font_size` (8), `S.watermark_crf`, `S.watermark_preset` at `app/core/settings.py:1915-1918` are **defined but unused** — no consumer in `app/` references them (confirm via grep). These are the intended faint-forensic knobs that were never wired.
- Catalogue what "machine-detectable" means for each mark type (burned drawtext → OCR/template-match on extracted frames; player overlay → DOM only) and capture a baseline: at current params, can the forensic payload be OCR'd from a rendered frame?

**Acceptance Criteria**
- Written audit (in PR description or `docs/`) listing each mark, its file:line, current opacity/size/position, and whether it is "visible branding" vs "forensic".
- Confirmation that `watermark_opacity` / `watermark_font_size` / `watermark_crf` / `watermark_preset` are currently orphaned, with the list of call sites that *should* consume them.
- A baseline detectability note: current forensic opacity (0.02) and font size (8) tested against an OCR/template extractor on at least one rendered sample.

**Dependencies**
- None.

---

### WMK-002: Split the policy model into one visible mark + forensic mark
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Extend `WatermarkPolicy` in `app/contracts/watermark_policy.py:43-66` so a single policy expresses BOTH layers without breaking the existing flat fields:
  - Keep the current fields (`mode`, `position`, `opacity`, `margin_x/y`, `text_template`, `asset_uri`) as the **visible corner mark**.
  - Add an optional nested `forensic` sub-model: `enabled: bool`, `opacity: float` (default `S.watermark_opacity`=0.02), `font_size: int` (default `S.watermark_font_size`=8), `position` (default `bottom_right`), `repeat: int` (tile count, default 1), `payload_template` (default `{{tenant_id}}` carrying the WM payload).
- Default `forensic.opacity` and `forensic.font_size` to the existing-but-unused settings so the orphaned knobs finally drive behavior.
- Ensure `TenantWatermarkSettings` (`:69-72`) can carry a default forensic config alongside `default_policy`.
- Preserve backward compatibility: existing callers constructing `WatermarkPolicy(mode=..., opacity=...)` keep working (forensic defaults to disabled or to settings-driven defaults per WMK-005).

**Acceptance Criteria**
- New `forensic` sub-model added with validated ranges (`opacity` `ge=0,le=1`; `font_size` `ge=1`; `repeat` `ge=1`).
- All existing `WatermarkPolicy(...)` construction sites still validate (no required new field).
- `tests/test_watermark_policy_contract.py` extended to cover the new sub-model and its defaults.

**Dependencies**
- WMK-001.

---

## Milestone 2 — Visible Corner Mark

### WMK-003: Render exactly one prominent corner watermark
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- In the ABR builder `build_rendition_ffmpeg_args` (`app/services/ffmpeg_abr_pipeline.py:77-105`) and the shared `ffmpeg_watermark_filter` (`app/services/watermark_profile_renderers.py:51-75`), treat the visible mark as a single, clearly-readable corner element:
  - Use `watermark_policy.position` (configurable corner) and `watermark_policy.opacity` for the ONE visible mark.
  - Replace the hardcoded `fontsize=24` at `app/services/ffmpeg_abr_pipeline.py:89` with a configurable visible font size (new `WatermarkPolicy` field or setting), and add a subtle drop-shadow/box for legibility (`box=1:boxcolor=black@0.4` or `shadowx/shadowy`) so the single mark reads cleanly on any background.
  - Guarantee it is drawn once (no tiling) and clamped to the chosen corner via the existing `_overlay_xy` (`:17-24`).
- Keep the MediaLive path (`medialive_watermark_settings`, `app/services/watermark_profile_renderers.py:78-116`) consistent: one image/text mark at the configured corner.

**Acceptance Criteria**
- For `mode in {dynamic_text, static_image}` exactly one visible overlay is emitted at the configured corner.
- Visible mark opacity/position/font-size are read from policy (no hardcoded `fontsize=24`).
- `tests/test_watermark_profile_renderers.py` updated: asserts the generated filter string contains exactly one corner placement and the configured opacity/size.

**Dependencies**
- WMK-002.

---

### WMK-004: Configurable corner position & opacity surfaced to creators/admins
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Expose visible-mark position + opacity through the existing config surfaces so it is changeable without redeploy:
  - Tenant defaults via `app/routers/admin_tenant_watermark_assets.py` (`/v1/admin/tenants/{tenant_id}/watermark-default-profile`, `:97-106`) → `set_tenant_default_watermark_profile`.
  - Broadcast per-stream `watermark_asset` already exists at `app/routers/broadcast.py:84,291`; add position/opacity passthrough where a broadcast carries a visible mark.
- Frontend: surface the corner/opacity choice where the watermark asset is configured (e.g. broadcast profile UI at `frontend/src/pages/broadcast/BroadcastPage.tsx:427`), defaulting to the tenant default.

**Acceptance Criteria**
- An admin can set the visible corner (top_left/top_right/bottom_left/bottom_right) and opacity per tenant; new VOD renders honor it.
- A broadcast can override position/opacity for its visible mark.
- Invalid values rejected by the Pydantic validators added in WMK-002.

**Dependencies**
- WMK-002, WMK-003.

---

## Milestone 3 — Faint Forensic Marks

### WMK-005: Wire the forensic mark to faint, machine-readable params
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Make the per-viewer forensic render in `app/services/vod_watermark_download.py:133-150` (`_build_ffmpeg_filter`) and the main download path in `app/services/watermark_generator.py` use the faint forensic params:
  - Drive forensic `opacity` from `S.vod_watermark_download_opacity` (already 0.02 at `app/core/settings.py:1930`) AND finally consume `S.watermark_font_size` (8) and `S.watermark_crf` (18) which are presently orphaned (`:1916-1917`).
  - Lower the burned forensic font size from the hardcoded `fontsize=24` in `ffmpeg_watermark_filter` (`app/services/watermark_profile_renderers.py:68`) to `S.watermark_font_size` for the forensic layer.
  - Use a HIGH-quality encode for the forensic pass (`-crf {S.watermark_crf}`, `-preset {S.watermark_preset}`) so the low-alpha text survives compression (faint marks die under aggressive CRF). Wire `S.watermark_crf`/`S.watermark_preset` into the executor args.
- Add the forensic layer as a SECOND drawtext pass distinct from the visible corner mark (WMK-003), so visible and forensic are independent (different opacity/size/position).
- Optionally support `forensic.repeat` (tiled low-alpha payload) so the machine has multiple decode chances while a human sees nothing — keep alpha low enough that tiling stays imperceptible.

**Acceptance Criteria**
- Forensic mark opacity/font-size/CRF/preset all read from settings (no hardcoded `0.7`, `24`, or default CRF for the forensic pass).
- A rendered output contains BOTH the one visible corner mark AND the faint forensic payload, drawn by separate filter stages.
- `S.watermark_opacity`, `S.watermark_font_size`, `S.watermark_crf`, `S.watermark_preset` are now referenced by production code (grep proves they are no longer orphaned).
- Forensic payload still encodes/decodes via `build_watermark_payload`/`decode_watermark_payload` unchanged.

**Dependencies**
- WMK-002, WMK-003.

---

### WMK-006: Soften the player-side screen-record overlay
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Reduce `frontend/src/components/shared/WatermarkOverlay.tsx:40,49` so the live overlay is barely-there for the human eye but still captured on screen-record:
  - Lower container `opacity` from `0.18` toward ~0.06–0.08 and shrink `fontSize` from `11px`.
  - Keep the repeating diagonal tiling (`length: 12`, `:44`) so the per-session fingerprint (`sessionId`/`tenantId`, passed at `frontend/src/pages/videos/VideoPlayerPage.tsx:542-545`) appears multiple times for recovery from a screen capture.
  - Drive opacity/font-size/repeat from props/config (with sensible defaults) so they are tunable, mirroring the backend forensic knobs.

**Acceptance Criteria**
- Overlay default opacity/font noticeably reduced; the single visible corner mark (burned by WMK-003) is the prominent on-screen brand, not the overlay.
- Overlay remains `aria-hidden` + `pointer-events:none` and still tiles the fingerprint.
- Existing `data-testid="watermark-overlay"` retained for E2E.

**Dependencies**
- WMK-001.

---

## Milestone 4 — Config, Detectability & Docs

### WMK-007: Centralize watermark config + feature flags
**Type:** Chore  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Consolidate the tuning knobs in `app/core/settings.py:1915-1930` into a documented, env-overridable group and add the missing flags:
  - Existing: `WATERMARK_OPACITY`, `WATERMARK_FONT_SIZE`, `WATERMARK_CRF`, `WATERMARK_PRESET`, `VOD_WATERMARK_DOWNLOAD_OPACITY`.
  - Add: a visible-mark default opacity/font-size/position, a `WATERMARK_FORENSIC_REPEAT`, and a master `WATERMARK_FORENSIC_ENABLED` flag so forensic marking can be toggled without disabling the visible mark.
- Ensure dev defaults (faint forensic 0.02/8, prominent visible ~0.7) are correct out of the box and documented in `.env.local.example`.

**Acceptance Criteria**
- All visible + forensic params are env-configurable; defaults give one prominent corner mark + faint forensic mark with no env changes.
- `WATERMARK_FORENSIC_ENABLED=0` disables forensic embedding while leaving the visible mark intact (and vice versa).
- Settings documented in `.env.local.example`.

**Dependencies**
- WMK-002, WMK-005.

---

### WMK-008: Detectability verification (prove the faint mark is machine-readable)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Build a verification path that proves a machine can recover the forensic payload at the new faint params even though a human can't see it:
  - Add a test (e.g. `tests/test_watermark_detectability.py`) that renders a short clip with the forensic filter at `S.watermark_opacity`/`S.watermark_font_size`/`S.watermark_crf`, then recovers the payload and asserts `decode_watermark_payload(...)` round-trips the original `build_watermark_payload(user_id, ts)`.
  - For environments without real FFmpeg/OCR, gate the heavy path behind a flag and otherwise assert at the filter level: a known payload string is present in the generated filter and the alpha/size are within the machine-detectable band (alpha ≥ a documented floor; contrast-boost step recovers it).
  - Extend the existing extraction tooling: `app/routers/watermark.py:313-324` (`/internal/watermark/extract`, currently mock) and `app/routers/vod_watermark_download.py:125` (forensic extract) to perform a real frame-grab + contrast-amplify + OCR/template decode when given a rendered file, and use it as the detector in the test.
- Document a "detectability floor": the minimum opacity/font-size at which decode still succeeds, so future tuning can't drop the mark below readability.

**Acceptance Criteria**
- A test renders (or filter-level simulates) a faint forensic mark and successfully decodes the exact payload back via `decode_watermark_payload`.
- The detector lives behind `/internal/watermark/extract` (or the VOD forensic extract endpoint) and works on a real rendered sample when FFmpeg is available.
- A documented detectability floor (opacity/font-size) exists; CI guards that defaults stay above it.

**Dependencies**
- WMK-005, WMK-007.

---

### WMK-009: Docs & rollout
**Type:** Chore  
**Priority:** P2  
**Estimate:** 1 day

**Description**
- Update `docs/watermark-policy-spec.md` and `docs/VIDEO_ENCODING_WATERMARK_DRM_PLAN.md` to describe the two-layer model: one prominent configurable corner mark + faint machine-detectable forensic mark + softened player overlay.
- Document the config knobs (WMK-007), the detectability floor and verification approach (WMK-008), and how to extract a forensic payload from a leaked file.
- Note CLAUDE.md "common gotchas" entry summarizing the visible-vs-forensic split and that `watermark_opacity`/`watermark_font_size`/`watermark_crf`/`watermark_preset` are now wired (they were previously orphaned).

**Acceptance Criteria**
- `docs/watermark-policy-spec.md` reflects the new model and params.
- Extraction/forensic-recovery runbook documented.
- CLAUDE.md updated with a one-paragraph summary + file references.

**Dependencies**
- WMK-003, WMK-005, WMK-006, WMK-008.

---

## Suggested execution order
1. WMK-001 (audit) → WMK-002 (policy split)
2. WMK-003 (visible corner mark) → WMK-004 (config surface)
3. WMK-005 (faint forensic wiring) → WMK-006 (player overlay)
4. WMK-007 (config/flags) → WMK-008 (detectability) → WMK-009 (docs)

## Definition of Done (cross-ticket)
- Every output has exactly ONE prominent, configurable corner watermark.
- Forensic marks are faint enough to be near-imperceptible to humans yet decode reliably via `decode_watermark_payload`, proven by an automated detectability test.
- The previously-orphaned `watermark_opacity` / `watermark_font_size` / `watermark_crf` / `watermark_preset` settings are wired and env-configurable.
- All new/updated tests pass; visible + forensic layers are independently toggleable via feature flags.
