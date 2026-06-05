# GAP-0376: frontend UI for VOD bridge entirely absent

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-014 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/VOD-014.md`); see also `docs/tickets/writeups/VOD-014.md`

## Location
`frontend/src/pages/files/FileTable.tsx`

## Problem / Impact
spec §4.1-4.3 and §4 Phase 2 require: vod_* fields on FileEntry type, importFileToVod/getVodBridgeStatus API functions in vod.ts, "Watch" and "Send to VOD" actions in FileTable.tsx, import dialog in FilesPage.tsx, and "In Files" badge in VideosPage.tsx; none of these exist

## Fix
add FileEntry.vod_* fields to types.ts, add bridge API functions, add VOD context menu items to FileTable.tsx, and add "In Files" badge to video cards

## Notes
This gap was identified by the second-pass as-built review of VOD-014. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
