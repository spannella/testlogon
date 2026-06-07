/**
 * Regression test for GAP-0376 (frontend UI for the VOD ↔ File Manager bridge
 * was entirely absent).
 *
 * The bridge backend (`app/routers/vod_bridge.py`) already existed, but the
 * frontend had no `vod_*` fields on `FileEntry`, no `importFileToVod` /
 * `getVodBridgeStatus` API wrappers, no "Send to VOD"/"Watch" context-menu
 * actions in the file table, and no "In Files" badge on video cards.
 *
 * A full UI interaction test requires a seeded video file + the live dev stack;
 * the robust, hermetic regression here is a SOURCE-LEVEL assertion (mirrors the
 * readFileSync-based specs already in this folder, e.g. media-player-drm.spec.ts):
 * read the changed source files and assert the new wiring is present.
 *
 * Fails-before: none of these symbols existed.
 * Passes-after: all of them are present.
 */
import { test, expect } from "@playwright/test";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";

const here = dirname(fileURLToPath(import.meta.url));
const read = (rel: string) => readFileSync(resolve(here, rel), "utf-8");

const TYPES = read("../src/api/types.ts");
const VOD = read("../src/api/endpoints/vod.ts");
const FILE_TABLE = read("../src/pages/files/FileTable.tsx");
const FILES_PAGE = read("../src/pages/files/FilesPage.tsx");
const VIDEOS_PAGE = read("../src/pages/videos/VideosPage.tsx");

test.describe("GAP-0376 — VOD bridge frontend wiring", () => {
  test("FileEntry carries vod_* bridge fields", () => {
    expect(TYPES).toMatch(/vod_video_id\??:\s*string\s*\|\s*null/);
    expect(TYPES).toMatch(/vod_status\??:\s*string\s*\|\s*null/);
    expect(TYPES).toContain("vod_linked");
    expect(TYPES).toContain("vod_imported_at");
  });

  test("vod.ts exports importFileToVod and getVodBridgeStatus wrappers", () => {
    expect(VOD).toMatch(/export const importFileToVod\b/);
    expect(VOD).toMatch(/export const getVodBridgeStatus\b/);
    // hit the real backend endpoints
    expect(VOD).toContain("/ui/vod-bridge/import");
    expect(VOD).toContain("/ui/vod-bridge/status/");
    // request/response types
    expect(VOD).toMatch(/interface\s+VodImportToVodIn\b/);
    expect(VOD).toMatch(/interface\s+VodBridgeStatusOut\b/);
  });

  test("FileTable exposes Send-to-VOD and Watch actions for video files", () => {
    expect(FILE_TABLE).toMatch(/onSendToVod\??:/);
    expect(FILE_TABLE).toMatch(/onWatchVod\??:/);
    expect(FILE_TABLE).toContain("Send to VOD");
    expect(FILE_TABLE).toContain("Watch");
    // video-only gating
    expect(FILE_TABLE).toMatch(/video\//);
    // icons imported
    expect(FILE_TABLE).toMatch(/Video,\s*Play|Video,|, Video|Play/);
  });

  test("FilesPage wires the import-to-VOD dialog + mutation", () => {
    expect(FILES_PAGE).toContain("importFileToVod");
    expect(FILES_PAGE).toMatch(/onSendToVod=/);
    expect(FILES_PAGE).toMatch(/onWatchVod=/);
    expect(FILES_PAGE).toContain("Send to VOD");
    // navigates to the player on Watch
    expect(FILES_PAGE).toMatch(/\/videos\/\$\{?/);
  });

  test("VideosPage shows an In Files badge for file-bridged videos", () => {
    expect(VIDEOS_PAGE).toContain("In Files");
    expect(VIDEOS_PAGE).toContain("source_file_node_id");
  });
});
