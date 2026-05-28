/**
 * VOD-021: Video Subtitles and Closed Captions
 *
 * Sections 80-83: Subtitle upload API, subtitle list/delete API,
 * SRT-to-VTT conversion, subtitle sanitization.
 *
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: alice (owner), bob (non-owner)
 */
import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const TS = Date.now();

// ─── Session helpers ─────────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function newPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(getSessions()[identity].cookies);
  return page;
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiPost(page: Page, id: string, path: string, body?: unknown) {
  const s = getSessions()[id];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPatch(page: Page, id: string, path: string, body: unknown) {
  const s = getSessions()[id];
  return page.request.patch(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiDelete(page: Page, id: string, path: string) {
  const s = getSessions()[id];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

// Multipart upload helper
async function apiUploadSubtitle(
  page: Page,
  id: string,
  videoId: string,
  opts: {
    fileName: string;
    content: string;
    language: string;
    label: string;
    isDefault?: boolean;
    contentType?: string;
  },
) {
  const s = getSessions()[id];
  const resp = await page.request.post(`${BASE}/ui/videos/${videoId}/subtitles`, {
    headers: { "x-csrf-token": s.csrf_token },
    multipart: {
      file: {
        name: opts.fileName,
        mimeType: opts.contentType || "text/vtt",
        buffer: Buffer.from(opts.content, "utf-8"),
      },
      language: opts.language,
      label: opts.label,
      is_default: String(opts.isDefault ?? false),
    },
  });
  return resp;
}

// ─── Seed video ──────────────────────────────────────────────────────────────

const ALICE_VIDEO_ID = `v_sub_${TS}`;
const ALICE_SUB = () => getSessions()["alice"].user_sub;

function seedVideo(videoId: string, ownerUserId: string): void {
  const now = Math.floor(Date.now() / 1000);
  const script = `
import sys, os
sys.path.insert(0, '/home/ubuntu/testlogon')
os.environ.setdefault('DEV_MODE', '1')
os.environ.setdefault('DDB_ENDPOINT_URL', 'http://localhost:8001')
os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
import boto3
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1')
table = ddb.Table('VideoMetadata')
table.put_item(Item={
    'video_id': '${videoId}',
    'owner_user_id': '${ownerUserId}',
    'title': 'Subtitle Test Video ${TS}',
    'status': 'published',
    'visibility': 'public',
    'created_at': ${now},
    'updated_at': ${now},
    'source_type': 'upload',
    'published_at': ${now},
})
`;
  execSync(`/home/ubuntu/testlogon/.venv/bin/python3 -c "${script.replace(/"/g, '\\"')}"`, {
    cwd: "/home/ubuntu/testlogon",
    timeout: 10_000,
  });
}

function deleteVideo(videoId: string): void {
  const script = `
import sys, os
os.environ.setdefault('DDB_ENDPOINT_URL', 'http://localhost:8001')
os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
import boto3
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1')
table = ddb.Table('VideoMetadata')
table.delete_item(Key={'video_id': '${videoId}'})
`;
  try {
    execSync(`/home/ubuntu/testlogon/.venv/bin/python3 -c "${script.replace(/"/g, '\\"')}"`, {
      cwd: "/home/ubuntu/testlogon",
      timeout: 10_000,
    });
  } catch { /* ignore cleanup errors */ }
}

// ─── VTT content samples ────────────────────────────────────────────────────

const VALID_VTT = `WEBVTT

00:00:01.000 --> 00:00:04.000
Hello, welcome to the tutorial.

00:00:05.200 --> 00:00:08.800
Today we will cover video editing basics.
`;

const VALID_SRT = `1
00:00:01,500 --> 00:00:04,000
Hello from SRT format.

2
00:00:05,200 --> 00:00:08,800
This is the second cue.
`;

const VTT_WITH_SCRIPT = `WEBVTT

00:00:01.000 --> 00:00:04.000
Hello <script>alert(1)</script>world.

00:00:05.000 --> 00:00:08.000
<b onclick="alert(1)">bold text</b> here.
`;

const VTT_WITH_ALLOWED_TAGS = `WEBVTT

00:00:01.000 --> 00:00:04.000
<b>Bold</b> and <i>italic</i> and <v Speaker>voiced</v>.

00:00:05.000 --> 00:00:08.000
Normal text cue.
`;

// ─── Tests ──────────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;

test.describe("VOD-021: Video Subtitles", () => {
  test.beforeAll(async ({ browser }) => {
    // Ensure sessions are loaded
    getSessions();

    // Seed the test video
    seedVideo(ALICE_VIDEO_ID, ALICE_SUB());

    alicePage = await newPage(browser, "alice");
    bobPage = await newPage(browser, "bob");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
    deleteVideo(ALICE_VIDEO_ID);
  });

  // ─── Section 80: Subtitle Upload API ──────────────────────────────────────

  test.describe("Section 80: Subtitle Upload API", () => {
    test("80.1 Upload VTT subtitle track", async () => {
      const resp = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "english.vtt",
        content: VALID_VTT,
        language: "en",
        label: "English",
      });
      expect(resp.status()).toBe(201);
      const body = await resp.json();
      expect(body.track_id).toMatch(/^st_/);
      expect(body.format).toBe("vtt");
      expect(body.language).toBe("en");
      expect(body.label).toBe("English");
      expect(body.vtt_url).toBeTruthy();
    });

    test("80.2 Upload SRT subtitle track (auto-converts to VTT)", async () => {
      const resp = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "spanish.srt",
        content: VALID_SRT,
        language: "es",
        label: "Espanol",
      });
      expect(resp.status()).toBe(201);
      const body = await resp.json();
      expect(body.format).toBe("vtt");
      expect(body.language).toBe("es");

      // Verify the VTT URL returns valid VTT content
      const vttResp = await alicePage.request.get(`${BASE}${body.vtt_url}`);
      expect(vttResp.status()).toBe(200);
      const vttText = await vttResp.text();
      expect(vttText).toContain("WEBVTT");
      // SRT comma should be converted to period
      expect(vttText).toContain("00:00:01.500");
      expect(vttText).not.toContain(",500");
    });

    test("80.3 List subtitle tracks", async () => {
      const resp = await apiGet(alicePage, `/ui/videos/${ALICE_VIDEO_ID}/subtitles`);
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      expect(body.tracks.length).toBeGreaterThanOrEqual(2);
      for (const t of body.tracks) {
        expect(t.vtt_url).toBeTruthy();
        expect(t.track_id).toMatch(/^st_/);
      }
    });

    test("80.4 Upload with is_default replaces previous default", async () => {
      // Upload a default track
      const resp1 = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "french.vtt",
        content: VALID_VTT,
        language: "fr",
        label: "Francais",
        isDefault: true,
      });
      expect(resp1.status()).toBe(201);
      const track1 = await resp1.json();
      expect(track1.is_default).toBe(true);

      // Upload another default track
      const resp2 = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "german.vtt",
        content: VALID_VTT,
        language: "de",
        label: "Deutsch",
        isDefault: true,
      });
      expect(resp2.status()).toBe(201);
      const track2 = await resp2.json();
      expect(track2.is_default).toBe(true);

      // Verify: only the newest default should be true
      const listResp = await apiGet(alicePage, `/ui/videos/${ALICE_VIDEO_ID}/subtitles`);
      const list = await listResp.json();
      const defaults = list.tracks.filter((t: any) => t.is_default);
      expect(defaults.length).toBe(1);
      expect(defaults[0].track_id).toBe(track2.track_id);
    });

    test("80.5 Delete subtitle track", async () => {
      // List tracks first
      const listBefore = await apiGet(alicePage, `/ui/videos/${ALICE_VIDEO_ID}/subtitles`);
      const before = await listBefore.json();
      const countBefore = before.tracks.length;
      const trackToDelete = before.tracks[before.tracks.length - 1]; // delete last

      const resp = await apiDelete(alicePage, "alice", `/ui/videos/${ALICE_VIDEO_ID}/subtitles/${trackToDelete.track_id}`);
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      expect(body.ok).toBe(true);

      // Verify it's gone
      const listAfter = await apiGet(alicePage, `/ui/videos/${ALICE_VIDEO_ID}/subtitles`);
      const after = await listAfter.json();
      expect(after.tracks.length).toBe(countBefore - 1);
      expect(after.tracks.find((t: any) => t.track_id === trackToDelete.track_id)).toBeUndefined();
    });

    test("80.6 Non-owner cannot upload subtitles", async () => {
      const resp = await apiUploadSubtitle(bobPage, "bob", ALICE_VIDEO_ID, {
        fileName: "evil.vtt",
        content: VALID_VTT,
        language: "en",
        label: "Evil",
      });
      expect(resp.status()).toBe(403);
    });

    test("80.7 Update subtitle track label and default", async () => {
      // Pick the first track
      const listResp = await apiGet(alicePage, `/ui/videos/${ALICE_VIDEO_ID}/subtitles`);
      const list = await listResp.json();
      const track = list.tracks[0];

      const resp = await apiPatch(alicePage, "alice", `/ui/videos/${ALICE_VIDEO_ID}/subtitles/${track.track_id}`, {
        label: "English (SDH)",
        is_default: true,
      });
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      expect(body.label).toBe("English (SDH)");
      expect(body.is_default).toBe(true);

      // Verify persistence
      const listAfter = await apiGet(alicePage, `/ui/videos/${ALICE_VIDEO_ID}/subtitles`);
      const afterList = await listAfter.json();
      const updated = afterList.tracks.find((t: any) => t.track_id === track.track_id);
      expect(updated.label).toBe("English (SDH)");
    });
  });

  // ─── Section 81: Subtitle Validation API ──────────────────────────────────

  test.describe("Section 81: Subtitle Validation API", () => {
    test("81.1 Upload invalid VTT (no WEBVTT header)", async () => {
      const resp = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "bad.vtt",
        content: "This is not a VTT file\n00:00:01.000 --> 00:00:02.000\nHello",
        language: "en",
        label: "Bad",
      });
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(body.detail).toContain("Missing WEBVTT header");
    });

    test("81.2 Upload VTT with no cues", async () => {
      const resp = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "empty.vtt",
        content: "WEBVTT\n\n",
        language: "en",
        label: "Empty",
      });
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(body.detail).toContain("No valid cues found");
    });

    test("81.3 Upload file exceeding size limit", async () => {
      // Create content > 512KB
      const bigContent = "WEBVTT\n\n" + "00:00:01.000 --> 00:00:02.000\n" + "x".repeat(600 * 1024) + "\n";
      const resp = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "big.vtt",
        content: bigContent,
        language: "en",
        label: "Big",
      });
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(body.detail).toContain("exceeds maximum size");
    });

    test("81.4 Upload unsupported format (.txt)", async () => {
      const resp = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "readme.txt",
        content: "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nHello",
        language: "en",
        label: "Txt",
      });
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(body.detail).toContain("unsupported subtitle format");
    });

    test("81.5 Upload empty file", async () => {
      const resp = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "empty.vtt",
        content: "",
        language: "en",
        label: "Empty",
      });
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(body.detail).toContain("subtitle file is empty");
    });

    test("81.6 Upload invalid language code", async () => {
      const resp = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "bad_lang.vtt",
        content: VALID_VTT,
        language: "!!!",
        label: "Bad Lang",
      });
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(body.detail).toContain("invalid language code");
    });
  });

  // ─── Section 82: SRT-to-VTT Conversion ───────────────────────────────────

  test.describe("Section 82: SRT-to-VTT Conversion", () => {
    test("82.1 Valid SRT conversion preserves timestamp format", async () => {
      const srt = `1
00:01:02,500 --> 00:01:05,300
First cue with comma timestamps.

2
00:02:10,100 --> 00:02:15,900
Second cue.
`;
      const resp = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "convert_test.srt",
        content: srt,
        language: "pt",
        label: "Portuguese",
      });
      expect(resp.status()).toBe(201);
      const body = await resp.json();

      // Fetch the VTT content
      const vttResp = await alicePage.request.get(`${BASE}${body.vtt_url}`);
      const vtt = await vttResp.text();
      expect(vtt).toContain("WEBVTT");
      expect(vtt).toContain("00:01:02.500 --> 00:01:05.300");
      expect(vtt).toContain("00:02:10.100 --> 00:02:15.900");
    });

    test("82.2 Multi-line cues preserved in conversion", async () => {
      const srt = `1
00:00:01,000 --> 00:00:04,000
First line of cue
Second line of cue
`;
      const resp = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "multiline.srt",
        content: srt,
        language: "ja",
        label: "Japanese",
      });
      expect(resp.status()).toBe(201);
      const body = await resp.json();

      const vttResp = await alicePage.request.get(`${BASE}${body.vtt_url}`);
      const vtt = await vttResp.text();
      expect(vtt).toContain("First line of cue");
      expect(vtt).toContain("Second line of cue");
    });

    test("82.3 Sequence numbers stripped from SRT", async () => {
      const srt = `1
00:00:01,000 --> 00:00:02,000
Cue one.

2
00:00:03,000 --> 00:00:04,000
Cue two.

3
00:00:05,000 --> 00:00:06,000
Cue three.
`;
      const resp = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "seqnums.srt",
        content: srt,
        language: "ko",
        label: "Korean",
      });
      expect(resp.status()).toBe(201);
      const body = await resp.json();

      const vttResp = await alicePage.request.get(`${BASE}${body.vtt_url}`);
      const vtt = await vttResp.text();
      // Lines that are only digits (SRT sequence numbers) should be removed
      const lines = vtt.split("\n").map((l: string) => l.trim()).filter(Boolean);
      const digitOnlyLines = lines.filter((l: string) => /^\d+$/.test(l));
      expect(digitOnlyLines.length).toBe(0);
    });
  });

  // ─── Section 83: Subtitle Content Sanitization ────────────────────────────

  test.describe("Section 83: Subtitle Content Sanitization", () => {
    test("83.1 Script tags stripped from uploaded VTT", async () => {
      const resp = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "xss.vtt",
        content: VTT_WITH_SCRIPT,
        language: "ar",
        label: "Arabic",
      });
      expect(resp.status()).toBe(201);
      const body = await resp.json();

      const vttResp = await alicePage.request.get(`${BASE}${body.vtt_url}`);
      const vtt = await vttResp.text();
      expect(vtt).not.toContain("<script>");
      expect(vtt).not.toContain("</script>");
      expect(vtt).toContain("world");
    });

    test("83.2 Event handlers stripped from uploaded VTT", async () => {
      const resp = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "events.vtt",
        content: VTT_WITH_SCRIPT,
        language: "hi",
        label: "Hindi",
      });
      expect(resp.status()).toBe(201);
      const body = await resp.json();

      const vttResp = await alicePage.request.get(`${BASE}${body.vtt_url}`);
      const vtt = await vttResp.text();
      expect(vtt).toContain("<b");
      expect(vtt).not.toContain("onclick");
    });

    test("83.3 Allowed tags preserved in uploaded VTT", async () => {
      const resp = await apiUploadSubtitle(alicePage, "alice", ALICE_VIDEO_ID, {
        fileName: "allowed.vtt",
        content: VTT_WITH_ALLOWED_TAGS,
        language: "ru",
        label: "Russian",
      });
      expect(resp.status()).toBe(201);
      const body = await resp.json();

      const vttResp = await alicePage.request.get(`${BASE}${body.vtt_url}`);
      const vtt = await vttResp.text();
      expect(vtt).toContain("<b>");
      expect(vtt).toContain("<i>");
      expect(vtt).toContain("<v Speaker>");
    });
  });
});
