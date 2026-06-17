import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as zlib from "zlib";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const API = "http://localhost:8000";
const TS = Date.now();

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
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT, timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, identity);
  return page;
}

const ALICE_ID = "alice";

// ─── Helper: build a minimal valid PNG ──────────────────────────────────────

function crc32(buf: Buffer): number {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xEDB88320 : crc >>> 1;
    }
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function makePngChunk(type: string, data: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, "ascii");
  const combined = Buffer.concat([typeBuf, data]);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(combined), 0);
  return Buffer.concat([len, typeBuf, data, crcBuf]);
}

function createTestPng(width: number, height: number): Buffer {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;   // bit depth
  ihdr[9] = 2;   // RGB
  ihdr[10] = 0;  // compression
  ihdr[11] = 0;  // filter
  ihdr[12] = 0;  // interlace

  const rows: Buffer[] = [];
  for (let y = 0; y < height; y++) {
    const row = Buffer.alloc(1 + width * 3);
    row[0] = 0; // filter: none
    for (let x = 0; x < width; x++) {
      row[1 + x * 3] = (x * 17 + y * 31) % 256;
      row[2 + x * 3] = (x * 23 + y * 37) % 256;
      row[3 + x * 3] = (x * 29 + y * 41) % 256;
    }
    rows.push(row);
  }
  const compressed = zlib.deflateSync(Buffer.concat(rows));

  return Buffer.concat([
    signature,
    makePngChunk("IHDR", ihdr),
    makePngChunk("IDAT", compressed),
    makePngChunk("IEND", Buffer.alloc(0)),
  ]);
}

// ─── PLATFORM-004: Image Optimization ───────────────────────────────────────

test.describe("82 · Image Optimization — Variant generation", () => {
  let alicePage: Page;
  let uploadedVariants: Record<string, { url: string; width: number; height: number; size_bytes: number }>;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage?.context().close();
  });

  test("82.1 Upload image generates variant metadata", async () => {
    const session = getSessions()[ALICE_ID];
    const pngBuffer = createTestPng(1000, 800);

    const resp = await alicePage.request.post(`${API}/uploads/image`, {
      headers: { "x-csrf-token": session.csrf_token },
      multipart: {
        file: {
          name: `opt_test_${TS}.png`,
          mimeType: "image/png",
          buffer: pngBuffer,
        },
      },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.url).toBeTruthy();
    expect(body.s3_key).toBeTruthy();
    expect(body.variants).toBeTruthy();

    uploadedVariants = body.variants;
    // "sm" variant is always generated
    expect(uploadedVariants).toHaveProperty("sm");
  });

  test("82.2 SM variant has correct dimensions (max 480px)", async () => {
    const sm = uploadedVariants.sm;
    expect(sm).toBeTruthy();
    expect(sm.width).toBeLessThanOrEqual(480);
    expect(sm.height).toBeLessThanOrEqual(480);
    expect(sm.size_bytes).toBeGreaterThan(0);
    expect(sm.url).toBeTruthy();
  });

  test("82.3 WebP variants are served with correct content type", async () => {
    const smUrl = uploadedVariants.sm.url;
    const resp = await alicePage.request.get(`${API}${smUrl}`);
    expect(resp.status()).toBe(200);
    const contentType = resp.headers()["content-type"] || "";
    expect(contentType).toContain("image/webp");
  });

  test("82.4 Variant URLs serve with immutable cache headers", async () => {
    const smUrl = uploadedVariants.sm.url;
    const resp = await alicePage.request.get(`${API}${smUrl}`);
    expect(resp.status()).toBe(200);
    const cacheControl = resp.headers()["cache-control"] || "";
    expect(cacheControl).toContain("immutable");
    expect(cacheControl).toContain("max-age=31536000");
  });

  test("82.5 Non-image file upload is rejected", async () => {
    const session = getSessions()[ALICE_ID];
    const textBuffer = Buffer.from("This is not an image file.");
    const resp = await alicePage.request.post(`${API}/uploads/image`, {
      headers: { "x-csrf-token": session.csrf_token },
      multipart: {
        file: {
          name: `not_image_${TS}.txt`,
          mimeType: "text/plain",
          buffer: textBuffer,
        },
      },
    });
    expect(resp.status()).toBe(400);
  });

  test("82.6 Original image URL serves with short-lived cache", async () => {
    const session = getSessions()[ALICE_ID];
    // Upload another image and check original cache header
    const pngBuffer = createTestPng(200, 150);
    const resp = await alicePage.request.post(`${API}/uploads/image`, {
      headers: { "x-csrf-token": session.csrf_token },
      multipart: {
        file: {
          name: `cache_test_${TS}.png`,
          mimeType: "image/png",
          buffer: pngBuffer,
        },
      },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();

    // Fetch original (not a variant)
    const origResp = await alicePage.request.get(`${API}${body.url}`);
    expect(origResp.status()).toBe(200);
    const cacheControl = origResp.headers()["cache-control"] || "";
    // Original should NOT have immutable
    expect(cacheControl).not.toContain("immutable");
  });
});

test.describe("82 · Image Optimization — ResponsiveImage UI", () => {
  test("82.7 Feed page renders without JS errors (ResponsiveImage loaded)", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE_ID);
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));

    await page.goto("/feed");
    await page.waitForLoadState("domcontentloaded");
    await page.waitForTimeout(1500);

    expect(errors.length).toBe(0);
    await page.context().close();
  });
});

// ─── PLATFORM-004: On-demand optimization router (/ui/images/optimize) ───────

test.describe("83 · Image Optimization — On-demand optimization API", () => {
  let alicePage: Page;
  let sourceKey: string;
  let optimizationId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
    // Upload a source image to optimize on demand.
    const session = getSessions()[ALICE_ID];
    const pngBuffer = createTestPng(1200, 900);
    const resp = await alicePage.request.post(`${API}/uploads/image`, {
      headers: { "x-csrf-token": session.csrf_token },
      multipart: {
        file: { name: `ondemand_${TS}.png`, mimeType: "image/png", buffer: pngBuffer },
      },
    });
    expect(resp.status()).toBe(200);
    sourceKey = (await resp.json()).s3_key;
  });

  test.afterAll(async () => {
    await alicePage?.context().close();
  });

  test("83.1 Request optimization returns a record with variants", async () => {
    const session = getSessions()[ALICE_ID];
    const resp = await alicePage.request.post(`${API}/ui/images/optimize`, {
      headers: { "x-csrf-token": session.csrf_token },
      data: { source_key: sourceKey, format: "webp" },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.optimization_id).toBeTruthy();
    expect(body.output_format).toBe("webp");
    expect(body.variants).toBeTruthy();
    expect(body.variants).toHaveProperty("sm");
    expect(body.variants.sm.width).toBeLessThanOrEqual(480);
    expect(body.variants.sm.format).toBe("webp");
    optimizationId = body.optimization_id;
  });

  test("83.2 Served variant is fetchable as WebP", async () => {
    const session = getSessions()[ALICE_ID];
    const resp = await alicePage.request.post(`${API}/ui/images/optimize`, {
      headers: { "x-csrf-token": session.csrf_token },
      data: { source_key: sourceKey },
    });
    const body = await resp.json();
    const smUrl = body.variants.sm.url;
    const served = await alicePage.request.get(`${API}${smUrl}`);
    expect(served.status()).toBe(200);
    expect(served.headers()["content-type"] || "").toContain("image/webp");
  });

  test("83.3 Repeat request returns a cached record", async () => {
    const session = getSessions()[ALICE_ID];
    const resp = await alicePage.request.post(`${API}/ui/images/optimize`, {
      headers: { "x-csrf-token": session.csrf_token },
      data: { source_key: sourceKey, use_cache: true },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.cached).toBe(true);
  });

  test("83.4 Fetch persisted optimization record by id", async () => {
    expect(optimizationId).toBeTruthy();
    const resp = await alicePage.request.get(`${API}/ui/images/optimize/${optimizationId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.optimization_id).toBe(optimizationId);
    expect(body.variants).toHaveProperty("sm");
  });

  test("83.5 Missing source_key/source_url returns 422", async () => {
    const session = getSessions()[ALICE_ID];
    const resp = await alicePage.request.post(`${API}/ui/images/optimize`, {
      headers: { "x-csrf-token": session.csrf_token },
      data: { format: "webp" },
    });
    expect(resp.status()).toBe(422);
  });

  test("83.6 Invalid format returns 422", async () => {
    const session = getSessions()[ALICE_ID];
    const resp = await alicePage.request.post(`${API}/ui/images/optimize`, {
      headers: { "x-csrf-token": session.csrf_token },
      data: { source_key: sourceKey, format: "gif" },
    });
    expect(resp.status()).toBe(422);
  });

  test("83.7 Optimizing a non-existent source returns 404", async () => {
    const session = getSessions()[ALICE_ID];
    const resp = await alicePage.request.post(`${API}/ui/images/optimize`, {
      headers: { "x-csrf-token": session.csrf_token },
      data: { source_key: `uploads/${ALICE_ID}/does-not-exist-${TS}/missing.png` },
    });
    expect(resp.status()).toBe(404);
  });

  test("83.8 Fetching an unknown optimization id returns 404", async () => {
    const resp = await alicePage.request.get(`${API}/ui/images/optimize/nonexistent${TS}`);
    expect(resp.status()).toBe(404);
  });
});
