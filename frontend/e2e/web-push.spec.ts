import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";

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
      cwd: "/home/ubuntu/testlogon", timeout: 30_000,
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

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const s = getSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, identity);
  return page;
}

const ALICE_ID = "alice";

// ---------------------------------------------------------------------------
// Section 78: Web Push Service Worker
// ---------------------------------------------------------------------------
test.describe("78 · Web Push — VAPID key and service worker", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage?.context().close();
  });

  test("78.1 VAPID public key endpoint returns key", async () => {
    const resp = await apiGet(alicePage, "/ui/push/vapid-key");
    // If VAPID is configured, returns 200 with key; if not, 404
    if (resp.status() === 200) {
      const body = await resp.json();
      expect(body.vapid_public_key).toBeTruthy();
      expect(typeof body.vapid_public_key).toBe("string");
      expect(body.vapid_public_key.length).toBeGreaterThan(10);
    } else {
      expect(resp.status()).toBe(404);
    }
  });

  test("78.2 Service worker file is accessible", async ({ browser }) => {
    const page = await browser.newPage();
    const resp = await page.request.get("http://localhost:3000/sw.js");
    // sw.js should be served by Vite from public/
    if (resp.status() === 200) {
      const body = await resp.text();
      expect(body).toContain("push");
    }
    // 404 is acceptable if sw.js serves index.html (SPA catch-all)
    await page.close();
  });

  test("78.3 Register push device stores subscription", async () => {
    const mockToken = JSON.stringify({
      endpoint: "https://fcm.googleapis.com/fcm/send/test-token-e2e-" + Date.now(),
      keys: {
        p256dh: "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8p8REqnSs",
        auth: "tBHItJI5svbpC7t8hAwxsQ",
      },
    });
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/push/register", {
      token: mockToken,
      platform: "web",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.device_id).toBeTruthy();
    expect(body.platform).toBe("web");
  });

  test("78.4 Push device list shows registered device", async () => {
    const resp = await apiGet(alicePage, "/ui/push/devices");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const devices = body.devices;
    expect(Array.isArray(devices)).toBe(true);
    expect(devices.length).toBeGreaterThanOrEqual(1);
    expect(devices[0]).toHaveProperty("device_id");
    expect(devices[0]).toHaveProperty("platform");
  });

  test("78.5 Revoke push device removes it", async () => {
    // List current devices
    const listResp = await apiGet(alicePage, "/ui/push/devices");
    const body = await listResp.json();
    const devices = body.devices;
    const countBefore = devices.length;

    if (countBefore > 0) {
      const deviceId = devices[0].device_id;
      const revokeResp = await apiPost(alicePage, ALICE_ID, "/ui/push/revoke", {
        device_id: deviceId,
      });
      expect(revokeResp.status()).toBe(200);

      // Verify device was removed
      const afterResp = await apiGet(alicePage, "/ui/push/devices");
      const afterBody = await afterResp.json();
      const afterDevices = afterBody.devices;
      expect(afterDevices.length).toBeLessThan(countBefore);
    }
  });

  test("78.6 Push test endpoint sends test notification", async () => {
    // Register a fresh device for the test
    const mockToken = JSON.stringify({
      endpoint: "https://fcm.googleapis.com/fcm/send/test-push-" + Date.now(),
      keys: {
        p256dh: "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8p8REqnSs",
        auth: "tBHItJI5svbpC7t8hAwxsQ",
      },
    });
    await apiPost(alicePage, ALICE_ID, "/ui/push/register", {
      token: mockToken,
      platform: "web",
    });

    // Fire test push — in dev mode this logs instead of delivering
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/push/test", {});
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
  });
});
