/**
 * E2E tests for Kubernetes Container Launcher (INFRA-004).
 *
 * Sections:
 *   253 — Image & Preset API (3 tests)
 *   254 — Pod Launch & Lifecycle API (6 tests)
 *   255 — Pod Limits & TTL (5 tests)
 *   256 — Containers UI (4 tests)
 *
 * Auth: Alice & Bob session cookies (from e2e_admin_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = BASE;
const ALICE_ID = "alice";
const BOB_ID = "bob";
const TS = Date.now();

// ─── Session bootstrap ───────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    httpOnly: boolean;
    secure: boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

function csrfHeaders(identity: string) {
  return { "x-csrf-token": getSessions()[identity].csrf_token };
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  return page.request.post(`${API}${path}`, {
    headers: csrfHeaders(identity),
    data: body,
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${API}${path}`;
  if (params) {
    url += "?" + new URLSearchParams(params).toString();
  }
  return page.request.get(url);
}

async function apiDelete(page: Page, identity: string, path: string) {
  return page.request.delete(`${API}${path}`, {
    headers: csrfHeaders(identity),
  });
}

// ─── Test state ──────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;

// ─────────────────────────────────────────────────────────────────────────────
// Section 253: Image & Preset API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("253 — Image & Preset API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("253.1 List images returns allowlist", async () => {
    const resp = await apiGet(alicePage, "/ui/remote/k8s/images");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.images).toBeDefined();
    expect(data.images.length).toBe(3);
    for (const img of data.images) {
      expect(img.image).toBeTruthy();
      expect(img.display_name).toBeTruthy();
      expect(img.os_type).toBeTruthy();
      expect(img.username).toBeTruthy();
    }
  });

  test("253.2 List presets returns resource options", async () => {
    const resp = await apiGet(alicePage, "/ui/remote/k8s/presets");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.presets).toBeDefined();
    expect(data.presets.length).toBe(4);
    for (const p of data.presets) {
      expect(p.preset).toBeTruthy();
      expect(p.cpu_millicores).toBeGreaterThan(0);
      expect(p.memory_mb).toBeGreaterThan(0);
      expect(p.cost_cents_per_min).toBeGreaterThan(0);
    }
  });

  test("253.3 Unknown image on launch returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/k8s/launch", {
      label: "bad-image-test",
      image: "not-an-image",
      preset: "small",
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail).toContain("not in allowed image list");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 254: Pod Launch & Lifecycle API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("254 — Pod Launch & Lifecycle API", () => {
  let podId: string;
  const launchedIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    for (const id of launchedIds) {
      try {
        await apiDelete(alicePage, ALICE_ID, `/ui/remote/k8s/pods/${id}`);
      } catch (_) { /* ignore */ }
    }
    await alicePage.close();
  });

  test("254.1 Alice launches an ubuntu-ssh pod", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/k8s/launch", {
      label: `e2e-k8s-${TS}`,
      image: "ubuntu-ssh",
      preset: "medium",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.status).toBe("running");
    expect(data.pod_id).toBeTruthy();
    expect(data.pod_ip).toBeTruthy();
    expect(data.service_hostname).toBeTruthy();
    expect(data.image_display_name).toBe("Ubuntu SSH");
    expect(data.preset).toBe("medium");
    expect(data.cpu_millicores).toBe(500);
    expect(data.memory_mb).toBe(512);
    expect(data.expires_at).toBeGreaterThan(data.created_at);
    podId = data.pod_id;
    launchedIds.push(podId);
  });

  test("254.2 Get pod returns the launched pod", async () => {
    const resp = await apiGet(alicePage, `/ui/remote/k8s/pods/${podId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.pod_id).toBe(podId);
    expect(data.status).toBe("running");
    expect(data.label).toBe(`e2e-k8s-${TS}`);
  });

  test("254.3 Alice terminates a pod", async () => {
    const resp = await apiDelete(alicePage, ALICE_ID, `/ui/remote/k8s/pods/${podId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("terminated");
    expect(data.terminated_at).toBeGreaterThan(0);
  });

  test("254.4 Pod logs are available", async () => {
    const launchResp = await apiPost(alicePage, ALICE_ID, "/ui/remote/k8s/launch", {
      label: `logs-test-${TS}`,
      image: "dev-workspace",
      preset: "small",
    });
    expect(launchResp.status()).toBe(201);
    const pod = await launchResp.json();
    launchedIds.push(pod.pod_id);

    const resp = await apiGet(alicePage, `/ui/remote/k8s/pods/${pod.pod_id}/logs`, { tail: "10" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.pod_id).toBe(pod.pod_id);
    expect(data.lines).toBeDefined();
    expect(data.lines.length).toBeGreaterThan(0);
    expect(data.lines.some((l: string) => l.includes("SSH server"))).toBe(true);
  });

  test("254.5 Launch with SSH key sets key association", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/k8s/launch", {
      label: `ssh-key-test-${TS}`,
      image: "alpine-ssh",
      preset: "small",
      ssh_key_id: "key_test_123",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.ssh_key_id).toBe("key_test_123");
    launchedIds.push(data.pod_id);
  });

  test("254.6 List pods returns launched pods", async () => {
    const resp = await apiGet(alicePage, "/ui/remote/k8s/pods");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.pods).toBeDefined();
    expect(data.count).toBeGreaterThanOrEqual(2);
    const ids = data.pods.map((p: any) => p.pod_id);
    for (const id of launchedIds.slice(1)) {
      expect(ids).toContain(id);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 255: Pod Limits & TTL
// ─────────────────────────────────────────────────────────────────────────────

test.describe("255 — Pod Limits & TTL", () => {
  const limitIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);
  });

  test.afterAll(async () => {
    for (const id of limitIds) {
      try {
        await apiDelete(alicePage, ALICE_ID, `/ui/remote/k8s/pods/${id}`);
      } catch (_) { /* ignore */ }
    }
    await alicePage.close();
    await bobPage.close();
  });

  test("255.1 Alice cannot exceed max pods", async () => {
    // First terminate any existing running pods from other test sections
    const existingResp = await apiGet(alicePage, "/ui/remote/k8s/pods");
    const existing = await existingResp.json();
    for (const pod of existing.pods || []) {
      if (pod.status === "running" || pod.status === "pending") {
        await apiDelete(alicePage, ALICE_ID, `/ui/remote/k8s/pods/${pod.pod_id}`);
      }
    }

    // Launch up to the limit (5 by default)
    for (let i = 0; i < 5; i++) {
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/k8s/launch", {
        label: `limit-test-${TS}-${i}`,
        image: "alpine-ssh",
        preset: "small",
      });
      expect(resp.status()).toBe(201);
      const data = await resp.json();
      limitIds.push(data.pod_id);
    }

    // 6th should fail
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/k8s/launch", {
      label: `limit-test-${TS}-overflow`,
      image: "alpine-ssh",
      preset: "small",
    });
    expect(resp.status()).toBe(409);
    const data = await resp.json();
    expect(data.detail).toContain("Maximum");
  });

  test("255.2 TTL defaults to 4 hours", async () => {
    const id = limitIds[limitIds.length - 1];
    const resp = await apiGet(alicePage, `/ui/remote/k8s/pods/${id}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Number(data.ttl_seconds)).toBe(14400);
    expect(Number(data.expires_at)).toBe(Number(data.created_at) + 14400);
  });

  test("255.3 Custom TTL is respected", async () => {
    // Free a slot
    await apiDelete(alicePage, ALICE_ID, `/ui/remote/k8s/pods/${limitIds[0]}`);

    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/k8s/launch", {
      label: `ttl-custom-${TS}`,
      image: "ubuntu-ssh",
      preset: "small",
      ttl_seconds: 3600,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(Number(data.ttl_seconds)).toBe(3600);
    expect(Number(data.expires_at)).toBe(Number(data.created_at) + 3600);
    limitIds.push(data.pod_id);
  });

  test("255.4 TTL below minimum returns 422", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/k8s/launch", {
      label: `ttl-short-${TS}`,
      image: "ubuntu-ssh",
      preset: "small",
      ttl_seconds: 60,
    });
    expect(resp.status()).toBe(422);
  });

  test("255.5 Alice cannot access Bob's pods", async () => {
    const bobResp = await apiPost(bobPage, BOB_ID, "/ui/remote/k8s/launch", {
      label: `bob-pod-${TS}`,
      image: "alpine-ssh",
      preset: "small",
    });
    expect(bobResp.status()).toBe(201);
    const bobData = await bobResp.json();
    const bobPodId = bobData.pod_id;

    // Alice tries to GET Bob's pod -> 404
    const aliceGetResp = await apiGet(alicePage, `/ui/remote/k8s/pods/${bobPodId}`);
    expect(aliceGetResp.status()).toBe(404);

    // Alice tries to DELETE Bob's pod -> 404
    const aliceDelResp = await apiDelete(alicePage, ALICE_ID, `/ui/remote/k8s/pods/${bobPodId}`);
    expect(aliceDelResp.status()).toBe(404);

    // Cleanup
    await apiDelete(bobPage, BOB_ID, `/ui/remote/k8s/pods/${bobPodId}`);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 256: Containers UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("256 — Containers UI", () => {
  const uiPodIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    for (const id of uiPodIds) {
      try {
        await apiDelete(alicePage, ALICE_ID, `/ui/remote/k8s/pods/${id}`);
      } catch (_) { /* ignore */ }
    }
    await alicePage.close();
  });

  test("256.1 K8sLauncherPage renders pod table", async () => {
    await alicePage.goto(`${BASE}/remote/k8s`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText("Containers", { exact: true })).toBeVisible();
    await expect(alicePage.getByTestId("launch-btn")).toBeVisible();
  });

  test("256.2 Launch dialog shows images and presets", async () => {
    await alicePage.goto(`${BASE}/remote/k8s`, { waitUntil: "domcontentloaded" });
    await alicePage.getByTestId("launch-btn").click();
    await expect(alicePage.getByRole("heading", { name: "Launch Container" })).toBeVisible();
    await expect(alicePage.getByTestId("launch-label")).toBeVisible();
    await expect(alicePage.getByTestId("launch-image")).toBeVisible();
    await expect(alicePage.getByTestId("launch-preset")).toBeVisible();
    await expect(alicePage.getByTestId("launch-submit")).toBeVisible();
  });

  test("256.3 Launch from dialog creates pod", async () => {
    await alicePage.goto(`${BASE}/remote/k8s`, { waitUntil: "domcontentloaded" });

    // First terminate any existing running pods
    const existingResp = await apiGet(alicePage, "/ui/remote/k8s/pods");
    const existing = await existingResp.json();
    for (const pod of existing.pods || []) {
      if (pod.status === "running" || pod.status === "pending") {
        await apiDelete(alicePage, ALICE_ID, `/ui/remote/k8s/pods/${pod.pod_id}`);
      }
    }

    await alicePage.getByTestId("launch-btn").click();
    await expect(alicePage.getByRole("heading", { name: "Launch Container" })).toBeVisible();

    // Fill label
    await alicePage.getByTestId("launch-label").fill(`ui-k8s-${TS}`);

    // Select image
    await alicePage.getByTestId("launch-image").click();
    await alicePage.getByRole("option", { name: /Ubuntu SSH/ }).click();

    // Select preset
    await alicePage.getByTestId("launch-preset").click();
    await alicePage.getByRole("option", { name: /small/ }).click();

    // Submit
    await alicePage.getByTestId("launch-submit").click();

    // Wait for new row in the table
    await expect(alicePage.getByText(`ui-k8s-${TS}`)).toBeVisible({ timeout: 10_000 });

    // Track pod for cleanup
    const podsResp = await apiGet(alicePage, "/ui/remote/k8s/pods");
    const podsData = await podsResp.json();
    const uiPod = podsData.pods.find((p: any) => p.label === `ui-k8s-${TS}`);
    if (uiPod) uiPodIds.push(uiPod.pod_id);
  });

  test("256.4 TTL countdown displays remaining time", async () => {
    await alicePage.goto(`${BASE}/remote/k8s`, { waitUntil: "domcontentloaded" });

    // Wait for pods to load
    await expect(alicePage.getByText(`ui-k8s-${TS}`)).toBeVisible({ timeout: 10_000 });

    // Find the TTL cell for our pod
    const podId = uiPodIds[0];
    if (podId) {
      const ttlCell = alicePage.getByTestId(`ttl-${podId}`);
      await expect(ttlCell).toBeVisible();
      const text = await ttlCell.textContent();
      expect(text).toMatch(/\d+h \d+m/);
    }
  });
});
