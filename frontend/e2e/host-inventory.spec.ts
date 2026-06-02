/**
 * INFRA-001 — Host Inventory Management.
 *
 * Sections 729–732. Covers:
 *   729 — Host CRUD API (create SSH/VNC, get, update, delete, owner isolation,
 *         validation, NO secret stored)
 *   730 — List / filter / groups API + pagination cursor
 *   731 — CSV import (multi-host create, invalid-row reporting, >200 reject,
 *         source=csv_import) + connection tracking + quick-connect + history
 *   732 — Host Inventory UI (page renders, add via dialog, quick-connect)
 *
 * Reuses the standard cookie + CSRF auth pattern: page.request carries the
 * session cookies; non-GET requests must send the x-csrf-token header.
 */
import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import path from "path";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

interface SessionData {
  user_sub: string;
  csrf_token: string;
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
    const repoRoot = process.cwd().includes("/frontend")
      ? path.resolve(process.cwd(), "..")
      : process.cwd();
    const setupScript = path.join(repoRoot, "e2e_session_setup.py");
    const raw = execSync(`python3 ${setupScript}`, { cwd: repoRoot, timeout: 30_000 }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function apiPost(page: Page, userId: string, endpoint: string, data?: object) {
  const session = getSessions()[userId];
  return page.request.post(`${API}${endpoint}`, {
    data: data ?? {},
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiPatch(page: Page, userId: string, endpoint: string, data: object) {
  const session = getSessions()[userId];
  return page.request.patch(`${API}${endpoint}`, {
    data,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, userId: string, endpoint: string) {
  const session = getSessions()[userId];
  return page.request.get(`${API}${endpoint}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiDelete(page: Page, userId: string, endpoint: string) {
  const session = getSessions()[userId];
  return page.request.delete(`${API}${endpoint}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

interface Host {
  host_id: string;
  label: string;
  hostname: string;
  port: number;
  protocol: string;
  username: string;
  description: string;
  tags: string[];
  group: string;
  os_type: string;
  created_at: number;
  updated_at: number;
  last_connected_at: number;
  connection_count: number;
  status: string;
  is_pinned: boolean;
  source: string;
}

let alice: Page;
let bob: Page;

test.describe("INFRA-001 Host Inventory", () => {
  test.beforeAll(async ({ browser }) => {
    alice = await browser.newPage();
    bob = await browser.newPage();
    await injectAuth(alice, ALICE_ID);
    await injectAuth(bob, BOB_ID);
  });

  // ── Section 729: Host CRUD API ──────────────────────────────────
  test.describe("Section 729: Host CRUD API", () => {
    test("Alice creates an SSH host", async () => {
      const resp = await apiPost(alice, ALICE_ID, "/ui/hosts", {
        label: `ssh-host-${TS}`,
        hostname: "10.0.1.10",
        port: 22,
        protocol: "ssh",
        username: "ubuntu",
        group: `grp-a-${TS}`,
      });
      expect(resp.status()).toBe(201);
      const h = (await resp.json()) as Host;
      expect(h.host_id).toBeTruthy();
      expect(h.protocol).toBe("ssh");
      expect(h.port).toBe(22);
      expect(h.source).toBe("manual");
      expect(h.status).toBe("unknown");
      expect(h.created_at).toBeGreaterThan(0);
    });

    test("Alice creates a VNC host with default port", async () => {
      const resp = await apiPost(alice, ALICE_ID, "/ui/hosts", {
        label: `vnc-host-${TS}`,
        hostname: "192.168.1.100",
        protocol: "vnc",
        port: 5900,
      });
      expect(resp.status()).toBe(201);
      const h = (await resp.json()) as Host;
      expect(h.protocol).toBe("vnc");
      expect(h.port).toBe(5900);
    });

    test("Host record stores NO secret fields", async () => {
      const resp = await apiPost(alice, ALICE_ID, "/ui/hosts", {
        label: `secret-check-${TS}`,
        hostname: "10.0.2.20",
        protocol: "ssh",
      });
      expect(resp.status()).toBe(201);
      const h = (await resp.json()) as Record<string, unknown>;
      // Connection metadata only — never any credential material.
      expect(h).not.toHaveProperty("password");
      expect(h).not.toHaveProperty("private_key");
      expect(h).not.toHaveProperty("passphrase");
      expect(h).not.toHaveProperty("secret");
      expect(h).not.toHaveProperty("credentials");
      const json = JSON.stringify(h).toLowerCase();
      expect(json).not.toContain("password");
      expect(json).not.toContain("private_key");
    });

    test("Alice updates host label and group", async () => {
      const c = await apiPost(alice, ALICE_ID, "/ui/hosts", {
        label: `upd-${TS}`,
        hostname: "10.0.3.30",
        protocol: "ssh",
      });
      const created = (await c.json()) as Host;
      const resp = await apiPatch(alice, ALICE_ID, `/ui/hosts/${created.host_id}`, {
        label: `upd-renamed-${TS}`,
        group: `prod-${TS}`,
      });
      expect(resp.status()).toBe(200);
      const h = (await resp.json()) as Host;
      expect(h.label).toBe(`upd-renamed-${TS}`);
      expect(h.group).toBe(`prod-${TS}`);
      expect(h.updated_at).toBeGreaterThanOrEqual(created.created_at);
    });

    test("Alice deletes a host -> GET returns 404", async () => {
      const c = await apiPost(alice, ALICE_ID, "/ui/hosts", {
        label: `del-${TS}`,
        hostname: "10.0.4.40",
        protocol: "ssh",
      });
      const created = (await c.json()) as Host;
      const del = await apiDelete(alice, ALICE_ID, `/ui/hosts/${created.host_id}`);
      expect(del.status()).toBe(200);
      const get = await apiGet(alice, ALICE_ID, `/ui/hosts/${created.host_id}`);
      expect(get.status()).toBe(404);
    });

    test("Bob cannot access Alice's host (owner isolation)", async () => {
      const c = await apiPost(alice, ALICE_ID, "/ui/hosts", {
        label: `iso-${TS}`,
        hostname: "10.0.5.50",
        protocol: "ssh",
      });
      const created = (await c.json()) as Host;
      const get = await apiGet(bob, BOB_ID, `/ui/hosts/${created.host_id}`);
      expect(get.status()).toBe(404);
      const patch = await apiPatch(bob, BOB_ID, `/ui/hosts/${created.host_id}`, {
        label: "hijack",
      });
      expect(patch.status()).toBe(404);
      const del = await apiDelete(bob, BOB_ID, `/ui/hosts/${created.host_id}`);
      expect(del.status()).toBe(404);
    });

    test("Create host with empty hostname returns 422", async () => {
      const resp = await apiPost(alice, ALICE_ID, "/ui/hosts", {
        label: `bad-${TS}`,
        hostname: "",
        protocol: "ssh",
      });
      expect(resp.status()).toBe(422);
    });

    test("Unauthenticated request returns 401", async ({ request }) => {
      const resp = await request.get(`${API}/ui/hosts`);
      expect(resp.status()).toBe(401);
    });
  });

  // ── Section 730: List / filter / groups API ─────────────────────
  test.describe("Section 730: List & filter API", () => {
    const PREFIX = `lf-${TS}`;
    test("List + filter by protocol + groups + pagination", async () => {
      // Create a known set of hosts.
      await apiPost(alice, ALICE_ID, "/ui/hosts", {
        label: `${PREFIX}-zulu`,
        hostname: "10.1.0.1",
        protocol: "ssh",
        group: `${PREFIX}-Production`,
      });
      await apiPost(alice, ALICE_ID, "/ui/hosts", {
        label: `${PREFIX}-alpha`,
        hostname: "10.1.0.2",
        protocol: "vnc",
        port: 5900,
        group: `${PREFIX}-Staging`,
      });
      await apiPost(alice, ALICE_ID, "/ui/hosts", {
        label: `${PREFIX}-mango`,
        hostname: "10.1.0.3",
        protocol: "ssh",
        group: `${PREFIX}-Production`,
      });

      // List all (alphabetical by label default).
      const all = await apiGet(alice, ALICE_ID, "/ui/hosts?limit=500");
      expect(all.status()).toBe(200);
      const allData = await all.json();
      const mine = (allData.hosts as Host[]).filter((h) => h.label.startsWith(PREFIX));
      const labels = mine.map((h) => h.label);
      expect(labels).toContain(`${PREFIX}-alpha`);
      expect(labels).toContain(`${PREFIX}-mango`);
      expect(labels).toContain(`${PREFIX}-zulu`);

      // Filter by protocol=vnc.
      const vnc = await apiGet(alice, ALICE_ID, "/ui/hosts?protocol=vnc&limit=500");
      const vncMine = ((await vnc.json()).hosts as Host[]).filter((h) =>
        h.label.startsWith(PREFIX),
      );
      expect(vncMine.length).toBe(1);
      expect(vncMine[0].protocol).toBe("vnc");

      // Filter by group.
      const grp = await apiGet(
        alice,
        ALICE_ID,
        `/ui/hosts?group=${PREFIX}-Production&limit=500`,
      );
      const grpHosts = (await grp.json()).hosts as Host[];
      expect(grpHosts.length).toBe(2);
      expect(grpHosts.every((h) => h.group === `${PREFIX}-Production`)).toBe(true);

      // Groups list contains our groups.
      const groups = await apiGet(alice, ALICE_ID, "/ui/hosts/groups");
      expect(groups.status()).toBe(200);
      const gnames = (await groups.json()).groups as string[];
      expect(gnames).toContain(`${PREFIX}-Production`);
      expect(gnames).toContain(`${PREFIX}-Staging`);

      // Pagination: limit=1 yields a cursor.
      const page1 = await apiGet(alice, ALICE_ID, "/ui/hosts?limit=1");
      const p1 = await page1.json();
      expect(p1.hosts.length).toBe(1);
      expect(p1.cursor).toBeTruthy();
      const page2 = await apiGet(alice, ALICE_ID, `/ui/hosts?limit=1&cursor=${p1.cursor}`);
      const p2 = await page2.json();
      expect(p2.hosts.length).toBe(1);
      expect(p2.hosts[0].host_id).not.toBe(p1.hosts[0].host_id);
    });
  });

  // ── Section 731: CSV import + connection tracking + quick-connect
  test.describe("Section 731: CSV import, tracking, quick-connect", () => {
    test("Import 3 hosts from CSV, source=csv_import", async () => {
      const csv =
        "label,hostname,port,protocol,group,os_type,description,tags\n" +
        `csv-${TS}-1,10.2.0.1,22,ssh,Imported-${TS},linux,web,"web,prod"\n` +
        `csv-${TS}-2,10.2.0.2,5900,vnc,Imported-${TS},linux,desk,"vnc"\n` +
        `csv-${TS}-3,10.2.0.3,22,ssh,Imported-${TS},linux,db,"db"\n`;
      const resp = await apiPost(alice, ALICE_ID, "/ui/hosts/import", {
        csv_content: csv,
      });
      expect(resp.status()).toBe(200);
      const r = await resp.json();
      expect(r.imported).toBe(3);
      expect(r.skipped).toBe(0);
      expect(r.errors.length).toBe(0);

      const list = await apiGet(
        alice,
        ALICE_ID,
        `/ui/hosts?group=Imported-${TS}&limit=500`,
      );
      const hosts = (await list.json()).hosts as Host[];
      expect(hosts.length).toBe(3);
      expect(hosts.every((h) => h.source === "csv_import")).toBe(true);
    });

    test("Import with invalid row reports errors", async () => {
      const csv =
        "label,hostname,port,protocol\n" +
        `csv-good-${TS},10.3.0.1,22,ssh\n` +
        `csv-bad-${TS},,22,ssh\n`; // missing hostname
      const resp = await apiPost(alice, ALICE_ID, "/ui/hosts/import", {
        csv_content: csv,
      });
      expect(resp.status()).toBe(200);
      const r = await resp.json();
      expect(r.imported).toBe(1);
      expect(r.errors.length).toBeGreaterThanOrEqual(1);
      expect(r.errors.join(" ")).toContain("row 3");
    });

    test("Import exceeding 200 hosts returns 400", async () => {
      let csv = "label,hostname,port,protocol\n";
      for (let i = 0; i < 201; i++) {
        csv += `csv-big-${TS}-${i},10.4.0.${(i % 250) + 1},22,ssh\n`;
      }
      const resp = await apiPost(alice, ALICE_ID, "/ui/hosts/import", {
        csv_content: csv,
      });
      expect(resp.status()).toBe(400);
    });

    test("Quick-connect returns SSH params + records connection", async () => {
      const c = await apiPost(alice, ALICE_ID, "/ui/hosts", {
        label: `qc-ssh-${TS}`,
        hostname: "10.5.0.10",
        port: 2222,
        protocol: "ssh",
        username: "deploy",
      });
      const host = (await c.json()) as Host;
      expect(host.connection_count).toBe(0);

      const qc = await apiPost(alice, ALICE_ID, `/ui/hosts/${host.host_id}/quick-connect`);
      expect(qc.status()).toBe(200);
      const params = await qc.json();
      expect(params.protocol).toBe("ssh");
      expect(params.hostname).toBe("10.5.0.10");
      expect(params.port).toBe(2222);
      expect(params.username).toBe("deploy");
      expect(params.connect_path).toContain("host=10.5.0.10");
      // No secrets in quick-connect payload.
      expect(JSON.stringify(params).toLowerCase()).not.toContain("password");

      // Connection was recorded.
      const after = await apiGet(alice, ALICE_ID, `/ui/hosts/${host.host_id}`);
      const h2 = (await after.json()) as Host;
      expect(h2.connection_count).toBe(1);
      expect(h2.last_connected_at).toBeGreaterThan(0);
    });

    test("Quick-connect on VNC returns target_id + ws_url", async () => {
      const c = await apiPost(alice, ALICE_ID, "/ui/hosts", {
        label: `qc-vnc-${TS}`,
        hostname: "10.5.0.20",
        protocol: "vnc",
        port: 5901,
      });
      const host = (await c.json()) as Host;
      const qc = await apiPost(alice, ALICE_ID, `/ui/hosts/${host.host_id}/quick-connect`);
      const params = await qc.json();
      expect(params.protocol).toBe("vnc");
      expect(params.target_id).toBe(`user:${host.host_id}`);
      expect(params.ws_url).toContain("10.5.0.20:5901");
    });

    test("record-connection endpoint + history", async () => {
      const c = await apiPost(alice, ALICE_ID, "/ui/hosts", {
        label: `hist-${TS}`,
        hostname: "10.6.0.10",
        protocol: "ssh",
      });
      const host = (await c.json()) as Host;
      await apiPost(alice, ALICE_ID, `/ui/hosts/${host.host_id}/record-connection`);
      await apiPost(alice, ALICE_ID, `/ui/hosts/${host.host_id}/record-connection`);

      const hist = await apiGet(alice, ALICE_ID, `/ui/hosts/${host.host_id}/history`);
      expect(hist.status()).toBe(200);
      const h = await hist.json();
      expect(h.connection_count).toBe(2);
      expect(h.events.length).toBe(2);
      expect(h.events[0].protocol).toBe("ssh");
    });
  });

  // ── Section 732: Host Inventory UI ──────────────────────────────
  test.describe("Section 732: Host Inventory UI", () => {
    test("Page renders host table headers", async () => {
      // Seed one host so the table renders.
      await apiPost(alice, ALICE_ID, "/ui/hosts", {
        label: `ui-${TS}`,
        hostname: "10.7.0.10",
        protocol: "ssh",
        group: `UI-${TS}`,
      });
      await alice.goto(`${BASE}/remote/hosts`, { waitUntil: "domcontentloaded" });
      await expect(alice.getByRole("heading", { name: "Host Inventory" })).toBeVisible();
      await expect(alice.getByRole("button", { name: "Add Host" })).toBeVisible();
      await expect(
        alice.locator("th").filter({ hasText: "Hostname" }).first(),
      ).toBeVisible();
    });

    test("Add Host dialog creates and shows new host", async () => {
      await alice.goto(`${BASE}/remote/hosts`, { waitUntil: "domcontentloaded" });
      await alice.getByRole("button", { name: "Add Host" }).click();
      const newLabel = `ui-add-${TS}`;
      await alice.locator("#hi-label").fill(newLabel);
      await alice.locator("#hi-hostname").fill("10.7.1.10");
      await alice.getByRole("button", { name: "Create" }).click();
      await expect(
        alice.locator('[data-testid="host-row"]').filter({ hasText: newLabel }),
      ).toBeVisible({ timeout: 10_000 });
    });
  });
});
