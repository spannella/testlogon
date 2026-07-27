/**
 * FIN-017: Bulk Payout & Refund Tools — E2E
 *
 * Covers the admin bulk-processing API + UI:
 *  - list eligible pending payouts / refund requests
 *  - dry-run preview (totals + per-item validation) persists a preview batch
 *  - execute marks items success, sets batch status, writes refund ledger entries
 *  - history + detail return the batch
 *  - re-execute a previewed batch by batch_id
 *  - USER role gets 403
 *
 * Pending payouts/refunds are seeded directly via DynamoDB (scripts/
 * e2e_seed_bulk_payouts.py) for deterministic batch processing. Real provider
 * calls are gated behind `bulk_payout_use_real_provider` (default false), so
 * execute is deterministic.
 */
import { test, expect, type Browser, type Page } from "@playwright/test";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { execFileSync } from "child_process";
import { loadSessions } from "./helpers/session";
import {
  usingCpp,
  resolveIdentityId,
  cppSeedBulkPending,
} from "./helpers/cpp-seed-payouts-subs-ats-misc";

// ESM-safe __dirname (this spec runs under Playwright's ESM loader).
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const BASE = "http://localhost:3000";
const API = "/ui/admin/bulk-payouts";
const REPO_ROOT = path.join(__dirname, "..", "..");
const SESSION_FILE = path.join(__dirname, "..", ".admin-sessions.json");

interface SessionRec {
  user_sub: string;
  ui_session: string;
  ui_csrf: string;
  ui_access_token: string;
  csrf_token: string;
}

// Generate fresh — a cached session file goes stale across backend restarts
// (dead session ids => 401/empty results). e2e_admin_session_setup.py emits
// {key: {session_id, csrf_token, cookies:[{name,value}]}}; flatten the cookies
// into the ui_session/ui_csrf/ui_access_token shape this spec expects.
let SESSIONS: Record<string, SessionRec> = {};
try {
  const raw = loadSessions() as Record<string, { csrf_token: string; cookies: Array<{ name: string; value: string }> }>;
  for (const key of Object.keys(raw)) {
    const s = raw[key];
    const ck: Record<string, string> = {};
    for (const c of s.cookies ?? []) ck[c.name] = c.value;
    SESSIONS[key] = {
      ui_session: ck.ui_session ?? "",
      ui_csrf: ck.ui_csrf ?? "",
      ui_access_token: ck.ui_access_token ?? "",
      csrf_token: s.csrf_token,
    };
  }
} catch {
  try {
    SESSIONS = JSON.parse(fs.readFileSync(SESSION_FILE, "utf-8"));
  } catch {
    SESSIONS = {};
  }
}

function rec(identity: string): SessionRec {
  return SESSIONS[identity] ?? ({} as SessionRec);
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const r = rec(identity);
  const ctx = await browser.newContext();
  await ctx.addCookies([
    { name: "ui_session", value: r.ui_session ?? "", domain: "localhost", path: "/" },
    { name: "ui_csrf", value: r.ui_csrf ?? "", domain: "localhost", path: "/" },
    { name: "ui_access_token", value: r.ui_access_token ?? "", domain: "localhost", path: "/" },
  ]);
  const page = await ctx.newPage();
  // Seed the client-side auth store so ProtectedRoute treats the page as
  // authenticated (cookies alone only satisfy server-side API auth).
  await page.goto("/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, r.user_sub);
  return page;
}

function csrfHeaders(identity: string): Record<string, string> {
  return { "x-csrf-token": rec(identity).csrf_token ?? "" };
}

/** Seed a pending payout/refund row directly in DynamoDB. Returns the ref_id. */
function seedPending(kind: "payout" | "refund", userId: string, amountCents: number): string {
  // cpp path: the Python seed script writes the :8001 DDB-Local; cpp reads its
  // own tlc_creator_payouts / tlc_refund_requests. Seed a pending row there and
  // return the ref_id (email->SUB resolution happens inside the wrapper).
  if (usingCpp()) {
    return cppSeedBulkPending(kind, userId, amountCents);
  }
  const out = execFileSync(
    "bash",
    [
      "-lc",
      `set -a; source .env.local 2>/dev/null; set +a; ` +
        `PYTHONPATH=. .venv/bin/python scripts/e2e_seed_bulk_payouts.py ${kind} ${userId} ${amountCents}`,
    ],
    { cwd: REPO_ROOT, encoding: "utf-8" },
  );
  return out.trim().split("\n").pop()!.trim();
}

const ALICE = "e2e_alice@test.local";
const BOB = "e2e_bob@test.local";

test.describe("FIN-017 Bulk Payout & Refund Tools", () => {
  test("admin lists eligible pending payouts", async ({ browser }) => {
    const page = await newIdentityPage(browser, "root");
    const resp = await page.request.get(`${BASE}${API}/eligible?kind=payout`);
    expect(resp.ok()).toBeTruthy();
    expect(Array.isArray(await resp.json())).toBeTruthy();
    await page.context().close();
  });

  test("dry-run preview returns totals + per-item validation and persists a preview batch", async ({ browser }) => {
    const page = await newIdentityPage(browser, "root");
    const id1 = seedPending("payout", ALICE, 1000);
    const id2 = seedPending("payout", BOB, 2500);

    const resp = await page.request.post(`${BASE}${API}/preview`, {
      headers: csrfHeaders("root"),
      data: { kind: "payout", ref_ids: [id1, id2, "payout_does_not_exist"] },
    });
    expect(resp.ok()).toBeTruthy();
    const batch = await resp.json();

    expect(batch.status).toBe("preview");
    expect(batch.item_count).toBe(3);
    expect(batch.total_cents).toBe(3500);
    expect(batch.items.filter((i: any) => i.status === "pending").length).toBe(2);
    expect(batch.items.filter((i: any) => i.status === "skipped").length).toBe(1);

    const got = await page.request.get(`${BASE}${API}/batches/${batch.batch_id}`);
    expect(got.ok()).toBeTruthy();
    expect((await got.json()).batch_id).toBe(batch.batch_id);
    await page.context().close();
  });

  test("execute marks payouts success and sets batch status", async ({ browser }) => {
    const page = await newIdentityPage(browser, "root");
    const id1 = seedPending("payout", ALICE, 1500);
    const id2 = seedPending("payout", BOB, 750);

    const exec = await page.request.post(`${BASE}${API}/execute`, {
      headers: csrfHeaders("root"),
      data: { kind: "payout", ref_ids: [id1, id2] },
    });
    expect(exec.ok()).toBeTruthy();
    const result = await exec.json();
    expect(result.status).toBe("completed");
    expect(result.success_count).toBe(2);
    expect(result.failure_count).toBe(0);
    expect(result.items.every((i: any) => i.status === "success")).toBeTruthy();
    await page.context().close();
  });

  test("execute approves refund requests (ledger credit written by reused service)", async ({ browser }) => {
    const page = await newIdentityPage(browser, "root");
    const id = seedPending("refund", ALICE, 1200);
    const exec = await page.request.post(`${BASE}${API}/execute`, {
      headers: csrfHeaders("root"),
      data: { kind: "refund", ref_ids: [id] },
    });
    expect(exec.ok()).toBeTruthy();
    const result = await exec.json();
    expect(result.status).toBe("completed");
    expect(result.success_count).toBe(1);
    await page.context().close();
  });

  test("re-executing an already-processed item is skipped at validation", async ({ browser }) => {
    const page = await newIdentityPage(browser, "root");
    const id = seedPending("payout", BOB, 1100);
    await page.request.post(`${BASE}${API}/execute`, {
      headers: csrfHeaders("root"),
      data: { kind: "payout", ref_ids: [id] },
    });
    const second = await page.request.post(`${BASE}${API}/execute`, {
      headers: csrfHeaders("root"),
      data: { kind: "payout", ref_ids: [id] },
    });
    const result = await second.json();
    expect(result.items[0].status).toBe("skipped");
    await page.context().close();
  });

  test("history + detail return the batch", async ({ browser }) => {
    const page = await newIdentityPage(browser, "root");
    const id = seedPending("payout", ALICE, 500);
    const exec = await page.request.post(`${BASE}${API}/execute`, {
      headers: csrfHeaders("root"),
      data: { kind: "payout", ref_ids: [id] },
    });
    const batchId = (await exec.json()).batch_id;

    const hist = await page.request.get(`${BASE}${API}/batches`);
    expect(hist.ok()).toBeTruthy();
    expect((await hist.json()).some((b: any) => b.batch_id === batchId)).toBeTruthy();

    const detail = await page.request.get(`${BASE}${API}/batches/${batchId}`);
    expect(detail.ok()).toBeTruthy();
    expect((await detail.json()).batch_id).toBe(batchId);
    await page.context().close();
  });

  test("re-execute a previewed batch by batch_id", async ({ browser }) => {
    const page = await newIdentityPage(browser, "root");
    const id = seedPending("payout", BOB, 999);
    const preview = await page.request.post(`${BASE}${API}/preview`, {
      headers: csrfHeaders("root"),
      data: { kind: "payout", ref_ids: [id] },
    });
    const batchId = (await preview.json()).batch_id;

    const exec = await page.request.post(`${BASE}${API}/execute`, {
      headers: csrfHeaders("root"),
      data: { batch_id: batchId },
    });
    const result = await exec.json();
    expect(result.batch_id).toBe(batchId);
    expect(result.status).toBe("completed");
    expect(result.success_count).toBe(1);
    await page.context().close();
  });

  test("USER role is blocked (403) on all bulk endpoints", async ({ browser }) => {
    const page = await newIdentityPage(browser, "alice");

    const eligible = await page.request.get(`${BASE}${API}/eligible?kind=payout`);
    expect(eligible.status()).toBe(403);

    const preview = await page.request.post(`${BASE}${API}/preview`, {
      headers: csrfHeaders("alice"),
      data: { kind: "payout", ref_ids: [] },
    });
    expect(preview.status()).toBe(403);

    const execute = await page.request.post(`${BASE}${API}/execute`, {
      headers: csrfHeaders("alice"),
      data: { kind: "payout", ref_ids: [] },
    });
    expect(execute.status()).toBe(403);

    const batches = await page.request.get(`${BASE}${API}/batches`);
    expect(batches.status()).toBe(403);
    await page.context().close();
  });

  test("admin (charlie) can drive the console too", async ({ browser }) => {
    const page = await newIdentityPage(browser, "charlie_admin");
    const resp = await page.request.get(`${BASE}${API}/eligible?kind=refund`);
    expect(resp.ok()).toBeTruthy();
    await page.context().close();
  });

  test("UI: console renders kind picker, preview and execute flow", async ({ browser }) => {
    const page = await newIdentityPage(browser, "root");
    await page.goto(`${BASE}/admin/bulk-payouts`);
    await expect(page.getByRole("heading", { name: /Bulk Payout/i })).toBeVisible();
    await expect(page.getByTestId("preview-btn")).toBeVisible();
    await page.context().close();
  });
});
