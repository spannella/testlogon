/**
 * E2E tests for the Account State feature.
 *
 * Sections:
 *   96 — Account State API (6 tests)
 *
 * Auth: Cookie-based session for Alice (e2e_alice@test.local) with CSRF.
 *
 * Endpoints under test:
 *   GET  /ui/account/status
 *   POST /ui/account/suspend
 *   POST /ui/account/reactivate
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";

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
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, path: string, body?: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

// ─── DDB helpers ─────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os
from pathlib import Path
for ln in Path('${REPO_ROOT}/.env.local').read_text().splitlines():
    ln = ln.strip()
    if ln and not ln.startswith('#') and '=' in ln:
        k, v = ln.split('=', 1); os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
`;

function resetAccountState(userSub: string): void {
  execSync(
    `python3 -c "${DDB_PRELUDE}
tbl = ddb.Table('account_state')
tbl.put_item(Item={'user_sub': '${userSub}', 'status': 'active', 'updated_at': 0, 'reason': '', 'requested_by': ''})
print('account reset')
"`,
    { timeout: 10_000 },
  );
}

// ─── Section 96: Account State API ──────────────────────────────────────────

test.describe.serial("96 — Account State API", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    resetAccountState(getSessions()[ALICE_ID].user_sub);
  });

  test.afterAll(async () => {
    resetAccountState(getSessions()[ALICE_ID].user_sub);
    await page.close();
  });

  test("96.1 — Get account status returns active by default", async () => {
    const resp = await apiGet(page, "/ui/account/status");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("active");
    expect(data).toHaveProperty("updated_at");
    expect(data).toHaveProperty("reason");
    expect(data).toHaveProperty("requested_by");
  });

  test("96.2 — Suspend account with reason", async () => {
    const resp = await apiPost(page, "/ui/account/suspend", {
      reason: "Taking a break",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("suspension_requested");
    expect(data.reason).toBe("Taking a break");
    expect(data.updated_at).toBeGreaterThan(0);
  });

  test("96.3 — Get status reflects suspension_requested", async () => {
    const resp = await apiGet(page, "/ui/account/status");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("suspension_requested");
    expect(data.reason).toBe("Taking a break");
  });

  test("96.4 — Reactivate account", async () => {
    const resp = await apiPost(page, "/ui/account/reactivate", {
      reason: "Changed my mind",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("reactivation_requested");
    expect(data.reason).toBe("Changed my mind");
    expect(data.updated_at).toBeGreaterThan(0);
  });

  test("96.5 — Get status reflects reactivation_requested", async () => {
    const resp = await apiGet(page, "/ui/account/status");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("reactivation_requested");
    expect(data.reason).toBe("Changed my mind");
  });

  test("96.6 — Suspend when not active returns 400", async () => {
    // Account is in reactivation_requested state, not active
    const resp = await apiPost(page, "/ui/account/suspend", {
      reason: "Should fail",
    });
    expect(resp.status()).toBe(400);
  });
});
