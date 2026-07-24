/**
 * E2E tests for AGENT-007: Agent PR & Ticket Integration.
 *
 * Section 647: PR Creation API
 * Section 648: Work Completion API
 * Section 649: Status Flow & GitHub Webhook API
 * Section 650: Agent PR UI
 *
 * Auth: cookie auth via `e2e_admin_session_setup.py` sessions. Non-GET cookie
 * requests carry an `x-csrf-token` header. Alice = USER, root = ROOT.
 *
 * Setup: a coder worker is created via the orchestrator create-worker endpoint,
 * and tickets are written directly to DynamoDB (agent_eligible=yes) and claimed
 * so the worker has a current ticket to work on.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

// ─── Session bootstrap ─────────────────────────────────────────────────────────

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

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

const FE = "http://localhost:3000";

/** Hydrate the React auth store so guarded routes render (browser nav). */
async function injectUiAuth(page: Page, identity: string, userId: string) {
  const sessions = getSessions();
  await page.context().addCookies(sessions[identity].cookies);
  await page.goto(`${FE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

// ─── DDB helper: create an agent-eligible ticket ────────────────────────────────

function createEligibleTicket(ticketId: string, subject: string): void {
  execSync(
    `python3 -c "
import boto3, os, time
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('TICKETS_TABLE_NAME','tickets'))
ts = int(time.time())
tbl.put_item(Item={
    'pk': 'TICKET#${ticketId}', 'sk': 'META', 'entity_type': 'ticket_meta',
    'ticket_id': '${ticketId}', 'subject': '${subject}', 'description': 'Agent work for ${subject}',
    'owner_sub': '${ALICE_ID}', 'status': 'open', 'created_at': ts, 'updated_at': ts,
    'version': 1, 'agent_eligible': 'yes', 'agent_worker_id': '', 'priority': 'medium',
})
print('created ${ticketId}')
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

function readTicket(ticketId: string): Record<string, unknown> {
  const raw = execSync(
    `python3 -c "
import boto3, os, json
from decimal import Decimal
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('TICKETS_TABLE_NAME','tickets'))
item = tbl.get_item(Key={'pk':'TICKET#${ticketId}','sk':'META'}).get('Item', {})
def conv(o):
    if isinstance(o, Decimal): return int(o)
    raise TypeError
print(json.dumps(item, default=conv))
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  ).toString();
  return JSON.parse(raw);
}

// ─── Worker + ticket setup ──────────────────────────────────────────────────────

let workerId = "";
const ticketCli = `tkt_pr_cli_${TS}`;
const ticketApi = `tkt_pr_api_${TS}`;
const ticketComplete = `tkt_pr_done_${TS}`;

async function createWorker(page: Page, agentType: string): Promise<string> {
  const r = await apiPost(page, "alice", "ui/agent/orchestrator/create-worker", {
    label: `PR Test ${agentType} ${TS}`,
    agent_type: agentType,
  });
  const body = await r.json();
  return body.worker_id;
}

async function claim(page: Page, wid: string, ticketId: string): Promise<void> {
  await apiPost(page, "alice", `ui/agent/orchestrator/${wid}/claim-ticket`, {
    ticket_id: ticketId,
  });
}

// ─── 647. PR Creation API ───────────────────────────────────────────────────────

test.describe("647. Agent PR Creation API", () => {
  let alice: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alice = await newIdentityPage(browser, "alice");
    workerId = await createWorker(alice, "coder");
    createEligibleTicket(ticketCli, `PR CLI ${TS}`);
    createEligibleTicket(ticketApi, `PR API ${TS}`);
  });

  test.afterAll(async () => {
    await alice?.close();
  });

  test("create PR from agent work (CLI method)", async () => {
    const r = await apiPost(alice, "alice", `ui/agent/pr/${workerId}/create`, {
      ticket_id: ticketCli,
      method: "cli",
    });
    expect(r.status()).toBe(201);
    const pr = await r.json();
    expect(pr.pr_id).toBeTruthy();
    expect(pr.ticket_id).toBe(ticketCli);
    expect(pr.branch).toContain(workerId);
    expect(pr.title).toContain("PR CLI");
    expect(pr.status).toBe("open");
  });

  test("create PR from agent work (API method)", async () => {
    const r = await apiPost(alice, "alice", `ui/agent/pr/${workerId}/create`, {
      ticket_id: ticketApi,
      method: "api",
      repo_url: "https://github.com/test/repo",
    });
    expect(r.status()).toBe(201);
    const pr = await r.json();
    expect(pr.pr_url).toContain("github.com");
    expect(pr.pr_number).toBeGreaterThan(0);
  });

  test("list agent PRs", async () => {
    const r = await apiGet(alice, "ui/agent/pr");
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.count).toBeGreaterThanOrEqual(2);
    for (const pr of body.prs) {
      expect(pr.pr_id).toBeTruthy();
      expect(pr.worker_id).toBeTruthy();
      expect(pr.ticket_id).toBeTruthy();
    }
  });

  test("get PR linked to ticket", async () => {
    const r = await apiGet(alice, `ui/agent/pr/ticket/${ticketCli}`);
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.count).toBeGreaterThanOrEqual(1);
    expect(body.prs[0].ticket_id).toBe(ticketCli);
  });

  test("get single PR by id", async () => {
    const list = await (await apiGet(alice, "ui/agent/pr")).json();
    const prId = list.prs[0].pr_id;
    const r = await apiGet(alice, `ui/agent/pr/${prId}`);
    expect(r.status()).toBe(200);
    const pr = await r.json();
    expect(pr.pr_id).toBe(prId);
  });
});

// ─── 648. Work Completion API ─────────────────────────────────────────────────

test.describe("648. Agent Work Completion API", () => {
  let alice: Page;
  let completeWorker = "";

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    completeWorker = await createWorker(alice, "coder");
    createEligibleTicket(ticketComplete, `PR DONE ${TS}`);
    await claim(alice, completeWorker, ticketComplete);
  });

  test.afterAll(async () => {
    await alice?.close();
  });

  test("complete agent work generates summary", async () => {
    const r = await apiPost(alice, "alice", `ui/agent/pr/${completeWorker}/complete`, {
      ticket_id: ticketComplete,
    });
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.summary).toBeTruthy();
    expect(body.summary.text).toContain(ticketComplete);
    expect(body.new_status).toBeTruthy();
  });

  test("ticket updated with agent summary", async () => {
    const t = readTicket(ticketComplete);
    expect(t.agent_summary).toBeTruthy();
    expect(Number(t.agent_completed_at)).toBeGreaterThan(0);
  });

  test("worker returns to idle after completion", async () => {
    const r = await apiGet(alice, `ui/agent/orchestrator/${completeWorker}/status`);
    expect(r.status()).toBe(200);
    const s = await r.json();
    expect(s.agent_state).toBe("idle");
    expect(s.current_ticket_id).toBe("");
    expect(s.tickets_completed).toBeGreaterThanOrEqual(1);
  });

  test("work completion records memory", async () => {
    const r = await apiGet(alice, `ui/agent/memory/${completeWorker}/entries`, {
      category: "learning",
    });
    expect(r.status()).toBe(200);
    const body = await r.json();
    const entries = body.entries ?? body;
    const match = entries.find(
      (e: { ticket_id?: string }) => e.ticket_id === ticketComplete,
    );
    expect(match).toBeTruthy();
  });

  test("cross-agent handoff queues ticket for next agent", async () => {
    const t = readTicket(ticketComplete);
    expect(t.next_agent_type).toBe("qa");
    expect(t.agent_eligible).toBe("yes");
    expect(t.agent_worker_id).toBe("");
  });
});

// ─── 649. Status Flow & GitHub Webhook API ────────────────────────────────────

test.describe("649. Status Flow & GitHub Webhook API", () => {
  let alice: Page;

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alice?.close();
  });

  test("get default status flow for coder", async () => {
    const r = await apiGet(alice, "ui/agent/pr/status-flow/coder");
    expect(r.status()).toBe(200);
    const flow = await r.json();
    expect(flow.on_claim).toBe("in_progress");
    expect(flow.on_complete).toBe("code_complete");
    expect(flow.on_pr_merged).toBe("done");
    expect(flow.next_agent_type).toBe("qa");
  });

  test("status flow for QA agent ends the chain", async () => {
    const r = await apiGet(alice, "ui/agent/pr/status-flow/qa");
    const flow = await r.json();
    expect(flow.on_complete).toBe("qa_passed");
    expect(flow.next_agent_type).toBe("");
  });

  test("set custom status flow", async () => {
    const r = await apiPut(alice, "alice", "ui/agent/pr/status-flow/reviewer", {
      on_complete: "ready_for_review",
    });
    expect(r.status()).toBe(200);
    const updated = await apiGet(alice, "ui/agent/pr/status-flow/reviewer");
    const flow = await updated.json();
    expect(flow.on_complete).toBe("ready_for_review");
  });

  test("github webhook handles PR merge", async () => {
    // First create a PR via API so it can be found by URL.
    const wid = await createWorker(alice, "coder");
    const mergeTicket = `tkt_pr_merge_${TS}`;
    createEligibleTicket(mergeTicket, `PR MERGE ${TS}`);
    const created = await (
      await apiPost(alice, "alice", `ui/agent/pr/${wid}/create`, {
        ticket_id: mergeTicket,
        method: "api",
        repo_url: "https://github.com/test/merge-repo",
      })
    ).json();
    const prUrl = created.pr_url;
    expect(prUrl).toContain("github.com");

    // Webhook router needs the github event header.
    const sess = getSessions()["alice"];
    const r2 = await alice.request.post(`${API}/ui/agent/webhooks/github`, {
      data: { action: "closed", pull_request: { html_url: prUrl, merged: true } },
      headers: {
        "x-csrf-token": sess.csrf_token,
        "x-github-event": "pull_request",
        "Content-Type": "application/json",
      },
    });
    expect(r2.status()).toBe(200);
    const body = await r2.json();
    expect(body.handled).toBe(true);
    expect(body.action).toBe("pr_merged");
    expect(body.ticket_id).toBe(mergeTicket);
  });

  test("github webhook ignores unrelated event", async () => {
    const sess = getSessions()["alice"];
    const r = await alice.request.post(`${API}/ui/agent/webhooks/github`, {
      data: { action: "labeled" },
      headers: {
        "x-csrf-token": sess.csrf_token,
        "x-github-event": "issues",
        "Content-Type": "application/json",
      },
    });
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.handled).toBe(false);
  });
});

// ─── 650. Agent PR UI ────────────────────────────────────────────────────────

test.describe("650. Agent PR UI", () => {
  let alice: Page;

  test.beforeAll(async ({ browser }) => {
    alice = await browser.newPage();
    await injectUiAuth(alice, "alice", ALICE_ID);
  });

  test.afterAll(async () => {
    await alice?.close();
  });

  test("Agent PRs page renders PR list", async () => {
    await alice.goto("/agents/prs");
    await expect(
      alice.getByRole("heading", { name: "Agent PRs" }),
    ).toBeVisible();
    await expect(alice.getByText("PR Title")).toBeVisible();
    await expect(alice.getByText("Branch", { exact: true })).toBeVisible();
  });

  test("PR row shows a status badge", async () => {
    await alice.goto("/agents/prs");
    await expect(
      alice.locator('[data-testid="pr-status-open"]').first(),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("PR row links to ticket", async () => {
    await alice.goto("/agents/prs");
    await expect(
      alice.getByRole("link", { name: /View Ticket/i }).first(),
    ).toBeVisible();
  });

  test("status flow editor shows transition fields", async () => {
    await alice.goto("/agents/prs");
    await expect(alice.getByText("Status Flow Editor")).toBeVisible();
    await expect(alice.getByLabel("On Claim")).toBeVisible();
    await expect(alice.getByLabel("On Complete")).toBeVisible();
    await expect(alice.getByLabel("On PR Created")).toBeVisible();
    await expect(alice.getByLabel("On PR Merged")).toBeVisible();
    await expect(alice.getByLabel("Next Agent Type")).toBeVisible();
  });

  test("status filter is present", async () => {
    await alice.goto("/agents/prs");
    await expect(alice.getByLabel("Status filter")).toBeVisible();
  });
});
