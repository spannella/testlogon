/**
 * VIDEO SEGMENT 22 — AI Agent Fleet  (~2 min)
 *
 * The platform's autonomous-agent layer: provision LLM-backed worker agents,
 * orchestrate them against a ticket queue, give them durable memory + project
 * context, and keep a human in the loop via a feedback queue.
 *   - LLM provider keys (encrypted at rest via KMS, per-key budgets)
 *   - Agent workers (Coder / QA / Reviewer) on EC2 or Kubernetes compute
 *   - The fleet dashboard: capacity, queue depth, start/stop-all
 *   - The orchestrator state machine for a single worker
 *   - Agent memory: identity, project context, a token-budgeted knowledge base
 *   - The human-feedback queue: agents ask, humans answer
 *
 * Seeding (off camera): a real KMS-encrypted Anthropic key (boto3), then the
 * production APIs (cookie + CSRF as Alice) to provision a worker — in dev mode
 * it provisions instantly to "ready" — set its identity/project, add knowledge
 * entries, and raise one feedback request.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg22-ai-agents.demo.ts
 */
import { test } from "@playwright/test";
import { BASE, injectAuth, caption, clearCaption, titleCard, beat, reveal, api, py, loadSessions } from "./_demo";

type Json = { json: () => Promise<Record<string, unknown>> };

test("Segment 22 — AI Agent Fleet", async ({ page }) => {
  test.setTimeout(600_000);
  const aliceSub = loadSessions()["alice"].user_sub;

  // ── Seed an active, KMS-encrypted Anthropic key (idempotent) ──────────────
  const out = py(`
import uuid, time
import boto3.dynamodb.conditions as C
from app.core.crypto import kms_encrypt
tbl = ddb.Table('llm_provider_keys')
USER = '${aliceSub}'
existing = None
r = tbl.query(KeyConditionExpression=C.Key('pk').eq('USER#' + USER) & C.Key('sk').begins_with('KEY#'))
for it in r.get('Items', []):
    if it.get('label') == 'Anthropic - Production':
        existing = it.get('key_id'); break
if existing:
    print('LLM_KEY_ID=' + existing)
else:
    key_id = uuid.uuid4().hex
    ts = int(time.time())
    raw = 'sk-ant-demo-' + uuid.uuid4().hex[:16]
    tbl.put_item(Item={
        'pk': 'USER#' + USER, 'sk': 'KEY#' + key_id, 'key_id': key_id, 'user_id': USER,
        'provider': 'anthropic', 'label': 'Anthropic - Production',
        'encrypted_api_key': kms_encrypt(raw), 'key_suffix': raw[-4:],
        'base_url': 'https://api.anthropic.com/v1', 'model_preference': '',
        'available_models': [], 'rate_limit_rpm': 60, 'monthly_budget_cents': 50000,
        'current_month_usage_cents': 12500, 'usage_reset_at': 0, 'total_requests': 248,
        'total_tokens_used': 1840000, 'status': 'active', 'last_tested_at': ts,
        'last_used_at': ts, 'created_at': ts, 'updated_at': ts, 'assigned_worker_ids': [],
    })
    print('LLM_KEY_ID=' + key_id)
`);
  const keyId = (out.match(/LLM_KEY_ID=([0-9a-f]+)/) || [])[1] || "";

  // ── Provision a worker + memory + a feedback request via the real APIs ────
  await injectAuth(page, "alice");
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(800);

  let workerId = "";
  try {
    const w = await api(page, "post", "/ui/agent/workers", "alice", {
      label: "Coder - feature work",
      agent_type: "coder",
      tool: "claude_code",
      compute_type: "k8s",
      instance_type: "standard-2cpu-4gb",
      llm_key_id: keyId,
      repo_url: "https://github.com/example/platform",
      branch_convention: "agent/{worker_id}/{ticket_id}",
      idle_timeout_seconds: 7200,
    });
    workerId = ((await (w as Json).json()) || {}).worker_id as string || "";
  } catch {
    /* tolerate — the fleet/keys pages still tell the story */
  }

  if (workerId) {
    await api(page, "put", `/ui/agent/memory/${workerId}/identity`, "alice", {
      identity_text:
        "You are a senior coding agent. Read the ticket, implement a clean, well-tested change, and open a small reviewable PR.",
      custom_instructions:
        "Always run the full test suite before opening a PR. Prefer minimal diffs that match the surrounding style.",
    }).catch(() => {});
    await api(page, "put", `/ui/agent/memory/${workerId}/project`, "alice", {
      repo_url: "https://github.com/example/platform",
      branch_convention: "agent/{worker_id}/{ticket_id}",
      coding_standards: "Python 3.12 + TypeScript. Type hints required. Match the existing module's style.",
      test_framework: "pytest + Playwright",
      ci_commands: "just test && just e2e",
    }).catch(() => {});
    await api(page, "post", `/ui/agent/memory/${workerId}/entries`, "alice", {
      category: "decision",
      title: "DynamoDB single-table pattern",
      content:
        "Feature tables share pk/sk; query with begins_with on sk and never scan a hot table. GSIs carry numeric sort keys declared in local-ddb-init.",
      importance: 5,
    }).catch(() => {});
    await api(page, "post", `/ui/agent/memory/${workerId}/entries`, "alice", {
      category: "learning",
      title: "React Query owns server state",
      content:
        "Use useQuery / useInfiniteQuery for all server data and invalidate on mutation success. No manual fetch inside components.",
      importance: 4,
    }).catch(() => {});
    await api(page, "post", `/ui/agent/feedback/${workerId}`, "alice", {
      ticket_id: "PLAT-482",
      question:
        "This migration touches the shared billing table. Run the online backfill now, or schedule a maintenance window?",
      terminal_context:
        "$ alembic upgrade head\n  -> applying 0042_billing_ledger_date_gsi\n  WARNING: table 'billing' has ~2.1M rows; online backfill ETA ~40m",
      detected_pattern: "awaiting human decision",
      timeout_seconds: 3600,
      timeout_action: "skip",
    }).catch(() => {});
    await api(page, "post", `/ui/agent/orchestrator/${workerId}/start`, "alice").catch(() => {});
  }

  // ── 1. Intro ──────────────────────────────────────────────────────────────
  await titleCard(
    page,
    22,
    "AI Agent Fleet",
    "LLM-backed workers · orchestration · agent memory · human-in-the-loop",
  );

  // ── 2. LLM provider keys ──────────────────────────────────────────────────
  await page.goto(`${BASE}/agents/llm-keys`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);
  await reveal(
    page,
    page.getByText(/llm api keys/i).first(),
    "Bring your own model",
    "Connect Anthropic, OpenAI and more — keys are encrypted at rest with KMS",
    { ms: 4200 },
  );
  await reveal(
    page,
    page.getByText("Anthropic - Production").first(),
    "Per-key budgets",
    "Each key has its own rate limit, monthly budget and live usage tracking",
    { ms: 4500 },
  ).catch(() => {});

  // ── 3. Agent workers ──────────────────────────────────────────────────────
  await page.goto(`${BASE}/agents/workers`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);
  await reveal(
    page,
    page.getByRole("heading", { name: /agent workers/i }).first(),
    "Agent workers",
    "Provision Coder, QA and Reviewer agents on EC2 or Kubernetes compute",
    { ms: 4000 },
  );
  await reveal(
    page,
    page.getByText("Coder - feature work").first(),
    "Provisioned & ready",
    "Compute launched, the tool installed, the key injected — ready in seconds",
    { ms: 4800 },
  ).catch(() => {});

  // ── 4. Fleet dashboard ────────────────────────────────────────────────────
  await page.goto(`${BASE}/agents/fleet`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);
  await reveal(
    page,
    page.getByText(/agent fleet/i).first(),
    "The fleet at a glance",
    "Total workers, active count, queue depth and errors — one control plane",
    { ms: 4500 },
  );
  await reveal(
    page,
    page.getByText(/start all/i).first(),
    "Fleet-level control",
    "Start or stop the whole fleet, and scale from saved worker templates",
    { ms: 4000 },
  ).catch(() => {});

  // ── 5. Orchestrator state machine ─────────────────────────────────────────
  await page.goto(`${BASE}/agents/dashboard`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1400);
  await reveal(
    page,
    page.getByRole("heading", { name: /agent dashboard/i }).first(),
    "Orchestrator",
    "Drive a single agent through its state machine: idle, claiming, working",
    { ms: 3800 },
  ).catch(() => {});
  if (workerId) {
    await page.getByPlaceholder(/worker id/i).first().fill(workerId).catch(() => {});
    await page.getByRole("button", { name: /^load$/i }).first().click().catch(() => {});
    await page.waitForTimeout(1600);
    await reveal(
      page,
      page.getByText(/last heartbeat|tickets completed|loop running|idle|claiming|working/i).first(),
      "Live agent state",
      "Heartbeats, the current ticket, and completed/failed counts in real time",
      { ms: 4500 },
    ).catch(() => {});
  }

  // ── 6. Agent memory ───────────────────────────────────────────────────────
  if (workerId) {
    await page.goto(`${BASE}/agents/memory/${workerId}`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1500);
    await reveal(
      page,
      page.getByRole("heading", { name: /agent memory/i }).first(),
      "Durable memory",
      "Agents remember — identity, project context and a curated knowledge base",
      { ms: 4200 },
    ).catch(() => {});
    await reveal(
      page,
      page.getByText(/tokens/i).first(),
      "Token-budgeted context",
      "The assembled context is measured against a budget so prompts stay lean",
      { ms: 4200 },
    ).catch(() => {});
    await reveal(
      page,
      page.getByText(/project context/i).first(),
      "Project context",
      "Repo, branch convention, test framework and coding standards travel with the agent",
      { ms: 4500 },
    ).catch(() => {});
    await reveal(
      page,
      page.getByText("DynamoDB single-table pattern").first(),
      "A growing knowledge base",
      "Learnings, decisions and patterns — each rated and token-counted",
      { ms: 4800 },
    ).catch(() => {});
  }

  // ── 7. Human-in-the-loop feedback ─────────────────────────────────────────
  await page.goto(`${BASE}/agents/feedback`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);
  await reveal(
    page,
    page.getByRole("heading", { name: /agent feedback/i }).first(),
    "Human in the loop",
    "When an agent hits a judgement call, it pauses and asks a human",
    { ms: 4200 },
  );
  await reveal(
    page,
    page.getByText(/maintenance window|backfill|billing table/i).first(),
    "Ask, then act",
    "Terminal context, the question, and a one-click answer — then the agent resumes",
    { ms: 5200 },
  ).catch(() => {});

  // ── 8. Outro ────────────────────────────────────────────────────────────────
  await caption(page, "AI Agent Fleet ✓", "Autonomous work, with humans on the controls");
  await beat(page, 3200);
  await clearCaption(page);
  await beat(page, 900);
});
