/**
 * E2E tests for the Payment Disputes / Incidents feature.
 *
 * Sections:
 *   80 — Customer payment issues API (3 tests)
 *   81 — Admin incident list + filters API (3 tests)
 *   82 — Admin incident detail + evidence + response API (4 tests)
 *   83 — Access control (3 tests)
 *
 * Auth: uses e2e_admin_session_setup.py (all identities)
 *
 * Identities:
 *   root          – root.admin@testdev.local  – role=root  (billing admin)
 *   alice         – e2e_alice@test.local      – role=user  (customer)
 *   charlie_admin – e2e_charlie@test.local    – role=admin (general; has billing_support implicitly)
 *   charlie_scoped – e2e_charlie@test.local   – role=admin (scoped to auth_support; NO billing_support)
 *
 * DynamoDB tables used:
 *   payment_incidents, payment_incident_events, payment_dispute_evidence,
 *   payment_retry_attempts, payment_incident_ticket_links
 *
 * The subsidiary tables (events, evidence, retries, ticket_links) may not exist
 * in a fresh DDB instance — ensureTables() creates them if missing.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const TS       = Date.now();
const ALICE_ID = "e2e_alice@test.local";
const ROOT_SUB = "root.admin@testdev.local";

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name:     string;
    value:    string;
    domain:   string;
    path:     string;
    httpOnly: boolean;
    secure:   boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires:  number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ─── Page factory ─────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}${path}`, { params });
}

// ─── DDB helpers ──────────────────────────────────────────────────────────────

const DDB_PY_PRELUDE = `
import boto3, time
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1',
                     aws_access_key_id='test', aws_secret_access_key='test')
ddb_client = boto3.client('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1',
                          aws_access_key_id='test', aws_secret_access_key='test')
`;

/**
 * Ensure all subsidiary payment-incident DDB tables exist.
 * The main `payment_incidents` table is created by local-ddb-init.py;
 * the events / evidence / retries / ticket_links tables may not be.
 */
function ensureTables(): void {
  execSync(
    `python3 -c "${DDB_PY_PRELUDE}
for tname, pk, sk in [
    ('payment_incident_events',       'incident_id', 'event_ts_id'),
    ('payment_dispute_evidence',      'incident_id', 'version'),
    ('payment_retry_attempts',        'incident_id', 'attempt_id'),
    ('payment_incident_ticket_links', 'incident_id', None),
]:
    key_schema = [{'AttributeName': pk, 'KeyType': 'HASH'}]
    attr_defs  = [{'AttributeName': pk, 'AttributeType': 'S'}]
    if sk:
        key_schema.append({'AttributeName': sk, 'KeyType': 'RANGE'})
        attr_defs.append({'AttributeName': sk, 'AttributeType': 'S'})
    try:
        ddb_client.create_table(
            TableName=tname,
            KeySchema=key_schema,
            AttributeDefinitions=attr_defs,
            BillingMode='PAY_PER_REQUEST',
        )
    except ddb_client.exceptions.ResourceInUseException:
        pass
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

function seedIncident(opts: {
  incidentId: string;
  provider: string;
  incidentType: string;
  status: string;
  accountId: string;
  paymentReference?: string;
  amount?: string;
}): void {
  const ref = opts.paymentReference ?? `pi_${opts.incidentId}`;
  const amt = opts.amount ?? "5000";
  execSync(
    `python3 -c "${DDB_PY_PRELUDE}
table = ddb.Table('payment_incidents')
table.put_item(Item={
    'incident_id': '${opts.incidentId}',
    'provider': '${opts.provider}',
    'provider_incident_id': '${opts.provider}_${opts.incidentId}',
    'incident_type': '${opts.incidentType}',
    'status': '${opts.status}',
    'account_id': '${opts.accountId}',
    'customer_id': '${opts.accountId}',
    'payment_reference': '${ref}',
    'amount': '${amt}',
    'currency': 'usd',
    'created_at': str(int(time.time())),
    'updated_at': str(int(time.time())),
    'provider_incident_key': '${opts.provider}#${opts.provider}_${opts.incidentId}',
    'response_due_scope': 'ALL',
    'response_due_at': '9999999999',
})
"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

function deleteIncident(incidentId: string): void {
  execSync(
    `python3 -c "${DDB_PY_PRELUDE}
ddb.Table('payment_incidents').delete_item(Key={'incident_id': '${incidentId}'})
"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

function cleanupIncidentArtifacts(incidentId: string): void {
  execSync(
    `python3 -c "${DDB_PY_PRELUDE}
from boto3.dynamodb.conditions import Key

# events
t = ddb.Table('payment_incident_events')
for item in t.query(KeyConditionExpression=Key('incident_id').eq('${incidentId}')).get('Items', []):
    t.delete_item(Key={'incident_id': item['incident_id'], 'event_ts_id': item['event_ts_id']})

# evidence
t2 = ddb.Table('payment_dispute_evidence')
for item in t2.query(KeyConditionExpression=Key('incident_id').eq('${incidentId}')).get('Items', []):
    t2.delete_item(Key={'incident_id': item['incident_id'], 'version': item['version']})

# retries
t3 = ddb.Table('payment_retry_attempts')
for item in t3.query(KeyConditionExpression=Key('incident_id').eq('${incidentId}')).get('Items', []):
    t3.delete_item(Key={'incident_id': item['incident_id'], 'attempt_id': item['attempt_id']})

# ticket links
t4 = ddb.Table('payment_incident_ticket_links')
try:
    t4.delete_item(Key={'incident_id': '${incidentId}'})
except Exception:
    pass
"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 80 — Customer payment issues API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 80: Customer payment issues API", () => {
  let alicePage: Page;
  const INC_FAILURE = `e2e_custfail_${TS}`;
  const INC_DISPUTE = `e2e_custdisp_${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    ensureTables();
    alicePage = await newIdentityPage(browser, "alice");

    // Seed a payment_failure incident owned by Alice
    seedIncident({
      incidentId: INC_FAILURE,
      provider: "stripe",
      incidentType: "payment_failure",
      status: "customer_action_required",
      accountId: ALICE_ID,
      amount: "2500",
    });

    // Seed a dispute incident owned by Alice — should NOT appear in payment-issues
    seedIncident({
      incidentId: INC_DISPUTE,
      provider: "stripe",
      incidentType: "dispute",
      status: "opened",
      accountId: ALICE_ID,
      amount: "7500",
    });
  });

  test.afterAll(async () => {
    deleteIncident(INC_FAILURE);
    cleanupIncidentArtifacts(INC_FAILURE);
    deleteIncident(INC_DISPUTE);
    cleanupIncidentArtifacts(INC_DISPUTE);
    await alicePage?.close();
  });

  test("80.1 — Alice lists her payment issues (only payment_failure type)", async () => {
    const resp = await apiGet(alicePage, "/ui/billing/payment-issues");
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { items: Array<Record<string, unknown>>; count: number };
    // Must include the payment_failure incident
    const failureItem = data.items.find((i) => i.incident_id === INC_FAILURE);
    expect(failureItem).toBeTruthy();
    expect(failureItem!.incident_type).toBe("payment_failure");
    expect(failureItem!.amount).toBe("2500");
    // Must NOT include the dispute incident (customer list filters to payment_failure)
    const disputeItem = data.items.find((i) => i.incident_id === INC_DISPUTE);
    expect(disputeItem).toBeUndefined();
  });

  test("80.2 — Alice confirm-and-retry on her payment failure", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `/ui/billing/payment-issues/${INC_FAILURE}/confirm-and-retry`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.ok).toBe("boolean");
    expect(typeof data.code).toBe("string");
    expect(data.attempt).toBeTruthy();
  });

  test("80.3 — Alice retry-automatic-payment on her payment failure", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `/ui/billing/payment-issues/${INC_FAILURE}/retry-automatic-payment`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.ok).toBe("boolean");
    expect(typeof data.code).toBe("string");
    expect(data.attempt).toBeTruthy();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 81 — Admin incident list + filters API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 81: Admin incident list + filters API", () => {
  let rootPage: Page;
  const INC_STRIPE_DISPUTE  = `e2e_adm_sd_${TS}`;
  const INC_PAYPAL_FAILURE  = `e2e_adm_pf_${TS}`;
  const INC_STRIPE_CHARGEBK = `e2e_adm_sc_${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    ensureTables();
    rootPage = await newIdentityPage(browser, "root");

    seedIncident({
      incidentId: INC_STRIPE_DISPUTE,
      provider: "stripe",
      incidentType: "dispute",
      status: "opened",
      accountId: ALICE_ID,
      amount: "10000",
    });
    seedIncident({
      incidentId: INC_PAYPAL_FAILURE,
      provider: "paypal",
      incidentType: "payment_failure",
      status: "failed_initial",
      accountId: ALICE_ID,
      amount: "3000",
    });
    seedIncident({
      incidentId: INC_STRIPE_CHARGEBK,
      provider: "stripe",
      incidentType: "chargeback",
      status: "opened",
      accountId: ALICE_ID,
      amount: "5000",
    });
  });

  test.afterAll(async () => {
    for (const id of [INC_STRIPE_DISPUTE, INC_PAYPAL_FAILURE, INC_STRIPE_CHARGEBK]) {
      deleteIncident(id);
      cleanupIncidentArtifacts(id);
    }
    await rootPage?.close();
  });

  test("81.1 — Admin lists all incidents (unfiltered)", async () => {
    const resp = await apiGet(rootPage, "/api/admin/payment-incidents");
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { items: Array<Record<string, unknown>>; count: number };
    expect(data.items.length).toBeGreaterThanOrEqual(3);
    const ids = data.items.map((i) => i.incident_id);
    expect(ids).toContain(INC_STRIPE_DISPUTE);
    expect(ids).toContain(INC_PAYPAL_FAILURE);
    expect(ids).toContain(INC_STRIPE_CHARGEBK);
  });

  test("81.2 — Admin filters by provider=stripe", async () => {
    const resp = await apiGet(rootPage, "/api/admin/payment-incidents", { provider: "stripe" });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { items: Array<Record<string, unknown>>; count: number };
    const ids = data.items.map((i) => i.incident_id);
    expect(ids).toContain(INC_STRIPE_DISPUTE);
    expect(ids).toContain(INC_STRIPE_CHARGEBK);
    expect(ids).not.toContain(INC_PAYPAL_FAILURE);
  });

  test("81.3 — Admin filters by incident_type=dispute and status=opened", async () => {
    const resp = await apiGet(rootPage, "/api/admin/payment-incidents", {
      incident_type: "dispute",
      status: "opened",
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { items: Array<Record<string, unknown>>; count: number };
    const ids = data.items.map((i) => i.incident_id);
    expect(ids).toContain(INC_STRIPE_DISPUTE);
    // payment_failure should be filtered out by incident_type
    expect(ids).not.toContain(INC_PAYPAL_FAILURE);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 82 — Admin incident detail + evidence + response API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 82: Admin incident detail, evidence upload, and submit response API", () => {
  let rootPage: Page;
  const INC_DETAIL = `e2e_detail_${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    ensureTables();
    rootPage = await newIdentityPage(browser, "root");

    seedIncident({
      incidentId: INC_DETAIL,
      provider: "stripe",
      incidentType: "dispute",
      status: "evidence_required",
      accountId: ALICE_ID,
      amount: "8000",
    });
  });

  test.afterAll(async () => {
    deleteIncident(INC_DETAIL);
    cleanupIncidentArtifacts(INC_DETAIL);
    await rootPage?.close();
  });

  test("82.1 — Admin gets incident detail", async () => {
    const resp = await apiGet(rootPage, `/api/admin/payment-incidents/${INC_DETAIL}`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as Record<string, unknown>;
    expect(data.incident_id).toBe(INC_DETAIL);
    expect(data.incident_type).toBe("dispute");
    expect(data.status).toBe("evidence_required");
    expect(data.provider).toBe("stripe");
    expect(data.amount).toBe("8000");
    // Detail endpoint includes events, evidence_versions, ticket_link
    expect(Array.isArray(data.events)).toBe(true);
    expect(Array.isArray(data.evidence_versions)).toBe(true);
  });

  test("82.2 — Admin uploads evidence for dispute", async () => {
    const resp = await apiPost(rootPage, "root", `/api/admin/payment-incidents/${INC_DETAIL}/evidence`, {
      summary: `E2E evidence summary ${TS}`,
      file_refs: ["receipt_001.pdf", "shipping_proof.pdf"],
      evidence_items: [
        { type: "receipt", description: "Purchase receipt" },
        { type: "shipping", description: "Shipping confirmation" },
      ],
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as {
      incident_id: string;
      version: number;
      evidence: Record<string, unknown>;
      event: Record<string, unknown>;
    };
    expect(data.incident_id).toBe(INC_DETAIL);
    expect(data.version).toBe(1);
    expect(data.evidence).toBeTruthy();
    expect(data.event).toBeTruthy();
    expect(data.event.event_type).toBe("evidence_uploaded");

    // Verify evidence appears in detail
    const detailResp = await apiGet(rootPage, `/api/admin/payment-incidents/${INC_DETAIL}`);
    const detail = (await detailResp.json()) as Record<string, unknown>;
    const evidenceVersions = detail.evidence_versions as Array<Record<string, unknown>>;
    expect(evidenceVersions.length).toBeGreaterThanOrEqual(1);
  });

  test("82.3 — Admin submits response for dispute", async () => {
    const resp = await apiPost(rootPage, "root", `/api/admin/payment-incidents/${INC_DETAIL}/submit-response`, {
      response_summary: `We have proof of delivery ${TS}`,
      rationale: "Customer received the product as confirmed by tracking",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.ok).toBe("boolean");
    if (data.ok) {
      expect(data.incident.status).toBe("response_submitted");
    } else {
      expect(typeof data.provider_code).toBe("string");
    }
  });

  test("82.4 — Evidence upload returns 400 for non-dispute incident", async () => {
    // Seed a payment_failure incident
    const incNonDispute = `e2e_nondispute_${TS}`;
    seedIncident({
      incidentId: incNonDispute,
      provider: "stripe",
      incidentType: "payment_failure",
      status: "customer_action_required",
      accountId: ALICE_ID,
    });

    try {
      const resp = await apiPost(rootPage, "root", `/api/admin/payment-incidents/${incNonDispute}/evidence`, {
        summary: "Test evidence",
        file_refs: [],
        evidence_items: [],
      });
      expect(resp.status()).toBe(400);
      const body = (await resp.json()) as { detail: { code: string } };
      expect(body.detail.code).toBe("payment_incident_not_dispute");

      // Also test submit-response on non-dispute
      const resp2 = await apiPost(rootPage, "root", `/api/admin/payment-incidents/${incNonDispute}/submit-response`, {
        response_summary: "Test",
        rationale: "Test",
      });
      expect(resp2.status()).toBe(400);
      const body2 = (await resp2.json()) as { detail: { code: string } };
      expect(body2.detail.code).toBe("payment_incident_not_dispute");
    } finally {
      deleteIncident(incNonDispute);
      cleanupIncidentArtifacts(incNonDispute);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 83 — Access control
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 83: Access control", () => {
  let alicePage:    Page;
  let scopedPage:   Page;
  let rootPage:     Page;
  const INC_AC = `e2e_ac_${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    ensureTables();
    alicePage  = await newIdentityPage(browser, "alice");
    scopedPage = await newIdentityPage(browser, "charlie_scoped");
    rootPage   = await newIdentityPage(browser, "root");

    seedIncident({
      incidentId: INC_AC,
      provider: "stripe",
      incidentType: "dispute",
      status: "opened",
      accountId: "someone_else@test.local",
    });
  });

  test.afterAll(async () => {
    deleteIncident(INC_AC);
    cleanupIncidentArtifacts(INC_AC);
    await alicePage?.close();
    await scopedPage?.close();
    await rootPage?.close();
  });

  test("83.1 — Regular user (Alice) cannot access admin incidents list", async () => {
    const resp = await apiGet(alicePage, "/api/admin/payment-incidents");
    expect(resp.status()).toBe(403);
  });

  test("83.2 — Scoped admin without billing_support cannot access admin incidents", async () => {
    const resp = await apiGet(scopedPage, "/api/admin/payment-incidents");
    expect(resp.status()).toBe(403);

    // Also verify scoped admin cannot upload evidence
    const resp2 = await apiPost(scopedPage, "charlie_scoped", `/api/admin/payment-incidents/${INC_AC}/evidence`, {
      summary: "Unauthorized",
      file_refs: [],
      evidence_items: [],
    });
    expect(resp2.status()).toBe(403);
  });

  test("83.3 — 404 for non-existent incident (admin detail + customer retry)", async () => {
    const fakeId = `nonexistent_${TS}`;

    // Admin detail: 404
    const adminResp = await apiGet(rootPage, `/api/admin/payment-incidents/${fakeId}`);
    expect(adminResp.status()).toBe(404);
    const adminBody = (await adminResp.json()) as { detail: { code: string } };
    expect(adminBody.detail.code).toBe("payment_incident_not_found");

    // Customer confirm-and-retry on non-existent: 404
    const custResp = await apiPost(
      alicePage,
      "alice",
      `/ui/billing/payment-issues/${fakeId}/confirm-and-retry`,
    );
    expect(custResp.status()).toBe(404);
    const custBody = (await custResp.json()) as { detail: { code: string } };
    expect(custBody.detail.code).toBe("payment_issue_not_found");
  });
});
