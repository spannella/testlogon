/**
 * E2E tests for the Projects feature.
 *
 * Sections:
 *   85 — Project CRUD API (6 tests)
 *   86 — Project File Tracking API (5 tests)
 *
 * Auth: Cookie-based session for Alice (e2e_alice@test.local) with CSRF.
 *
 * Endpoints under test:
 *   POST   /v1/projects
 *   GET    /v1/projects
 *   GET    /v1/projects/{project_id}
 *   PATCH  /v1/projects/{project_id}
 *   DELETE /v1/projects/{project_id}
 *   GET    /v1/projects/{project_id}/detail
 *   POST   /v1/projects/{project_id}/files
 *   GET    /v1/projects/{project_id}/files
 *   DELETE /v1/projects/{project_id}/files/{tracked_file_id}
 *   GET    /v1/projects/{project_id}/events
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
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
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
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

async function apiPatch(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.patch(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiDelete(page: Page, path: string) {
  const session = getSessions()[ALICE_ID];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── Section 85: Project CRUD ─────────────────────────────────────────────────

test.describe.serial("85 — Project CRUD API", () => {
  let page: Page;
  let projectId: string;
  const PROJECT_NAME = `E2E Project ${TS}`;
  const PROJECT_DESC = `Description for project ${TS}`;
  const UPDATED_NAME = `E2E Updated ${TS}`;
  const UPDATED_DESC = `Updated description ${TS}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("85.1 Create a new project", async () => {
    const resp = await apiPost(page, "/v1/projects", {
      name: PROJECT_NAME,
      description: PROJECT_DESC,
      tags: ["e2e", "test"],
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.id).toBeTruthy();
    expect(data.name).toBe(PROJECT_NAME);
    expect(data.description).toBe(PROJECT_DESC);
    expect(data.tags).toContain("e2e");
    expect(data.created_at).toBeTruthy();
    projectId = data.id;
  });

  test("85.2 List projects includes new project", async () => {
    const resp = await apiGet(page, "/v1/projects");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.items).toBeInstanceOf(Array);
    const found = data.items.find((p: any) => p.id === projectId);
    expect(found).toBeTruthy();
    expect(found.name).toBe(PROJECT_NAME);
  });

  test("85.3 Get project by id", async () => {
    const resp = await apiGet(page, `/v1/projects/${projectId}`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.id).toBe(projectId);
    expect(data.name).toBe(PROJECT_NAME);
    expect(data.description).toBe(PROJECT_DESC);
    expect(data.owner).toBeTruthy();
  });

  test("85.4 Update project name and description", async () => {
    const resp = await apiPatch(page, `/v1/projects/${projectId}`, {
      name: UPDATED_NAME,
      description: UPDATED_DESC,
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.name).toBe(UPDATED_NAME);
    expect(data.description).toBe(UPDATED_DESC);
    expect(data.id).toBe(projectId);
  });

  test("85.5 Get project detail returns project and files", async () => {
    const resp = await apiGet(page, `/v1/projects/${projectId}/detail`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.project).toBeTruthy();
    expect(data.project.id).toBe(projectId);
    expect(data.project.name).toBe(UPDATED_NAME);
    expect(data.files).toBeInstanceOf(Array);
  });

  test("85.6 Delete project", async () => {
    const resp = await apiDelete(page, `/v1/projects/${projectId}`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.ok).toBe(true);

    // Verify project is no longer accessible
    const getResp = await apiGet(page, `/v1/projects/${projectId}`);
    expect(getResp.ok()).toBe(false);
  });
});

// ─── DDB helpers ──────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os, time
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
`;

function injectFileNode(userSub: string, filePath: string, contentType = "text/plain"): void {
  const name = filePath.split("/").pop()!;
  const parent = filePath.substring(0, filePath.lastIndexOf("/")) || "/";
  execSync(
    `python3 -c "${DDB_PRELUDE}
tbl = ddb.Table('file_manager')
tbl.put_item(Item={
    'PK': 'USER#${userSub}',
    'SK': 'NODE#${filePath}',
    'type': 'file',
    'path': '${filePath}',
    'name': '${name}',
    'name_lc': '${name.toLowerCase()}',
    'parent': '${parent}',
    'content_type': '${contentType}',
    'size': 512,
    'created_at': str(int(time.time())),
    'updated_at': str(int(time.time())),
    's3_key': 'e2e/fake/${name}',
    's3_bucket': 'test-bucket',
})
print('node injected')
"`,
    { timeout: 10_000 },
  );
}

function cleanupFileNode(userSub: string, filePath: string): void {
  try {
    execSync(
      `python3 -c "${DDB_PRELUDE}
tbl = ddb.Table('file_manager')
tbl.delete_item(Key={'PK': 'USER#${userSub}', 'SK': 'NODE#${filePath}'})
print('node cleaned')
"`,
      { timeout: 10_000 },
    );
  } catch { /* ignore cleanup failures */ }
}

// ─── Section 86: Project File Tracking ────────────────────────────────────────

test.describe.serial("86 — Project File Tracking API", () => {
  let page: Page;
  let projectId: string;
  let trackedFileId1: string;
  let trackedFileId2: string;
  let aliceSub: string;
  const PROJECT_NAME = `E2E FileTrack ${TS}`;
  const FILE_REF_1 = `/e2e/readme_${TS}.md`;
  const FILE_REF_2 = `/e2e/spec_${TS}.pdf`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    aliceSub = getSessions()[ALICE_ID].user_sub;

    // Inject file nodes so local provider can find them
    injectFileNode(aliceSub, FILE_REF_1, "text/markdown");
    injectFileNode(aliceSub, FILE_REF_2, "application/pdf");

    // Create a project to track files in
    const resp = await apiPost(page, "/v1/projects", {
      name: PROJECT_NAME,
      description: "Project for file tracking tests",
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    projectId = data.id;
  });

  test.afterAll(async () => {
    // Cleanup: delete the project and file nodes
    await apiDelete(page, `/v1/projects/${projectId}`);
    cleanupFileNode(aliceSub, FILE_REF_1);
    cleanupFileNode(aliceSub, FILE_REF_2);
    await page.close();
  });

  test("86.1 Track a file in a project", async () => {
    const resp = await apiPost(page, `/v1/projects/${projectId}/files`, {
      provider: "local",
      provider_ref: FILE_REF_1,
      display_path: FILE_REF_1,
      metadata: { label: "README" },
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.id).toBeTruthy();
    expect(data.project_id).toBe(projectId);
    expect(data.provider).toBe("local");
    expect(data.provider_ref).toBe(FILE_REF_1);
    expect(data.display_path).toBe(FILE_REF_1);
    expect(data.status).toBeTruthy();
    trackedFileId1 = data.id;
  });

  test("86.2 List tracked files returns the file", async () => {
    const resp = await apiGet(page, `/v1/projects/${projectId}/files`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.items).toBeInstanceOf(Array);
    expect(data.items.length).toBeGreaterThanOrEqual(1);
    const found = data.items.find((f: any) => f.id === trackedFileId1);
    expect(found).toBeTruthy();
    expect(found.provider_ref).toBe(FILE_REF_1);
  });

  test("86.3 Track multiple files", async () => {
    const resp = await apiPost(page, `/v1/projects/${projectId}/files`, {
      provider: "local",
      provider_ref: FILE_REF_2,
      display_path: FILE_REF_2,
      metadata: { label: "Spec" },
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.id).toBeTruthy();
    trackedFileId2 = data.id;

    // Verify list now has 2 files
    const listResp = await apiGet(page, `/v1/projects/${projectId}/files`);
    expect(listResp.ok()).toBe(true);
    const listData = await listResp.json();
    expect(listData.items.length).toBeGreaterThanOrEqual(2);
  });

  test("86.4 Untrack a file", async () => {
    const resp = await apiDelete(
      page,
      `/v1/projects/${projectId}/files/${trackedFileId1}`,
    );
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.deleted).toBe(true);

    // Verify file is archived (not returned when filtering active)
    const listResp = await apiGet(
      page,
      `/v1/projects/${projectId}/files?status=active`,
    );
    expect(listResp.ok()).toBe(true);
    const listData = await listResp.json();
    const found = listData.items.find((f: any) => f.id === trackedFileId1);
    expect(found).toBeFalsy();
  });

  test("86.5 Project events log shows file tracking activity", async () => {
    const resp = await apiGet(page, `/v1/projects/${projectId}/events`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.items).toBeInstanceOf(Array);
    // Should have at least events from file track/untrack operations
    expect(data.items.length).toBeGreaterThanOrEqual(1);
    // Verify event structure
    const event = data.items[0];
    expect(event.id).toBeTruthy();
    expect(event.project_id).toBe(projectId);
    expect(event.event_type).toBeTruthy();
    expect(event.created_at).toBeTruthy();
  });
});
