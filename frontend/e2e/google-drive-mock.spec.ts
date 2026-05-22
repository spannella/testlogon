/**
 * E2E tests for Google Drive mount integration through the mock backend.
 *
 * Section 73 — Google Drive Mock Integration (5 tests)
 *
 * Prerequisites:
 *   - GOOGLE_DRIVE_MOCK_ENABLED=1 in .env.local
 *   - GOOGLE_DRIVE_API_BASE_URL=http://localhost:8000/mock/google-drive/drive/v3
 *   - GOOGLE_DRIVE_UPLOAD_API_BASE_URL=http://localhost:8000/mock/google-drive/upload/drive/v3
 *   - FILEMGR_GOOGLE_DRIVE_MOUNTS_ENABLED=true
 *   - KMS_KEY_ID set (mock KMS on port 7999)
 *
 * Auth: Alice session cookies (from e2e_admin_session_setup.py).
 *
 * The test seeds the mock Google Drive with files, creates a provider
 * credential and mount record directly in DDB, then exercises the real
 * file manager integration layer (list, download) through the mount.
 *
 * Mount and credential are created via Python/DDB because the FastAPI
 * route for creating Google Drive mounts (POST /v1/fs/mounts with
 * MountCreateIn) is shadowed by an earlier S3 mount route registered
 * at the same path. The file operations themselves go through the normal
 * HTTP endpoints and exercise the full GoogleDriveProvider code path.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync, execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

// ─── Constants ────────────────────────────────────────────────────────────────

const API  = "http://localhost:8000";
const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();
const MOUNT_PATH = `/gdrive_${TS}`;

// Seeded file IDs (deterministic for assertions)
const FOLDER_ID = `folder_${TS}`;
const FILE_A_ID = `fileA_${TS}`;
const FILE_B_ID = `fileB_${TS}`;
const NESTED_FILE_ID = `nested_${TS}`;

const VENV_PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface AdminSessionData {
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

let _sessions: Record<string, AdminSessionData> | null = null;
function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helper ──────────────────────────────────────────────────────────────

async function injectAuth(page: Page, identity = "alice") {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
}

// ─── API helpers (via Vite proxy so session cookies are forwarded) ─────────────

function csrfHeaders(identity = "alice"): Record<string, string> {
  const session = getSessions()[identity];
  return {
    "x-csrf-token": session.csrf_token,
    "Content-Type": "application/json",
  };
}

async function apiGet(page: Page, apiPath: string) {
  return page.request.get(`${BASE}${apiPath}`);
}

async function apiPost(page: Page, apiPath: string, body: object, identity = "alice") {
  return page.request.post(`${BASE}${apiPath}`, {
    data: body,
    headers: csrfHeaders(identity),
  });
}

// ─── Python helper ────────────────────────────────────────────────────────────

/**
 * Run a multi-line Python script by writing it to a temp file.
 * Uses the project venv so that app modules (fastapi, etc.) are available.
 * Returns stdout.
 */
function runPython(script: string): string {
  const tmpFile = path.join(
    os.tmpdir(),
    `e2e_gdrive_${Date.now()}_${Math.random().toString(36).slice(2)}.py`,
  );
  fs.writeFileSync(tmpFile, script, "utf-8");
  try {
    return execFileSync(VENV_PYTHON, [tmpFile], {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString().trim();
  } finally {
    try { fs.unlinkSync(tmpFile); } catch { /* best-effort */ }
  }
}

const DDB_PRELUDE = `
import boto3, os, json, time, sys, uuid
from pathlib import Path
from datetime import datetime, timezone
env_file = Path('/home/ubuntu/testlogon/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
sys.path.insert(0, '/home/ubuntu/testlogon')
ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
projects_table = ddb.Table(os.environ.get('PROJECTS_TABLE_NAME', 'projects'))
`;

/**
 * Seed a provider credential for google_drive AND create a mount record.
 * Returns the mount_id as a string.
 */
function seedMountAndCredential(
  owner: string,
  token: string,
  mountPath: string,
): string {
  const out = runPython(`${DDB_PRELUDE}
from app.core.crypto import kms_encrypt

owner = ${JSON.stringify(owner)}
token_text = ${JSON.stringify(token)}
mount_path = ${JSON.stringify(mountPath)}

# Normalize mount_path (ensure trailing slash)
if not mount_path.endswith('/'):
    mount_path = mount_path + '/'

# 1. Upsert provider credential (encrypted via mock KMS)
token_ct_b64 = kms_encrypt(token_text)
ts = datetime.now(timezone.utc).isoformat()

projects_table.put_item(Item={
    'PK': f'OWNER#{owner}',
    'SK': 'PROVIDER_CRED#google_drive#self',
    'entity_type': 'provider_credential',
    'owner': owner,
    'provider': 'google_drive',
    'org': None,
    'token_ct_b64': token_ct_b64,
    'scopes': ['https://www.googleapis.com/auth/drive.file'],
    'metadata': {},
    'created_at': ts,
    'updated_at': ts,
})

# 2. Create mount record directly in projects table
mount_id = str(uuid.uuid4())
projects_table.put_item(Item={
    'PK': f'OWNER#{owner}',
    'SK': f'MOUNT#{mount_id}',
    'entity_type': 'fs_mount',
    'mount_id': mount_id,
    'owner': owner,
    'provider': 'google_drive',
    'mount_path': mount_path,
    'provider_root_ref': 'gdrive://me/items/root',
    'mode': 'read_write',
    'status': 'active',
    'status_reason': None,
    'reconnect_required': False,
    'last_checked_at': None,
    'created_at': ts,
    'updated_at': ts,
})
print(mount_id)
`);
  if (!out) {
    throw new Error("seedMountAndCredential returned no mount_id");
  }
  return out;
}

/**
 * Clean up: remove the provider credential and any mount entries for the owner.
 */
function cleanupAll(owner: string): void {
  runPython(`${DDB_PRELUDE}
from boto3.dynamodb.conditions import Key as DDBKey

owner = ${JSON.stringify(owner)}

# Delete provider credential
try:
    projects_table.delete_item(Key={
        'PK': f'OWNER#{owner}',
        'SK': 'PROVIDER_CRED#google_drive#self',
    })
except Exception:
    pass

# Delete all mounts for this owner
resp = projects_table.query(
    KeyConditionExpression=DDBKey('PK').eq(f'OWNER#{owner}') & DDBKey('SK').begins_with('MOUNT#'),
)
for item in resp.get('Items', []):
    projects_table.delete_item(Key={'PK': item['PK'], 'SK': item['SK']})
print('OK')
`);
}

/**
 * Delete a specific mount from DDB.
 */
function deleteMountFromDDB(owner: string, mountId: string): void {
  runPython(`${DDB_PRELUDE}
owner = ${JSON.stringify(owner)}
mount_id = ${JSON.stringify(mountId)}
projects_table.delete_item(Key={
    'PK': f'OWNER#{owner}',
    'SK': f'MOUNT#{mount_id}',
})
print('OK')
`);
}

// ─── Tests ────────────────────────────────────────────────────────────────────

test.describe("73 — Google Drive Mock Integration", () => {
  let alicePage: Page;
  let mountId: string;

  test.beforeAll(async ({ browser }) => {
    // 1. Get sessions
    getSessions();

    // 2. Create a page with Alice's cookies
    alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");

    // 3. Clean up any leftover mounts / credentials for Alice
    cleanupAll(ALICE_ID);
  });

  test.afterAll(async () => {
    // Reset mock drive state
    try {
      await alicePage.request.post(`${API}/mock/google-drive/reset`);
    } catch {
      // ignore
    }

    // Clean up DDB state
    cleanupAll(ALICE_ID);

    await alicePage.close();
  });

  test("73.1 seed mock Google Drive and create mount", async () => {
    // Reset mock drive
    const resetResp = await alicePage.request.post(`${API}/mock/google-drive/reset`);
    expect(resetResp.status()).toBe(200);

    // Seed files: a root folder, a subfolder with nested file, and two files under root.
    // The "root" entry must exist because GoogleDriveProvider resolves it.
    const fileAContent = Buffer.from("Hello from file A").toString("base64");
    const nestedContent = Buffer.from("Nested file content").toString("base64");
    const seedResp = await alicePage.request.post(`${API}/mock/google-drive/seed`, {
      data: {
        files: [
          {
            id: "root",
            name: "My Drive",
            mimeType: "application/vnd.google-apps.folder",
            parents: [],
            size: "0",
          },
          {
            id: FOLDER_ID,
            name: "TestFolder",
            mimeType: "application/vnd.google-apps.folder",
            parents: ["root"],
            size: "0",
          },
          {
            id: FILE_A_ID,
            name: "file_a.txt",
            mimeType: "text/plain",
            parents: ["root"],
            size: String("Hello from file A".length),
          },
          {
            id: FILE_B_ID,
            name: "file_b.txt",
            mimeType: "text/plain",
            parents: ["root"],
            size: "12",
          },
          {
            id: NESTED_FILE_ID,
            name: "nested.txt",
            mimeType: "text/plain",
            parents: [FOLDER_ID],
            size: String("Nested file content".length),
          },
        ],
        file_content: {
          [FILE_A_ID]: fileAContent,
          [NESTED_FILE_ID]: nestedContent,
        },
      },
      headers: { "Content-Type": "application/json" },
    });
    expect(seedResp.status()).toBe(200);
    const seedBody = await seedResp.json();
    expect(seedBody.ok).toBe(true);
    expect(seedBody.seeded_files).toBe(5);
    expect(seedBody.seeded_content).toBe(2);

    // Create mount + provider credential via DDB
    mountId = seedMountAndCredential(ALICE_ID, "e2e-mock-gdrive-token", MOUNT_PATH);
    expect(mountId).toBeTruthy();
  });

  test("73.2 list files through mount shows seeded files", async () => {
    expect(mountId).toBeTruthy();
    const resp = await apiGet(
      alicePage,
      `/v1/fs/list?path=${encodeURIComponent(MOUNT_PATH + "/")}`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.items).toBeDefined();
    expect(Array.isArray(body.items)).toBe(true);

    const names = (body.items as Array<{ name: string }>).map((i) => i.name);
    expect(names).toContain("TestFolder");
    expect(names).toContain("file_a.txt");
    expect(names).toContain("file_b.txt");

    // Verify folder vs file types
    const folder = (body.items as Array<{ name: string; type: string }>).find(
      (i) => i.name === "TestFolder",
    );
    expect(folder).toBeTruthy();
    expect(folder!.type).toBe("folder");

    const fileA = (body.items as Array<{ name: string; type: string }>).find(
      (i) => i.name === "file_a.txt",
    );
    expect(fileA).toBeTruthy();
    expect(fileA!.type).toBe("file");
  });

  test("73.3 list subfolder through mount", async () => {
    expect(mountId).toBeTruthy();
    const subPath = `${MOUNT_PATH}/TestFolder/`;
    const resp = await apiGet(
      alicePage,
      `/v1/fs/list?path=${encodeURIComponent(subPath)}`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.items).toBeDefined();
    expect(Array.isArray(body.items)).toBe(true);
    expect(body.items.length).toBeGreaterThanOrEqual(1);

    const names = (body.items as Array<{ name: string }>).map((i) => i.name);
    expect(names).toContain("nested.txt");
  });

  test("73.4 download file through mount", async () => {
    expect(mountId).toBeTruthy();
    const downloadPath = `${MOUNT_PATH}/file_a.txt`;
    const resp = await apiGet(
      alicePage,
      `/v1/fs/download?path=${encodeURIComponent(downloadPath)}`,
    );
    expect(resp.status()).toBe(200);
    const text = await resp.text();
    expect(text).toBe("Hello from file A");
  });

  test("73.5 delete mount removes it from listing", async () => {
    expect(mountId).toBeTruthy();

    // Delete the mount from DDB
    deleteMountFromDDB(ALICE_ID, mountId);

    // Verify listing at the mount path now returns no items
    // (path falls through to local storage which has nothing there)
    const listResp = await apiGet(
      alicePage,
      `/v1/fs/list?path=${encodeURIComponent(MOUNT_PATH + "/")}`,
    );
    const body = await listResp.json();
    const items = body.items ?? [];
    expect(items.length).toBe(0);
  });
});
