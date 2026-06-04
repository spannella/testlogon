/**
 * E2E tests for SSH Key Manager (INFRA-002).
 *
 * Sections:
 *   244 -- Key Generation API  (5 tests)
 *   245 -- Key Upload API      (4 tests)
 *   246 -- Key Association & Deletion API (5 tests)
 *   247 -- SSH Key Manager UI  (4 tests)
 *
 * Auth: Alice + Bob session cookies (from e2e_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

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

// ─── API helpers ──────────────────────────────────────────────────────────────

function csrfHeader(userId: string) {
  return { "x-csrf-token": getSessions()[userId].csrf_token };
}

async function apiPost(page: Page, userId: string, path: string, body: object) {
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: csrfHeader(userId),
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiDelete(page: Page, userId: string, path: string) {
  return page.request.delete(`${BASE}${path}`, {
    headers: csrfHeader(userId),
  });
}

// ─── Test RSA key generation (via Python) ─────────────────────────────────────

function generateTestRsaKey(): string {
  const result = execSync(
    `python3 -c "
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.OpenSSH,
    encryption_algorithm=serialization.NoEncryption(),
)
print(pem.decode('utf-8'), end='')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
  return result.toString();
}

function generateTestRsaKeyWithPassphrase(): { pem: string; passphrase: string } {
  const passphrase = "test-passphrase-123";
  const result = execSync(
    `python3 -c "
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.OpenSSH,
    encryption_algorithm=serialization.BestAvailableEncryption(b'${passphrase}'),
)
print(pem.decode('utf-8'), end='')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
  return { pem: result.toString(), passphrase };
}

// ─── Cleanup helper ───────────────────────────────────────────────────────────

async function deleteAllKeys(page: Page, userId: string) {
  const resp = await apiGet(page, "/ui/remote/ssh-keys");
  if (resp.ok()) {
    const data = await resp.json();
    for (const key of data.keys || []) {
      await apiDelete(page, userId, `/ui/remote/ssh-keys/${key.key_id}`);
    }
  }
}

// ─── Test State ───────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let testRsaPem: string;
let testRsaPassphrase: { pem: string; passphrase: string };

// Track generated key IDs for cross-test references
let generatedEd25519KeyId: string;
let generatedRsaKeyId: string;
let uploadedRsaKeyId: string;

// =============================================================================
// Section 244: Key Generation API
// =============================================================================

test.describe("244 -- Key Generation API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    // Clean up any keys from previous runs
    await deleteAllKeys(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await deleteAllKeys(alicePage, ALICE_ID);
    await alicePage.close();
  });

  test("Alice generates an Ed25519 key", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/ssh-keys/generate", {
      label: `Ed25519 Test ${TS}`,
      key_type: "ed25519",
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.key_type).toBe("ed25519");
    expect(body.key_bits).toBe(256);
    expect(body.public_key_openssh).toMatch(/^ssh-ed25519 /);
    expect(body.public_key_fingerprint).toMatch(/^SHA256:/);
    expect(body.label).toBe(`Ed25519 Test ${TS}`);
    expect(body.key_id).toBeTruthy();
    generatedEd25519KeyId = body.key_id;
  });

  test("Alice generates an RSA 4096 key", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/ssh-keys/generate", {
      label: `RSA Test ${TS}`,
      key_type: "rsa",
      key_bits: 4096,
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.key_type).toBe("rsa");
    expect(body.key_bits).toBe(4096);
    expect(body.public_key_openssh).toMatch(/^ssh-rsa /);
    generatedRsaKeyId = body.key_id;
  });

  test("Generated key metadata does not contain private key", async () => {
    const resp = await apiGet(alicePage, `/ui/remote/ssh-keys/${generatedEd25519KeyId}`);
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body).not.toHaveProperty("encrypted_private_key_blob");
    expect(body).not.toHaveProperty("private_key");
    expect(body).not.toHaveProperty("private_key_pem");
  });

  test("Public key export returns copyable format", async () => {
    const resp = await apiGet(alicePage, `/ui/remote/ssh-keys/${generatedEd25519KeyId}/public`);
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.public_key_openssh).toMatch(/^ssh-ed25519 /);
    expect(body.public_key_fingerprint).toMatch(/^SHA256:/);
    expect(body.key_id).toBe(generatedEd25519KeyId);
  });

  test("List keys returns all user keys", async () => {
    const resp = await apiGet(alicePage, "/ui/remote/ssh-keys");
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.count).toBeGreaterThanOrEqual(2);
    const ids = body.keys.map((k: any) => k.key_id);
    expect(ids).toContain(generatedEd25519KeyId);
    expect(ids).toContain(generatedRsaKeyId);
  });
});

// =============================================================================
// Section 245: Key Upload API
// =============================================================================

test.describe("245 -- Key Upload API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await deleteAllKeys(alicePage, ALICE_ID);

    // Generate test keys
    testRsaPem = generateTestRsaKey();
    testRsaPassphrase = generateTestRsaKeyWithPassphrase();
  });

  test.afterAll(async () => {
    await deleteAllKeys(alicePage, ALICE_ID);
    await alicePage.close();
  });

  test("Alice uploads an RSA private key", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/ssh-keys", {
      label: `Uploaded RSA ${TS}`,
      private_key_pem: testRsaPem,
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.key_type).toBe("rsa");
    expect(body.public_key_fingerprint).toMatch(/^SHA256:/);
    expect(body.passphrase_protected).toBe(false);
    uploadedRsaKeyId = body.key_id;
  });

  test("Alice uploads a passphrase-protected key", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/ssh-keys", {
      label: `Protected Key ${TS}`,
      private_key_pem: testRsaPassphrase.pem,
      passphrase: testRsaPassphrase.passphrase,
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.passphrase_protected).toBe(true);
  });

  test("Upload rejects invalid PEM", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/ssh-keys", {
      label: "Bad Key",
      private_key_pem: "not a key but long enough to pass validation min length for the field",
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail).toMatch(/[Ii]nvalid/);
  });

  test("Upload without passphrase for protected key returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/ssh-keys", {
      label: "Missing Passphrase",
      private_key_pem: testRsaPassphrase.pem,
      // no passphrase provided
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail).toMatch(/[Pp]assphrase/);
  });
});

// =============================================================================
// Section 246: Key Association & Deletion API
// =============================================================================

test.describe("246 -- Key Association & Deletion API", () => {
  let keyId1: string;
  let keyId2: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
    await deleteAllKeys(alicePage, ALICE_ID);
    await deleteAllKeys(bobPage, BOB_ID);

    // Generate two keys for Alice
    const r1 = await apiPost(alicePage, ALICE_ID, "/ui/remote/ssh-keys/generate", {
      label: `Assoc Key 1 ${TS}`,
      key_type: "ed25519",
    });
    keyId1 = (await r1.json()).key_id;

    const r2 = await apiPost(alicePage, ALICE_ID, "/ui/remote/ssh-keys/generate", {
      label: `Assoc Key 2 ${TS}`,
      key_type: "ed25519",
    });
    keyId2 = (await r2.json()).key_id;
  });

  test.afterAll(async () => {
    await deleteAllKeys(alicePage, ALICE_ID);
    await deleteAllKeys(bobPage, BOB_ID);
    await alicePage.close();
    await bobPage.close();
  });

  test("Associate key with host", async () => {
    const hostId = `host_${TS}_1`;
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/remote/ssh-keys/${keyId1}/associate`, {
      host_id: hostId,
    });
    expect(resp.ok()).toBe(true);

    // Verify key metadata shows association
    const getResp = await apiGet(alicePage, `/ui/remote/ssh-keys/${keyId1}`);
    const body = await getResp.json();
    expect(body.associated_hosts).toContain(hostId);
  });

  test("Disassociate key from host", async () => {
    const hostId = `host_${TS}_2`;
    // Associate first
    await apiPost(alicePage, ALICE_ID, `/ui/remote/ssh-keys/${keyId1}/associate`, {
      host_id: hostId,
    });

    // Disassociate
    const resp = await apiDelete(alicePage, ALICE_ID, `/ui/remote/ssh-keys/${keyId1}/associate/${hostId}`);
    expect(resp.ok()).toBe(true);

    // Verify removed
    const getResp = await apiGet(alicePage, `/ui/remote/ssh-keys/${keyId1}`);
    const body = await getResp.json();
    expect(body.associated_hosts).not.toContain(hostId);
  });

  test("Delete key removes it from list", async () => {
    const resp = await apiDelete(alicePage, ALICE_ID, `/ui/remote/ssh-keys/${keyId2}`);
    expect(resp.ok()).toBe(true);

    // Verify not in list
    const listResp = await apiGet(alicePage, "/ui/remote/ssh-keys");
    const body = await listResp.json();
    const ids = body.keys.map((k: any) => k.key_id);
    expect(ids).not.toContain(keyId2);
  });

  test("Alice cannot access Bob's keys", async () => {
    // Bob generates a key
    const resp = await apiPost(bobPage, BOB_ID, "/ui/remote/ssh-keys/generate", {
      label: `Bob Key ${TS}`,
      key_type: "ed25519",
    });
    const bobKeyId = (await resp.json()).key_id;

    // Alice tries to get Bob's key -> 404 (partition isolation)
    const getResp = await apiGet(alicePage, `/ui/remote/ssh-keys/${bobKeyId}`);
    expect(getResp.status()).toBe(404);

    // Alice tries to delete Bob's key -> 404
    const delResp = await apiDelete(alicePage, ALICE_ID, `/ui/remote/ssh-keys/${bobKeyId}`);
    expect(delResp.status()).toBe(404);
  });

  test("Get non-existent key returns 404", async () => {
    const resp = await apiGet(alicePage, "/ui/remote/ssh-keys/nonexistent_key_id");
    expect(resp.status()).toBe(404);
  });
});

// =============================================================================
// Section 247: SSH Key Manager UI
// =============================================================================

test.describe("247 -- SSH Key Manager UI", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await deleteAllKeys(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await deleteAllKeys(alicePage, ALICE_ID);
    await alicePage.close();
  });

  test("SshKeyManagerPage shows empty state", async () => {
    await alicePage.goto(`${BASE}/remote/ssh-keys`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText("SSH Keys")).toBeVisible();
    await expect(alicePage.getByText("No SSH keys stored")).toBeVisible();
    await expect(alicePage.getByRole("button", { name: /Generate Key/i })).toBeVisible();
    await expect(alicePage.getByRole("button", { name: /Upload Key/i })).toBeVisible();
  });

  test("Generate key dialog creates key and shows public key", async () => {
    await alicePage.goto(`${BASE}/remote/ssh-keys`, { waitUntil: "domcontentloaded" });
    await alicePage.getByRole("button", { name: /Generate Key/i }).click();

    // Fill in label
    await alicePage.getByLabel("Label").fill(`UI Gen Key ${TS}`);

    // Ed25519 should be selected by default
    await alicePage.getByRole("button", { name: /Generate$/i }).click();

    // Wait for key to appear in table (scope to the row to avoid the toast match)
    await expect(
      alicePage.locator("tr").filter({ hasText: `UI Gen Key ${TS}` })
    ).toBeVisible({ timeout: 15_000 });

    // Should show the public key dialog after generation
    await expect(alicePage.getByText("Public Key")).toBeVisible();
    await expect(alicePage.getByText(/ssh-ed25519/)).toBeVisible();
  });

  test("Key appears in table with type badge", async () => {
    await alicePage.goto(`${BASE}/remote/ssh-keys`, { waitUntil: "domcontentloaded" });
    await expect(
      alicePage.locator("tr").filter({ hasText: `UI Gen Key ${TS}` })
    ).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.getByText("ED25519")).toBeVisible();
  });

  test("Delete key removes from list", async () => {
    await alicePage.goto(`${BASE}/remote/ssh-keys`, { waitUntil: "domcontentloaded" });
    await expect(
      alicePage.locator("tr").filter({ hasText: `UI Gen Key ${TS}` })
    ).toBeVisible({ timeout: 10_000 });

    // Click the delete button (trash icon) in the row
    const row = alicePage.locator("tr").filter({ hasText: `UI Gen Key ${TS}` });
    await row.locator("button.text-destructive").click();

    // Confirm in the alert dialog
    await alicePage.getByRole("button", { name: "Delete" }).click();

    // Key should be removed
    await expect(alicePage.getByText(`UI Gen Key ${TS}`)).not.toBeVisible({ timeout: 10_000 });
  });
});
