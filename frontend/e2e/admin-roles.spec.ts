/**
 * E2E tests for admin role management and impersonation:
 *
 * Section 45: Role management API (grant / update-profile / revoke / audit)
 * Section 46: Impersonation API (start / stop / audit)
 *
 * ── Authentication strategy ─────────────────────────────────────────────────
 *
 * The backend resolves the caller's role from the `role` claim embedded in the
 * HS256-signed `ui_access_token` cookie.  `e2e_admin_session_setup.py` creates
 * role-bearing JWT cookies for each test identity:
 *
 *   root           – role=root
 *   alice          – role=user  (for 403 rejection tests)
 *   charlie_admin  – role=admin, admin_profile={type:general}
 *
 * Each test identity gets its own Playwright browser page whose cookie jar is
 * pre-loaded with those three cookies (ui_access_token, ui_session, ui_csrf).
 * POST requests include an `x-csrf-token` header (required by require_ui_session
 * when the ui_session cookie is present).
 *
 * Sessions are created in DDB by `e2e_admin_session_setup.py`.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, resolveIdentityId } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ─────────────────────────────────────────────────────────────────

const ROOT_SUB   = "root.admin@testdev.local";
const BOB_ID     = resolveIdentityId("e2e_bob@test.local");
const ALICE_ID   = resolveIdentityId("e2e_alice@test.local");
const CHARLIE_ID = resolveIdentityId("e2e_charlie@test.local");

// ─── Session bootstrap ─────────────────────────────────────────────────────────

interface AdminSessionData {
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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

// ─── Identity page factory ─────────────────────────────────────────────────────

/**
 * Create a new browser page with the given identity's cookies injected.
 * All requests from this page will carry the role-bearing access-token cookie.
 */
async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ─── Request helpers ───────────────────────────────────────────────────────────

type ReqParams = Record<string, string>;

/**
 * Authenticated POST using a pre-cookie'd page.
 * `identity` is the session key used to look up the correct CSRF token.
 */
async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body?: unknown,
) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

/** Authenticated GET using a pre-cookie'd page (no CSRF needed). */
async function apiGet(page: Page, path: string, params?: ReqParams) {
  return page.request.get(`${API}/${path}`, { params });
}

// ─── DynamoDB cleanup helper ───────────────────────────────────────────────────

/** Reset Bob's role back to "user" in the auth users table (cleanup). */
function resetBobToUser(): void {
  execSync(
    `python3 -c "
import boto3, os
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('USERS_TABLE_NAME','users'))
tbl.update_item(Key={'user_sub':'${BOB_ID}'}, UpdateExpression='SET #r=:r REMOVE admin_profile', ExpressionAttributeNames={'#r':'role'}, ExpressionAttributeValues={':r':'user'})
print('reset bob to user')
"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

// ─── 45. Role management API ───────────────────────────────────────────────────

test.describe("45. Role management API — /admin/roles", () => {
  let rootPage: Page;
  let alicePage: Page;
  const startTs = Math.floor(Date.now() / 1000);

  test.beforeAll(async ({ browser }) => {
    getAdminSessions(); // warm-up: creates sessions in DDB, ensures role_audit table
    resetBobToUser();   // ensure Bob starts as a plain user
    rootPage  = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    try { resetBobToUser(); } catch { /* ignore */ }
    await rootPage?.close();
    await alicePage?.close();
  });

  // ── Grant ──────────────────────────────────────────────────────────────────

  test("root can grant general-admin role to a regular user", async () => {
    const r = await apiPost(rootPage, "root", "admin/roles/grant", {
      target_user_sub:    BOB_ID,
      role:               "admin",
      reason:             "e2e test grant",
      admin_profile_type: "general",
    });
    expect(r.status()).toBe(200);
    const data = await r.json() as Record<string, unknown>;
    expect(data.ok).toBe(true);
    expect(data.target_user_sub).toBe(BOB_ID);
    expect(data.role).toBe("admin");
    expect((data.admin_profile as Record<string, unknown>).type).toBe("general");
    expect(typeof data.event_id).toBe("string");
  });

  test("role audit log contains the grant event", async () => {
    const r = await apiGet(rootPage, "admin/roles/audit", {
      actor_sub: ROOT_SUB,
      start_ts:  String(startTs),
    });
    expect(r.status()).toBe(200);
    const data = await r.json() as { items: Array<Record<string, unknown>> };
    expect(Array.isArray(data.items)).toBe(true);
    const evt = data.items.find(
      (e) => e.action === "grant" && e.target_user_sub === BOB_ID,
    );
    expect(evt).toBeDefined();
    expect(evt!.new_role).toBe("admin");
    expect(evt!.previous_role).toBe("user");
    expect(evt!.actor_sub).toBe(ROOT_SUB);
  });

  test("granting admin to an already-admin user returns 409", async () => {
    const r = await apiPost(rootPage, "root", "admin/roles/grant", {
      target_user_sub:    BOB_ID,
      role:               "admin",
      admin_profile_type: "general",
    });
    expect(r.status()).toBe(409);
  });

  // ── Update profile ─────────────────────────────────────────────────────────

  test("root can update an admin's profile to scoped (auth_support)", async () => {
    const r = await apiPost(rootPage, "root", "admin/roles/update-profile", {
      target_user_sub:    BOB_ID,
      admin_profile_type: "scoped",
      admin_scopes:       ["auth_support"],
      reason:             "e2e test profile update",
    });
    expect(r.status()).toBe(200);
    const data = await r.json() as Record<string, unknown>;
    expect(data.ok).toBe(true);
    const profile = data.admin_profile as Record<string, unknown>;
    expect(profile.type).toBe("scoped");
    expect(profile.scopes).toContain("auth_support");
  });

  test("audit log contains the update_profile event", async () => {
    const r = await apiGet(rootPage, "admin/roles/audit", {
      actor_sub: ROOT_SUB,
      start_ts:  String(startTs),
    });
    expect(r.status()).toBe(200);
    const data = await r.json() as { items: Array<Record<string, unknown>> };
    const evt = data.items.find(
      (e) => e.action === "update_profile" && e.target_user_sub === BOB_ID,
    );
    expect(evt).toBeDefined();
    expect((evt!.new_admin_profile as Record<string, unknown>).type).toBe("scoped");
  });

  // ── Revoke ─────────────────────────────────────────────────────────────────

  test("root can revoke admin role from a user", async () => {
    const r = await apiPost(rootPage, "root", "admin/roles/revoke", {
      target_user_sub: BOB_ID,
      role:            "admin",
      reason:          "e2e test revoke",
    });
    expect(r.status()).toBe(200);
    const data = await r.json() as Record<string, unknown>;
    expect(data.ok).toBe(true);
    expect(data.role).toBe("user");
  });

  test("audit log contains the revoke event", async () => {
    const r = await apiGet(rootPage, "admin/roles/audit", {
      actor_sub: ROOT_SUB,
      start_ts:  String(startTs),
    });
    expect(r.status()).toBe(200);
    const data = await r.json() as { items: Array<Record<string, unknown>> };
    const evt = data.items.find(
      (e) => e.action === "revoke" && e.target_user_sub === BOB_ID,
    );
    expect(evt).toBeDefined();
    expect(evt!.previous_role).toBe("admin");
    expect(evt!.new_role).toBe("user");
  });

  test("revoking admin from a non-admin user returns 409", async () => {
    // Bob is now back to 'user' after the revoke above.
    const r = await apiPost(rootPage, "root", "admin/roles/revoke", {
      target_user_sub: BOB_ID,
      role:            "admin",
    });
    expect(r.status()).toBe(409);
  });

  // ── Immutability / error cases ─────────────────────────────────────────────

  test("granting admin to the root user itself returns 409 (root immutable)", async () => {
    const r = await apiPost(rootPage, "root", "admin/roles/grant", {
      target_user_sub:    ROOT_SUB,
      role:               "admin",
      admin_profile_type: "general",
    });
    expect(r.status()).toBe(409);
  });

  test("non-root user (Alice) cannot grant admin — returns 403", async () => {
    const r = await apiPost(alicePage, "alice", "admin/roles/grant", {
      target_user_sub:    BOB_ID,
      role:               "admin",
      admin_profile_type: "general",
    });
    expect(r.status()).toBe(403);
  });

  test("non-root user (Alice) cannot revoke admin — returns 403", async () => {
    const r = await apiPost(alicePage, "alice", "admin/roles/revoke", {
      target_user_sub: BOB_ID,
      role:            "admin",
    });
    expect(r.status()).toBe(403);
  });

  test("non-root user (Alice) cannot access role audit — returns 403", async () => {
    const r = await apiGet(alicePage, "admin/roles/audit");
    expect(r.status()).toBe(403);
  });

  test("grant with an invalid admin_profile_type returns 400", async () => {
    const r = await apiPost(rootPage, "root", "admin/roles/grant", {
      target_user_sub:    BOB_ID,
      role:               "admin",
      admin_profile_type: "superuser",   // not a valid type
    });
    expect(r.status()).toBe(400);
    const data = await r.json() as Record<string, unknown>;
    expect(data.detail).toMatchObject({ code: "invalid_admin_profile_type" });
  });

  test("grant with scoped profile but no scopes returns 400", async () => {
    const r = await apiPost(rootPage, "root", "admin/roles/grant", {
      target_user_sub:    BOB_ID,
      role:               "admin",
      admin_profile_type: "scoped",
      admin_scopes:       [],
    });
    expect(r.status()).toBe(400);
    const data = await r.json() as Record<string, unknown>;
    expect((data.detail as Record<string, unknown>).code).toBe("invalid_admin_scopes");
  });

  test("audit items include expected fields (event_id, action, ts, reason)", async () => {
    const r = await apiGet(rootPage, "admin/roles/audit", {
      actor_sub: ROOT_SUB,
      start_ts:  String(startTs),
    });
    expect(r.status()).toBe(200);
    const data = await r.json() as { items: Array<Record<string, unknown>> };
    if (data.items.length > 0) {
      const item = data.items[0];
      expect(item).toHaveProperty("event_id");
      expect(item).toHaveProperty("action");
      expect(item).toHaveProperty("ts");
      expect(item).toHaveProperty("actor_sub");
      expect(item).toHaveProperty("target_user_sub");
    }
  });
});

// ─── 46. Impersonation API ─────────────────────────────────────────────────────

test.describe("46. Impersonation API — /admin/impersonation", () => {
  let rootPage: Page;
  let alicePage: Page;
  let charlieAdminPage: Page;
  let impersonationId = "";
  const startTs = Math.floor(Date.now() / 1000);

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    resetBobToUser(); // impersonation of admins/root is blocked by default
    rootPage         = await newIdentityPage(browser, "root");
    alicePage        = await newIdentityPage(browser, "alice");
    charlieAdminPage = await newIdentityPage(browser, "charlie_admin");
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
    await charlieAdminPage?.close();
  });

  // ── Start impersonation ────────────────────────────────────────────────────

  test("root can start impersonation of a regular user", async () => {
    const r = await apiPost(rootPage, "root", "admin/impersonation/start", {
      target_user_sub: BOB_ID,
      reason:          "e2e test impersonation",
      ticket_id:       "TICKET-001",
    });
    expect(r.status()).toBe(200);
    const data = await r.json() as Record<string, unknown>;
    expect(data.ok).toBe(true);
    expect(typeof data.impersonation_id).toBe("string");
    expect((data.impersonation_id as string).startsWith("imp_")).toBe(true);
    expect(typeof data.token).toBe("string");
    expect(data.actor_sub).toBe(ROOT_SUB);
    expect(data.effective_sub).toBe(BOB_ID);
    impersonationId = data.impersonation_id as string;
  });

  test("impersonation response has correct actor and effective subject", async () => {
    // Re-start a fresh impersonation to verify fields independently.
    const r = await apiPost(rootPage, "root", "admin/impersonation/start", {
      target_user_sub: BOB_ID,
      reason:          "e2e field verification",
    });
    expect(r.status()).toBe(200);
    const data = await r.json() as Record<string, unknown>;
    expect(data.actor_sub).toBe(ROOT_SUB);
    expect(data.effective_sub).toBe(BOB_ID);
    expect(typeof data.expires_at).toBe("number");
    expect(typeof data.ttl_seconds).toBe("number");
    expect((data.ttl_seconds as number)).toBeGreaterThan(0);
    expect(data.reason).toBe("e2e field verification");
  });

  // ── Stop impersonation ─────────────────────────────────────────────────────

  test("root can stop impersonation", async () => {
    const r = await apiPost(rootPage, "root", "admin/impersonation/stop", {
      impersonation_id: impersonationId,
    });
    expect(r.status()).toBe(200);
    const data = await r.json() as Record<string, unknown>;
    expect(data.ok).toBe(true);
    expect(data.stopped).toBe(true);
  });

  test("stopping an already-stopped impersonation returns already_stopped:true", async () => {
    const r = await apiPost(rootPage, "root", "admin/impersonation/stop", {
      impersonation_id: impersonationId,
    });
    expect(r.status()).toBe(200);
    const data = await r.json() as Record<string, unknown>;
    expect(data.ok).toBe(true);
    expect(data.already_stopped).toBe(true);
  });

  // ── Audit ──────────────────────────────────────────────────────────────────

  test("impersonation audit log returns the start events", async () => {
    const r = await apiGet(rootPage, "admin/impersonation/audit", {
      actor_sub: ROOT_SUB,
      start_ts:  String(startTs),
    });
    expect(r.status()).toBe(200);
    const data = await r.json() as { items: Array<Record<string, unknown>> };
    expect(Array.isArray(data.items)).toBe(true);
    const evt = data.items.find(
      (e) => e.effective_sub === BOB_ID && e.actor_sub === ROOT_SUB,
    );
    expect(evt).toBeDefined();
    expect(typeof evt!.impersonation_id).toBe("string");
    expect(typeof evt!.created_at).toBe("number");
  });

  test("audit items include expected fields", async () => {
    const r = await apiGet(rootPage, "admin/impersonation/audit");
    expect(r.status()).toBe(200);
    const data = await r.json() as { items: Array<Record<string, unknown>> };
    if (data.items.length > 0) {
      const item = data.items[0];
      expect(item).toHaveProperty("impersonation_id");
      expect(item).toHaveProperty("actor_sub");
      expect(item).toHaveProperty("effective_sub");
      expect(item).toHaveProperty("created_at");
      expect(item).toHaveProperty("expires_at");
      expect(item).toHaveProperty("revoked");
    }
  });

  // ── Error cases ────────────────────────────────────────────────────────────

  test("impersonating the root user is forbidden (privileged targets disabled)", async () => {
    // IMPERSONATION_ALLOW_PRIVILEGED_TARGETS=false (default); root cannot
    // impersonate another root/admin user.
    const r = await apiPost(rootPage, "root", "admin/impersonation/start", {
      target_user_sub: ROOT_SUB,
      reason:          "e2e privilege escalation test",
    });
    expect(r.status()).toBe(403);
  });

  test("regular user (Alice) cannot start impersonation — returns 403", async () => {
    const r = await apiPost(alicePage, "alice", "admin/impersonation/start", {
      target_user_sub: BOB_ID,
      reason:          "unauthorised",
    });
    expect(r.status()).toBe(403);
  });

  test("regular user (Alice) cannot access impersonation audit — returns 403", async () => {
    const r = await apiGet(alicePage, "admin/impersonation/audit");
    expect(r.status()).toBe(403);
  });

  test("missing target_user_sub returns 400", async () => {
    const r = await apiPost(rootPage, "root", "admin/impersonation/start", {
      reason: "missing target",
    });
    expect(r.status()).toBe(400);
  });

  test("admin (general) can also start impersonation", async () => {
    // Charlie acts as a general admin.  A general admin profile passes the
    // auth_support scope check for impersonation.
    const r = await apiPost(charlieAdminPage, "charlie_admin", "admin/impersonation/start", {
      target_user_sub: BOB_ID,
      reason:          "e2e admin impersonation test",
    });
    expect(r.status()).toBe(200);
    const data = await r.json() as Record<string, unknown>;
    expect(data.ok).toBe(true);
    expect(data.effective_sub).toBe(BOB_ID);
    expect(data.actor_sub).toBe(CHARLIE_ID);
    // Clean up — stop the impersonation we just started.
    await apiPost(charlieAdminPage, "charlie_admin", "admin/impersonation/stop", {
      impersonation_id: data.impersonation_id,
    });
  });
});
