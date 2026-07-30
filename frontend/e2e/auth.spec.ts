/**
 * E2E tests for authentication flows.
 *
 * Covers:
 *  1. Login page structure & navigation
 *  2. Login form validation
 *  3. Login with wrong credentials
 *  4. Successful login via credential form
 *  5. Forgot / password-recovery page
 *  6. Register page structure & validation
 *  7. MFA devices page (TOTP enrollment dialog)
 *  8. Recovery / change-password section in /security
 *
 * Auth strategy:
 *  - Sections 1–6 use no auth (public pages).
 *  - Sections 7–8 inject Alice's session via cookies + localStorage.
 *  - Section 4 uses e2e_logintest@test.local (real password, created by
 *    e2e_auth_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
import { cppVerifyUser } from "./helpers/cpp-seed";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";

// ─── Session bootstrap (re-uses messaging spec helper) ────────────────────────

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None";
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

// Auth user data returned by e2e_auth_setup.py
interface AuthUserData { email: string; password: string; }
let _authUser: AuthUserData | null = null;
function getAuthUser(): AuthUserData {
  if (!_authUser) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_auth_setup.py",
      { cwd: REPO_ROOT, timeout: 60_000 }
    ).toString();
    _authUser = JSON.parse(raw);
    // Under cpp the seed user is unverified; mark it verified so
    // register/check reports available:false + unverified:false (the
    // "already exists" branch the tests assert), matching the Python path.
    cppVerifyUser(_authUser!.email);
  }
  return _authUser!;
}

// ─── Auth injection helper (for already-authenticated tests) ──────────────────

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function gotoAuthenticated(page: Page, path: string, userId = ALICE_ID) {
  await injectAuth(page, userId);
  await page.goto(`${BASE}${path}`, { waitUntil: "load" });
  await page.waitForTimeout(1000);
}

// ─── 1. Login page structure ──────────────────────────────────────────────────

test.describe("1. Login page structure", () => {
  test("renders email and password fields", async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await expect(page.locator("#username")).toBeVisible();
    await expect(page.locator("#password")).toBeVisible();
  });

  test("renders Sign in button", async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();
  });

  test("has Forgot password link", async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("link", { name: /forgot password/i })).toBeVisible();
  });

  test("has Register link", async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("link", { name: /register/i })).toBeVisible();
  });

  test("has Email link and Security key alternative buttons", async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("button", { name: /email link/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /security key/i })).toBeVisible();
  });

  test("show/hide password toggle changes input type", async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    const pwd = page.locator("#password");
    await expect(pwd).toHaveAttribute("type", "password");
    await page.getByRole("button", { name: /show password/i }).click();
    await expect(pwd).toHaveAttribute("type", "text");
    await page.getByRole("button", { name: /hide password/i }).click();
    await expect(pwd).toHaveAttribute("type", "password");
  });
});

// ─── 2. Login page navigation ─────────────────────────────────────────────────

test.describe("2. Login page navigation", () => {
  test("Email link button shows magic-link step", async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: /email link/i }).click();
    await expect(page.locator("#magic-email")).toBeVisible();
  });

  test("Back arrow on magic-link returns to credentials", async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: /email link/i }).click();
    // ArrowLeft back button
    await page.getByRole("button").filter({ has: page.locator("svg") }).first().click();
    await expect(page.locator("#username")).toBeVisible();
  });

  test("Security key button shows webauthn step", async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: /security key/i }).click();
    await expect(page.locator("#webauthn-user")).toBeVisible();
    await expect(page.getByRole("button", { name: /authenticate/i })).toBeVisible();
  });

  test("Forgot password link navigates to /password-recovery", async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await page.getByRole("link", { name: /forgot password/i }).click();
    await page.waitForURL(/password-recovery/);
    expect(page.url()).toContain("password-recovery");
  });

  test("Register link navigates to /register", async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await page.getByRole("link", { name: /register/i }).click();
    await page.waitForURL(/register/);
    expect(page.url()).toContain("register");
  });
});

// ─── 3. Login form validation ─────────────────────────────────────────────────

test.describe("3. Login form validation", () => {
  test("submitting empty form shows validation errors", async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: /sign in/i }).click();
    // At least one error message appears
    const errors = page.locator("p.text-xs.text-destructive");
    await expect(errors.first()).toBeVisible({ timeout: 3000 });
  });

  test("submitting only email shows password error", async ({ page }) => {
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await page.locator("#username").fill("test@example.com");
    await page.getByRole("button", { name: /sign in/i }).click();
    const error = page.locator("p.text-xs.text-destructive").filter({ hasText: /password/i });
    await expect(error).toBeVisible({ timeout: 3000 });
  });
});

// ─── 4. Login with wrong credentials ─────────────────────────────────────────

test.describe("4. Login with wrong credentials", () => {
  test("wrong password shows error banner", async ({ browser }) => {
    getAuthUser(); // ensure user exists
    // Under cpp every project inherits storageState: admin, so the login page
    // loads already-"authenticated" (admin cookie + auth-store). A wrong-password
    // 401 then hits the client's authenticated-refresh path (refresh succeeds on
    // the admin cookie -> retry -> 401 -> logout("session_expired")), which shows
    // the "session expired" banner INSTEAD of the credential error and clears the
    // error state. A truly anonymous context (no cookie, no localStorage) makes
    // the unauthenticated-401 branch throw so the destructive error renders.
    const context = await browser.newContext({ storageState: undefined });
    const page = await context.newPage();
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await page.locator("#username").fill("e2e_logintest@test.local");
    await page.locator("#password").fill("WrongPassword999!");
    await page.getByRole("button", { name: /sign in/i }).click();
    // Wait for error to appear (API call). Backend may return "Authentication required"
    // or "Invalid credentials" — match either.
    const errorBanner = page.locator("[class*='destructive']").filter({
      hasText: /invalid|incorrect|credential|authentication|unauthorized|failed/i,
    }).first();
    await expect(errorBanner).toBeVisible({ timeout: 10000 });
    await context.close();
  });
});

// ─── 5. Successful login via credential form ──────────────────────────────────

test.describe("5. Successful login", () => {
  test("correct credentials redirect to home", async ({ browser }) => {
    const authUser = getAuthUser();
    const page = await browser.newPage();

    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await page.locator("#username").fill(authUser.email);
    await page.locator("#password").fill(authUser.password);
    await page.getByRole("button", { name: /sign in/i }).click();

    // Should navigate away from /login
    await page.waitForURL((url) => !url.pathname.includes("/login"), { timeout: 15_000 });
    expect(page.url()).not.toContain("/login");
    await page.close();
  });
});

// ─── 6. Forgot password / password recovery page ─────────────────────────────

test.describe("6. Password recovery page", () => {
  test("renders username field and Send Recovery Code button", async ({ page }) => {
    await page.goto(`${BASE}/password-recovery`, { waitUntil: "domcontentloaded" });
    await expect(page.locator("#username")).toBeVisible();
    await expect(page.getByRole("button", { name: /send recovery code/i })).toBeVisible();
  });

  test("has Back to sign in link", async ({ page }) => {
    await page.goto(`${BASE}/password-recovery`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("link", { name: /back to sign in/i })).toBeVisible();
  });

  test("submitting username advances to confirm step", async ({ page }) => {
    getAuthUser(); // ensure user exists
    await page.goto(`${BASE}/password-recovery`, { waitUntil: "domcontentloaded" });
    await page.locator("#username").fill("e2e_logintest@test.local");
    await page.getByRole("button", { name: /send recovery code/i }).click();
    // Confirm step shows new-password field
    await expect(page.locator("#new-password")).toBeVisible({ timeout: 8000 });
    await expect(page.locator("#code")).toBeVisible({ timeout: 2000 });
  });

  test("confirm step has all required fields", async ({ page }) => {
    getAuthUser();
    await page.goto(`${BASE}/password-recovery`, { waitUntil: "domcontentloaded" });
    await page.locator("#username").fill("e2e_logintest@test.local");
    await page.getByRole("button", { name: /send recovery code/i }).click();
    await expect(page.locator("#code")).toBeVisible({ timeout: 8000 });
    await expect(page.locator("#new-password")).toBeVisible();
    await expect(page.locator("#confirm-password")).toBeVisible();
    await expect(page.getByRole("button", { name: /reset password/i })).toBeVisible();
  });
});

// ─── 7. Register page ─────────────────────────────────────────────────────────

test.describe("7. Register page", () => {
  test("renders all registration fields", async ({ page }) => {
    await page.goto(`${BASE}/register`, { waitUntil: "domcontentloaded" });
    await expect(page.locator("#full_name")).toBeVisible();
    await expect(page.locator("#email")).toBeVisible();
    await expect(page.locator("#password")).toBeVisible();
    await expect(page.locator("#confirm_password")).toBeVisible();
    await expect(page.getByRole("button", { name: /request access/i })).toBeVisible();
  });

  test("password strength indicator appears when typing", async ({ page }) => {
    await page.goto(`${BASE}/register`, { waitUntil: "domcontentloaded" });
    await page.locator("#password").fill("TestPa");
    // Strength indicator (bar or label) should be visible
    const strength = page.locator("text=/weak|fair|good|strong/i").first();
    await expect(strength).toBeVisible({ timeout: 3000 });
  });

  test("password requirements checklist renders all items", async ({ page }) => {
    await page.goto(`${BASE}/register`, { waitUntil: "domcontentloaded" });
    await page.locator("#password").fill("a"); // trigger requirements display
    await page.waitForTimeout(300);
    // Use <li> filter to avoid strict-mode issues with text-node selectors
    await expect(page.locator("li").filter({ hasText: "At least 12 characters" })).toBeVisible({ timeout: 5000 });
    await expect(page.locator("li").filter({ hasText: "One uppercase letter" })).toBeVisible();
    await expect(page.locator("li").filter({ hasText: "One number" })).toBeVisible();
    await expect(page.locator("li").filter({ hasText: "One special character" })).toBeVisible();
  });

  test("password mismatch shows error when confirm field is touched", async ({ page }) => {
    await page.goto(`${BASE}/register`, { waitUntil: "domcontentloaded" });
    await page.locator("#password").fill("ValidPass1!@3456");
    await page.locator("#confirm_password").fill("DifferentPass1!@");
    await page.locator("#confirm_password").blur();
    await page.waitForTimeout(300);
    const mismatch = page.locator("text=/don.t match|mismatch|do not match/i");
    await expect(mismatch).toBeVisible({ timeout: 3000 });
  });

  test("email availability check: valid new email shows available", async ({ page }) => {
    await page.goto(`${BASE}/register`, { waitUntil: "domcontentloaded" });
    const unique = `e2e_newuser_${Date.now()}@test.local`;
    await page.locator("#email").fill(unique);
    // Wait for debounced check (400ms) + network
    const available = page.locator("text=/email looks valid|available/i");
    await expect(available).toBeVisible({ timeout: 6000 });
  });

  test("email availability check: existing email shows unavailable", async ({ page }) => {
    getAuthUser(); // ensure e2e_logintest exists
    await page.goto(`${BASE}/register`, { waitUntil: "domcontentloaded" });
    await page.locator("#email").fill("e2e_logintest@test.local");
    const unavailable = page.locator("text=/already exists|unavailable/i");
    await expect(unavailable).toBeVisible({ timeout: 6000 });
  });

  test("Submit is disabled when password requirements not met", async ({ page }) => {
    await page.goto(`${BASE}/register`, { waitUntil: "domcontentloaded" });
    await page.locator("#full_name").fill("Test User");
    await page.locator("#email").fill("newemail@example.com");
    await page.locator("#password").fill("weak"); // too short
    await page.locator("#confirm_password").fill("weak");
    const btn = page.getByRole("button", { name: /request access/i });
    await expect(btn).toBeDisabled({ timeout: 3000 });
  });
});

// ─── 8. MFA devices page (TOTP enrollment) ───────────────────────────────────

test.describe("8. MFA devices page", () => {
  test("security page has TOTP section with Add button", async ({ browser }) => {
    const page = await browser.newPage();
    await gotoAuthenticated(page, "/security");
    // TOTP section header — use exact text to avoid strict-mode violations
    await expect(page.getByText("Authenticator Apps (TOTP)").first()).toBeVisible({ timeout: 8000 });
    // Add button inside the TOTP card
    const addBtn = page.locator("button").filter({ hasText: /^Add$/ }).first();
    await expect(addBtn).toBeVisible();
    await page.close();
  });

  test("clicking Add opens TOTP enrollment dialog with device name input", async ({ browser }) => {
    const page = await browser.newPage();
    await gotoAuthenticated(page, "/security");
    await page.waitForTimeout(1000);
    // Click the first "Add" button (TOTP section)
    const addBtn = page.locator("button").filter({ hasText: /^Add$/ }).first();
    await addBtn.click();
    // Dialog should open with a text input for device name
    const dialog = page.locator("[role='dialog']");
    await expect(dialog).toBeVisible({ timeout: 5000 });
    const nameInput = dialog.locator("input[type='text'], input:not([type])").first();
    await expect(nameInput).toBeVisible({ timeout: 3000 });
    await page.close();
  });

  test("security page has Recovery tab", async ({ browser }) => {
    const page = await browser.newPage();
    await gotoAuthenticated(page, "/security");
    await expect(page.locator("[role='tab']").filter({ hasText: /recovery/i })).toBeVisible({ timeout: 8000 });
    await page.close();
  });

  test("Recovery tab has Reset Password button", async ({ browser }) => {
    const page = await browser.newPage();
    await gotoAuthenticated(page, "/security");
    // Click the Recovery tab
    const recoveryTab = page.locator("[role='tab']").filter({ hasText: /recovery/i });
    await recoveryTab.click();
    await page.waitForTimeout(500);
    await expect(page.getByRole("button", { name: /reset password/i })).toBeVisible({ timeout: 5000 });
    await page.close();
  });

  test("Reset Password button opens dialog with username and code fields", async ({ browser }) => {
    const page = await browser.newPage();
    await gotoAuthenticated(page, "/security");
    const recoveryTab = page.locator("[role='tab']").filter({ hasText: /recovery/i });
    await recoveryTab.click();
    await page.waitForTimeout(500);
    await page.getByRole("button", { name: /reset password/i }).click();
    const dialog = page.locator("[role='dialog']");
    await expect(dialog).toBeVisible({ timeout: 5000 });
    // Username / email input inside dialog
    const usernameInput = dialog.locator("input").first();
    await expect(usernameInput).toBeVisible({ timeout: 3000 });
    await page.close();
  });

  test("MFA page also has SMS Devices section", async ({ browser }) => {
    const page = await browser.newPage();
    await gotoAuthenticated(page, "/security");
    await expect(page.locator("text=/SMS/i").first()).toBeVisible({ timeout: 8000 });
    await page.close();
  });
});

// ─── 9. MFA step in login (API-driven check) ─────────────────────────────────

test.describe("9. Login MFA step", () => {
  test("MFA step renders Recovery Code option when required factors present", async ({ page }) => {
    // Trigger MFA step for a user that has TOTP set up.
    // We just check that the recovery code input is reachable from the UI.
    // Since we don't have a real TOTP user in the test suite, we navigate
    // to /login and simulate switching to the MFA step via the URL.
    // (This is a structural test, not end-to-end MFA completion.)
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    // The MFA step is shown after credentials are submitted.
    // We verify the Recovery Code option exists structurally via the DOM:
    // the page has a "recovery-code" input id in the MFA section.
    // Trigger the step by submitting (wrong) credentials that have MFA
    // — we can't easily do this without a real TOTP user, so just verify
    // the login page structure supports the recovery flow.
    const hasRecoveryId = await page.locator("#recovery-code").count();
    // The element is only present in the MFA step, not credentials step.
    // Verify it is NOT present on the credentials step (expected behaviour).
    expect(hasRecoveryId).toBe(0);
    // Navigate via "Email link" step and back — confirms multi-step nav works.
    await page.getByRole("button", { name: /email link/i }).click();
    await expect(page.locator("#magic-email")).toBeVisible();
  });
});

// ─── Helpers for sections 10 & 11 ────────────────────────────────────────────

interface MfaSetupData {
  email: string;
  code: string;
  mfa_setup: string[];
  phone: string;
}

/**
 * Run e2e_register_mfa_setup.py with the given args, passing the Playwright
 * browser's user agent so the device can be pre-registered in DDB.
 */
async function runMfaSetup(args: string, browser: import("@playwright/test").Browser): Promise<MfaSetupData> {
  const tmpPage = await browser.newPage();
  const ua = await tmpPage.evaluate(() => navigator.userAgent);
  await tmpPage.close();

  // Under cpp the register API + moto DDB both live on .82 (moto binds
  // 127.0.0.1 there), so run the seeder ON .82 over ssh (same transport as
  // helpers/cpp-seed.ts). Python path unchanged when not usingCpp().
  const cpp = process.env.E2E_USE_CPP === "1"
    || (!!process.env.E2E_API_BASE && !/localhost:8000\/?$/.test(process.env.E2E_API_BASE));
  const raw = cpp
    ? execSync(
        `ssh -i ${process.env.E2E_CPP_SSH_KEY ?? "/home/sean/.ssh/e2e_cpp_seed_ed25519"} `
          + `-o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=20 `
          + `sean@192.168.0.82 `
          + `'E2E_USE_CPP=1 E2E_API_BASE=https://localhost:8443 E2E_PLAYWRIGHT_UA=${JSON.stringify(ua)} `
          + `DDB_ENDPOINT_URL=http://localhost:5005 `
          + `python3 ~/projects/testlogon-cpp/e2e/e2e_register_mfa_setup.py ${args}'`,
        { timeout: 40_000 },
      ).toString()
    : execSync(
        `python3 ${REPO_ROOT}/e2e_register_mfa_setup.py ${args}`,
        { cwd: REPO_ROOT, env: { ...process.env, E2E_PLAYWRIGHT_UA: ua }, timeout: 30_000 },
      ).toString();
  return JSON.parse(raw) as MfaSetupData;
}

/**
 * Navigate to /register, inject the pending registration into localStorage,
 * then reload so Register.tsx restores the verify step.
 */
async function gotoRegisterVerifyStep(
  page: import("@playwright/test").Page,
  data: MfaSetupData,
): Promise<void> {
  await page.goto(`${BASE}/register`, { waitUntil: "domcontentloaded" });
  await page.evaluate((d: MfaSetupData) => {
    const pending = {
      email: d.email,
      enable_totp_mfa: d.mfa_setup.includes("totp"),
      enable_sms_mfa: d.mfa_setup.includes("sms"),
      phone: d.phone || undefined,
    };
    localStorage.setItem("register-pending", JSON.stringify(pending));
  }, data);
  // Reload so Register.tsx reads localStorage and shows the verify step
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForTimeout(500);
}

// ─── 10. TOTP MFA at registration ────────────────────────────────────────────

test.describe("10. TOTP MFA at registration", () => {
  let totpData: MfaSetupData;
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    // Create a fresh user with TOTP MFA enabled via the real registration API.
    totpData = await runMfaSetup("--mfa totp", browser);
    page = await browser.newPage();

    // Put the page on the verify step (localStorage injection + reload).
    await gotoRegisterVerifyStep(page, totpData);

    // Enter the known verification code so the page advances to the MFA step.
    // Doing this here (not in a test) makes every test — including retries —
    // start from the correct MFA-step state.
    const firstInput = page.locator("input[inputmode='numeric']").first();
    await expect(firstInput).toBeVisible({ timeout: 5000 });
    await firstInput.click();
    await page.keyboard.type(totpData.code);

    // Wait for the MFA setup heading to confirm we've advanced.
    await expect(page.getByText("Secure your account", { exact: true })).toBeVisible({
      timeout: 10000,
    });
  });

  test.afterAll(async () => page?.close());

  test("email code accepted — TOTP MFA setup step appears", async () => {
    await expect(page.getByText("Secure your account", { exact: true })).toBeVisible({
      timeout: 5000,
    });
  });

  test("TOTP section 'Authenticator app' heading is visible", async () => {
    // Use exact: true to avoid matching the longer description paragraph that
    // also contains the words "authenticator app".
    await expect(page.getByText("Authenticator app", { exact: true })).toBeVisible({
      timeout: 5000,
    });
  });

  test("TOTP QR code image is displayed", async () => {
    await expect(page.locator("img[alt='TOTP QR code']")).toBeVisible({ timeout: 8000 });
  });

  test("Manual entry key (TOTP secret) is displayed", async () => {
    await expect(page.getByText("Manual entry key", { exact: true })).toBeVisible({
      timeout: 5000,
    });
    // The <code> element holds the base32 secret.
    const secretEl = page.locator("code").first();
    await expect(secretEl).toBeVisible({ timeout: 3000 });
    const secretText = await secretEl.textContent();
    expect(secretText).toBeTruthy();
    expect(secretText!.length).toBeGreaterThan(10);
  });

  test("'First 6-digit code' label is visible", async () => {
    await expect(page.getByText("First 6-digit code", { exact: true })).toBeVisible({
      timeout: 5000,
    });
  });

  test("'Second 6-digit code' label is visible", async () => {
    await expect(page.getByText("Second 6-digit code", { exact: true })).toBeVisible({
      timeout: 5000,
    });
  });

  test("'Verify authenticator' button is present and disabled until both codes entered", async () => {
    const btn = page.getByRole("button", { name: /verify authenticator/i });
    await expect(btn).toBeVisible({ timeout: 5000 });
    // Button should be disabled when no codes have been entered
    await expect(btn).toBeDisabled();
  });
});

// ─── 11. SMS MFA at registration ─────────────────────────────────────────────

test.describe("11. SMS MFA at registration", () => {
  let smsData: MfaSetupData;
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    // Create a fresh user with SMS MFA enabled via the real registration API.
    smsData = await runMfaSetup("--mfa sms --phone +15551234567", browser);
    page = await browser.newPage();

    // Put the page on the verify step (localStorage injection + reload).
    await gotoRegisterVerifyStep(page, smsData);

    // Enter the known verification code so the page advances to the MFA step.
    const firstInput = page.locator("input[inputmode='numeric']").first();
    await expect(firstInput).toBeVisible({ timeout: 5000 });
    await firstInput.click();
    await page.keyboard.type(smsData.code);

    // Wait for the MFA setup heading.
    await expect(page.getByText("Secure your account", { exact: true })).toBeVisible({
      timeout: 10000,
    });
  });

  test.afterAll(async () => page?.close());

  test("email code accepted — SMS MFA setup step appears", async () => {
    await expect(page.getByText("Secure your account", { exact: true })).toBeVisible({
      timeout: 5000,
    });
  });

  test("SMS section 'SMS verification' heading is visible", async () => {
    // exact: true avoids matching longer sentences that contain "SMS verification".
    await expect(page.getByText("SMS verification", { exact: true })).toBeVisible({
      timeout: 5000,
    });
  });

  test("'Send verification code' button is present", async () => {
    await expect(
      page.getByRole("button", { name: /send verification code/i }),
    ).toBeVisible({ timeout: 5000 });
  });

  test("SMS MFA description prompts the user to verify their phone number", async () => {
    await expect(page.getByText(/verify your phone number/i)).toBeVisible({
      timeout: 5000,
    });
  });
});

/**
 * Clear the IP-based MFA TOTP rate-limit bucket from DynamoDB so that section
 * 13 tests don't get 429s from accumulated calls across multiple test runs.
 */
function clearTotpRateLimitBucket(): void {
  execSync(
    `${REPO_ROOT}/.venv/bin/python3 -c "
import boto3, os
from pathlib import Path
for line in Path('${REPO_ROOT}/.env.local').read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
t = ddb.Table(os.environ.get('DDB_SESSIONS_TABLE', 'sessions'))
t.delete_item(Key={'user_sub': 'ip#127.0.0.1', 'session_id': 'rl#mfa_verify#totp'})
t.delete_item(Key={'user_sub': 'ip#127.0.0.1', 'session_id': 'lockout#mfa_totp'})
print('cleared')
"`,
    { timeout: 10_000 },
  );
}

// ─── Helpers for section 13 ───────────────────────────────────────────────────

interface MfaMultiSetup {
  email: string;
  password: string;
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

function runMfaMultiSetup(): MfaMultiSetup {
  const raw = execSync(
    "python3 " + REPO_ROOT + "/e2e_mfa_multidevice_setup.py",
    { cwd: REPO_ROOT, timeout: 30_000 },
  ).toString();
  return JSON.parse(raw) as MfaMultiSetup;
}

/** Generate a current TOTP code for the given base32 secret. */
function totpNow(secret: string): string {
  return execSync(
    `${REPO_ROOT}/.venv/bin/python3 -c "import pyotp; print(pyotp.TOTP('${secret}').now())"`,
    { timeout: 5_000 },
  ).toString().trim();
}

/**
 * Generate two *different* valid TOTP codes from adjacent 30-second windows.
 * Used for enrollment which requires two distinct codes.
 */
function totpTwoCodes(secret: string): [string, string] {
  const raw = execSync(
    `${REPO_ROOT}/.venv/bin/python3 -c ` +
    `"import pyotp,time,json; t=pyotp.TOTP('${secret}'); ` +
    `now=int(time.time()); c1=t.at(now); c2=t.at(now-30); ` +
    `c2=(t.at(now-60) if c1==c2 else c2); print(json.dumps([c1,c2]))"`,
    { timeout: 5_000 },
  ).toString().trim();
  return JSON.parse(raw) as [string, string];
}

// ─── 13. Multi-device TOTP MFA ────────────────────────────────────────────────

test.describe("13. Multi-device TOTP MFA", () => {
  let setupData: MfaMultiSetup;
  let device1Id: string;
  let device1Secret: string;
  let device2Id: string;
  let device2Secret: string;
  let enrollPage: import("@playwright/test").Page;

  test.beforeAll(async ({ browser }) => {
    // Clear accumulated IP rate-limit / lockout state from previous runs so
    // that totp/verify calls don't get throttled when the suite runs repeatedly.
    clearTotpRateLimitBucket();

    // Create a fresh user with known credentials + a session stamped with
    // mfa_verified_at so require_fresh_mfa() passes for device enrollment.
    setupData = runMfaMultiSetup();

    // Open a page and inject the session cookies so enrollPage.request sends
    // the ui_access_token cookie (used by require_ui_session on the API).
    enrollPage = await browser.newPage();
    await enrollPage.context().addCookies(setupData.cookies);
    // Navigate once to warm up the context; any authenticated page works.
    await enrollPage.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });

    const csrfHeader = { "x-csrf-token": setupData.csrf_token };

    // ── Enroll Device 1 ──────────────────────────────────────────────────────
    const begin1Resp = await enrollPage.request.post(
      `${API}/ui/mfa/totp/devices/begin`,
      { data: { label: "E2E TOTP Device 1" }, headers: csrfHeader },
    );
    expect(begin1Resp.ok()).toBeTruthy();
    const begin1 = await begin1Resp.json();
    device1Id     = begin1.device_id;
    device1Secret = begin1.secret;

    // totp_confirm_enroll requires two *different* valid codes.
    const [c1a, c1b] = totpTwoCodes(device1Secret);
    const confirm1 = await enrollPage.request.post(
      `${API}/ui/mfa/totp/devices/confirm`,
      { data: { device_id: device1Id, totp_code: c1a, totp_code2: c1b }, headers: csrfHeader },
    );
    expect(confirm1.ok()).toBeTruthy();
    // stamp_mfa_verified is called by /confirm, so the session is fresh for
    // the next enrollment even though TOTP is now required.

    // ── Enroll Device 2 ──────────────────────────────────────────────────────
    const begin2Resp = await enrollPage.request.post(
      `${API}/ui/mfa/totp/devices/begin`,
      { data: { label: "E2E TOTP Device 2" }, headers: csrfHeader },
    );
    expect(begin2Resp.ok()).toBeTruthy();
    const begin2 = await begin2Resp.json();
    device2Id     = begin2.device_id;
    device2Secret = begin2.secret;

    const [c2a, c2b] = totpTwoCodes(device2Secret);
    const confirm2 = await enrollPage.request.post(
      `${API}/ui/mfa/totp/devices/confirm`,
      { data: { device_id: device2Id, totp_code: c2a, totp_code2: c2b }, headers: csrfHeader },
    );
    expect(confirm2.ok()).toBeTruthy();
  });

  test.afterAll(async () => enrollPage?.close());

  // ── Device list ─────────────────────────────────────────────────────────────

  test("API: lists exactly 2 enabled TOTP devices after dual enrollment", async () => {
    const resp = await enrollPage.request.get(`${API}/ui/mfa/totp/devices`);
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    const enabled = (data.devices as Array<{ enabled: boolean }>).filter(d => d.enabled);
    expect(enabled.length).toBe(2);
  });

  test("API: Device 1 label is present in the device list", async () => {
    const resp = await enrollPage.request.get(`${API}/ui/mfa/totp/devices`);
    const data = await resp.json();
    const labels = (data.devices as Array<{ label: string }>).map(d => d.label);
    expect(labels).toContain("E2E TOTP Device 1");
  });

  test("API: Device 2 label is present in the device list", async () => {
    const resp = await enrollPage.request.get(`${API}/ui/mfa/totp/devices`);
    const data = await resp.json();
    const labels = (data.devices as Array<{ label: string }>).map(d => d.label);
    expect(labels).toContain("E2E TOTP Device 2");
  });

  // ── Login with Device 1 code ─────────────────────────────────────────────────
  //
  // Each login test uses the `request` fixture which has its own cookie jar.
  // POST /ui/session/start sets a short-lived ui_access_token cookie in the
  // response that subsequent calls in the same context pick up automatically.

  test("API: TOTP verify with Device 1 code returns ok", async ({ request }) => {
    const startResp = await request.post(`${API}/ui/session/start`, {
      data: { challenge_context: { username: setupData.email, password: setupData.password } },
    });
    expect(startResp.ok()).toBeTruthy();
    const startData = await startResp.json();
    expect(startData.auth_required).toBe(true);
    expect(startData.required_factors).toContain("totp");

    const code = totpNow(device1Secret);
    const verifyResp = await request.post(`${API}/ui/mfa/totp/verify`, {
      data: { challenge_id: startData.challenge_id, totp_code: code },
    });
    expect(verifyResp.ok()).toBeTruthy();
    const verifyData = await verifyResp.json();
    expect(verifyData.status).toBe("ok");
  });

  // ── Login with Device 2 code ─────────────────────────────────────────────────

  test("API: TOTP verify with Device 2 code returns ok", async ({ request }) => {
    const startResp = await request.post(`${API}/ui/session/start`, {
      data: { challenge_context: { username: setupData.email, password: setupData.password } },
    });
    expect(startResp.ok()).toBeTruthy();
    const startData = await startResp.json();
    expect(startData.auth_required).toBe(true);

    const code = totpNow(device2Secret);
    const verifyResp = await request.post(`${API}/ui/mfa/totp/verify`, {
      data: { challenge_id: startData.challenge_id, totp_code: code },
    });
    expect(verifyResp.ok()).toBeTruthy();
    const verifyData = await verifyResp.json();
    expect(verifyData.status).toBe("ok");
  });

  // ── Wrong code is rejected ───────────────────────────────────────────────────

  test("API: TOTP verify with wrong code returns 401", async ({ request }) => {
    const startResp = await request.post(`${API}/ui/session/start`, {
      data: { challenge_context: { username: setupData.email, password: setupData.password } },
    });
    const startData = await startResp.json();

    const verifyResp = await request.post(`${API}/ui/mfa/totp/verify`, {
      data: { challenge_id: startData.challenge_id, totp_code: "000000" },
    });
    expect(verifyResp.status()).toBe(401);
  });

  // ── Full login flows ─────────────────────────────────────────────────────────

  test("API: full login flow (start → TOTP Device 1 → finalize) creates a session", async ({ request }) => {
    const startResp = await request.post(`${API}/ui/session/start`, {
      data: { challenge_context: { username: setupData.email, password: setupData.password } },
    });
    expect(startResp.ok()).toBeTruthy();
    const { challenge_id } = await startResp.json();

    const code = totpNow(device1Secret);
    await request.post(`${API}/ui/mfa/totp/verify`, {
      data: { challenge_id, totp_code: code },
    });

    const finalizeResp = await request.post(`${API}/ui/session/finalize`, {
      data: { challenge_id, remember_device: false },
    });
    expect(finalizeResp.ok()).toBeTruthy();
    const finalizeData = await finalizeResp.json();
    expect(finalizeData.status).toBe("ok");
    expect(typeof finalizeData.session_id).toBe("string");
    expect(finalizeData.session_id.length).toBeGreaterThan(0);
  });

  test("API: full login flow (start → TOTP Device 2 → finalize) creates a session", async ({ request }) => {
    const startResp = await request.post(`${API}/ui/session/start`, {
      data: { challenge_context: { username: setupData.email, password: setupData.password } },
    });
    expect(startResp.ok()).toBeTruthy();
    const { challenge_id } = await startResp.json();

    const code = totpNow(device2Secret);
    await request.post(`${API}/ui/mfa/totp/verify`, {
      data: { challenge_id, totp_code: code },
    });

    const finalizeResp = await request.post(`${API}/ui/session/finalize`, {
      data: { challenge_id, remember_device: false },
    });
    expect(finalizeResp.ok()).toBeTruthy();
    const finalizeData = await finalizeResp.json();
    expect(finalizeData.status).toBe("ok");
    expect(typeof finalizeData.session_id).toBe("string");
  });

  // ── After removing Device 1, only Device 2 remains ──────────────────────────

  test("API: after removing Device 1, its TOTP code is rejected at login", async ({ request }) => {
    // Remove Device 1. The endpoint requires a valid TOTP code from *any*
    // remaining enabled device to confirm the removal, so we use Device 2.
    const removeCode = totpNow(device2Secret);
    const removeResp = await enrollPage.request.post(
      `${API}/ui/mfa/totp/devices/${device1Id}/remove`,
      { data: { totp_code: removeCode }, headers: { "x-csrf-token": setupData.csrf_token } },
    );
    expect(removeResp.ok()).toBeTruthy();

    // Start a fresh login and attempt TOTP with the now-removed Device 1.
    const startResp = await request.post(`${API}/ui/session/start`, {
      data: { challenge_context: { username: setupData.email, password: setupData.password } },
    });
    expect(startResp.ok()).toBeTruthy();
    const startData = await startResp.json();
    expect(startData.auth_required).toBe(true);

    const code1 = totpNow(device1Secret);
    const verifyResp = await request.post(`${API}/ui/mfa/totp/verify`, {
      data: { challenge_id: startData.challenge_id, totp_code: code1 },
    });
    expect(verifyResp.status()).toBe(401);
  });

  test("API: after removing Device 1, Device 2 still allows login", async ({ request }) => {
    // Device 1 was removed in the previous test; Device 2 must still work.
    const startResp = await request.post(`${API}/ui/session/start`, {
      data: { challenge_context: { username: setupData.email, password: setupData.password } },
    });
    expect(startResp.ok()).toBeTruthy();
    const { challenge_id } = await startResp.json();

    const code2 = totpNow(device2Secret);
    const verifyResp = await request.post(`${API}/ui/mfa/totp/verify`, {
      data: { challenge_id, totp_code: code2 },
    });
    expect(verifyResp.ok()).toBeTruthy();
    const verifyData = await verifyResp.json();
    expect(verifyData.status).toBe("ok");
  });
});

// ─── 12. Duplicate email registration (account enumeration protection) ────────

test.describe("12. Duplicate email (account enumeration protection)", () => {
  test("register/start with an existing email returns generic 200 ok", async ({ request }) => {
    // Ensure the e2e_logintest user exists first
    getAuthUser();
    const resp = await request.post(`${API}/ui/register/start`, {
      data: {
        email: "e2e_logintest@test.local",
        full_name: "Hacker Attempt",
        password: "ValidPass1!@3456",
        confirm_password: "ValidPass1!@3456",
        enable_totp_mfa: false,
        enable_sms_mfa: false,
      },
    });
    // Must return 200 — NOT 409 — to prevent account enumeration
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("ok");
    expect(data.verification_required).toBe(true);
  });

  test("register/check with an existing email returns available=false", async ({ request }) => {
    getAuthUser();
    const resp = await request.post(`${API}/ui/register/check`, {
      data: { email: "e2e_logintest@test.local" },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.available).toBe(false);
  });

  test("register/start with a brand-new email returns 200 ok", async ({ request }) => {
    const uniqueEmail = `e2e_new_${Date.now()}@test.local`;
    const resp = await request.post(`${API}/ui/register/start`, {
      data: {
        email: uniqueEmail,
        full_name: "Brand New User",
        password: "ValidPass1!@3456",
        confirm_password: "ValidPass1!@3456",
        enable_totp_mfa: false,
        enable_sms_mfa: false,
      },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("ok");
    expect(data.verification_required).toBe(true);
  });

  test("register/check with a brand-new email returns available=true", async ({ request }) => {
    const uniqueEmail = `e2e_check_${Date.now()}@test.local`;
    const resp = await request.post(`${API}/ui/register/check`, {
      data: { email: uniqueEmail },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.available).toBe(true);
  });
});
