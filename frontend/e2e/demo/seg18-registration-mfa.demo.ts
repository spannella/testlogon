/**
 * VIDEO SEGMENT 18 — Registration & MFA  (~2 min)
 *
 * The front door and the locks:
 *   - A real account registration: live email-availability check, a password
 *     strength meter, and optional security upgrades — submitted end-to-end,
 *     with the dev verification code fetched from the dev console and entered.
 *   - The Security Center: TOTP authenticator enrollment (name → QR → secret),
 *     passkeys / WebAuthn, scoped API keys, active sessions, and self-service
 *     password recovery.
 *
 * The registration completes against the real dev backend (Cognito is mocked,
 * the 6-digit code is read back from /internal/dev-tools). The MFA tour runs as
 * the seeded Alice so every Security Center surface renders.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg18-registration-mfa.demo.ts
 */
import { test } from "@playwright/test";
import { BASE, API, injectAuth, caption, clearCaption, titleCard, beat, reveal } from "./_demo";

test("Segment 18 — Registration & MFA", async ({ page }) => {
  test.setTimeout(600_000);
  const ts = Date.now();
  const email = `demo_${ts}@test.local`;

  // ── 1. Intro ──────────────────────────────────────────────────────────────
  await page.goto(`${BASE}/register`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1200);
  await titleCard(
    page,
    18,
    "Registration & MFA",
    "Self-service sign-up · password strength · TOTP · passkeys · recovery",
  );

  // ── 2. Registration form ──────────────────────────────────────────────────
  await reveal(
    page,
    page.getByText(/create your account/i).first(),
    "Create an account",
    "A guided sign-up with live validation at every step",
    { ms: 3400 },
  ).catch(() => {});

  await page.locator("#full_name").fill("Jordan Rivera").catch(() => {});
  await page.locator("#email").fill(email).catch(() => {});
  await page.waitForTimeout(1400); // let the live availability check resolve
  await reveal(
    page,
    page.getByText(/email looks valid|available/i).first(),
    "Live email check",
    "The address is validated for availability as you type",
    { ms: 3200 },
  ).catch(() => {});

  await page.locator("#password").fill("Demo-Pass-2026!").catch(() => {});
  await page.locator("#confirm_password").fill("Demo-Pass-2026!").catch(() => {});
  await page.waitForTimeout(700);
  await reveal(
    page,
    page.getByText(/password requirements|password strength/i).first(),
    "Strong by default",
    "A real-time strength meter enforces a robust password policy",
    { ms: 4000 },
  ).catch(() => {});
  await reveal(
    page,
    page.getByText(/optional security upgrades/i).first(),
    "Security from minute one",
    "Opt into an authenticator app or SMS right at sign-up",
    { ms: 4000 },
  ).catch(() => {});

  // Submit registration.
  await page.getByRole("button", { name: /request access/i }).first().click().catch(() => {});
  await page.waitForTimeout(2000);

  // ── 3. Verify with the dev-issued code ────────────────────────────────────
  await reveal(
    page,
    page.getByText(/verify your account|confirmation code/i).first(),
    "Confirm it's you",
    "A verification code is emailed to finish activating the account",
    { ms: 3600 },
  ).catch(() => {});

  // Fetch the 6-digit code from the dev console endpoint (dev-mode only).
  let code = "";
  for (let i = 0; i < 8 && !code; i++) {
    try {
      const r = await page.request.get(
        `${API}/internal/dev-tools/email/messages?mailbox=${encodeURIComponent(email)}&limit=1`,
      );
      const j = (await r.json()) as { messages?: Array<{ code?: string }> };
      code = (j.messages && j.messages[0] && j.messages[0].code) || "";
    } catch {
      /* retry */
    }
    if (!code) await page.waitForTimeout(1500);
  }

  if (code) {
    // Type into the OTP field (auto-advancing inputs).
    const otp = page
      .locator('input[inputmode="numeric"], input[autocomplete="one-time-code"], input[maxlength="1"]')
      .first();
    await otp.click().catch(() => {});
    await page.keyboard.type(code, { delay: 140 }).catch(() => {});
    await page.waitForTimeout(1200);
    await page.getByRole("button", { name: /verify account/i }).first().click().catch(() => {});
    await page.waitForTimeout(2200);
    await reveal(
      page,
      page.getByText(/registration complete|continue to sign in|secure your account/i).first(),
      "Account created",
      "Verified and ready — the new member can sign in",
      { ms: 4200 },
    ).catch(() => {});
  } else {
    await caption(page, "Email verification", "The code is delivered and entered to activate the account");
    await beat(page, 3000);
  }

  // ── 4. Security Center (as Alice) ─────────────────────────────────────────
  await caption(page, "Now — the Security Center", "Where members harden their account");
  await beat(page, 1600);
  await injectAuth(page, "alice");
  await page.goto(`${BASE}/security`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1600);

  const openTab = async (name: RegExp) => {
    await page
      .getByRole("tab", { name })
      .or(page.getByRole("button", { name }))
      .first()
      .click()
      .catch(() => {});
    await page.waitForTimeout(900);
  };

  // 4a. TOTP authenticator enrollment — name → QR → secret.
  await openTab(/mfa|authenticator/i);
  await reveal(
    page,
    page.getByText(/authenticator apps/i).first(),
    "Authenticator apps (TOTP)",
    "Time-based one-time-password devices, with one-time recovery codes",
    { ms: 4000 },
  ).catch(() => {});
  await page.getByRole("button", { name: /^add$/i }).first().click().catch(() => {});
  await page.waitForTimeout(900);
  await page
    .getByPlaceholder(/iphone|authenticator|google/i)
    .first()
    .fill("Pixel 8 — Authenticator")
    .catch(() => {});
  await page.getByRole("button", { name: /^continue$/i }).first().click().catch(() => {});
  await page.waitForTimeout(1100);
  await reveal(
    page,
    page.getByText(/manual entry key/i).first(),
    "Scan or type",
    "Scan the QR in any authenticator app, or enter the secret by hand",
    { ms: 5000 },
  ).catch(() => {});
  await page.keyboard.press("Escape").catch(() => {});
  await page.waitForTimeout(700);

  // 4b. Passkeys / WebAuthn.
  await openTab(/security keys|passkey|webauthn/i);
  await reveal(
    page,
    page.getByText(/security keys/i).first(),
    "Passkeys & security keys",
    "Hardware-backed, phishing-resistant sign-in with FIDO2 / WebAuthn",
    { ms: 4200 },
  ).catch(() => {});

  // 4c. API keys.
  await openTab(/api keys/i);
  await reveal(
    page,
    page.getByText(/api keys/i).first(),
    "Scoped API keys",
    "Programmatic access with per-scope permissions, expiry and IP rules",
    { ms: 4000 },
  ).catch(() => {});
  await page.getByRole("button", { name: /create key/i }).first().click().catch(() => {});
  await page.waitForTimeout(900);
  await reveal(
    page,
    page.getByText(/scopes/i).first(),
    "Least privilege",
    "Grant only the scopes a key needs — messaging, files, shop and more",
    { ms: 4200 },
  ).catch(() => {});
  await page.keyboard.press("Escape").catch(() => {});
  await page.waitForTimeout(600);

  // 4d. Active sessions.
  await openTab(/sessions/i);
  await reveal(
    page,
    page.getByText(/active sessions/i).first(),
    "Active sessions",
    "See every signed-in device — and revoke any of them in one click",
    { ms: 4200 },
  ).catch(() => {});

  // 4e. Recovery.
  await openTab(/recovery/i);
  await reveal(
    page,
    page.getByText(/password recovery/i).first(),
    "Self-service recovery",
    "Reset a forgotten password with a verification code — no support ticket",
    { ms: 4200 },
  ).catch(() => {});

  // ── 5. Outro ────────────────────────────────────────────────────────────────
  await caption(page, "Registration & MFA ✓", "Easy to join, hard to break into");
  await beat(page, 3000);
  await clearCaption(page);
  await beat(page, 900);
});
