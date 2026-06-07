/**
 * VIDEO SEGMENT 01 — Authentication & Onboarding  (~1 min)
 *
 * Beats: intro title card → login page → signed-in dashboard → Security center
 * (MFA devices, API keys, active sessions, WebAuthn/passkeys).
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg01-auth.demo.ts
 */
import { test } from "@playwright/test";
import { BASE, injectAuth, caption, clearCaption, titleCard, beat, visit } from "./_demo";

test("Segment 01 — Authentication & Onboarding", async ({ page }) => {
  // ── Intro ──────────────────────────────────────────────────────────────
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await titleCard(
    page,
    1,
    "Authentication & Onboarding",
    "Cookie sessions · CSRF · Cognito JWT · MFA · Passkeys",
  );

  // ── Login page ─────────────────────────────────────────────────────────
  await caption(
    page,
    "Secure sign-in",
    "Cookie-based UI sessions with CSRF protection, backed by Cognito JWTs",
  );
  await beat(page, 2600);

  // Type into the email field for visual effect (best-effort selectors).
  const emailField = page
    .locator(
      'input[type="email"], input[name="email"], input[placeholder*="mail" i], #email',
    )
    .first();
  if (await emailField.count().catch(() => 0)) {
    await emailField.click().catch(() => {});
    await emailField.fill("e2e_alice@test.local").catch(() => {});
    await beat(page, 1800);
  }
  const pwField = page.locator('input[type="password"]').first();
  if (await pwField.count().catch(() => 0)) {
    await pwField.click().catch(() => {});
    await pwField.fill("••••••••••").catch(() => {});
    await beat(page, 1500);
  }

  // ── Sign in (inject the seeded Alice session, then land on the dashboard) ──
  await injectAuth(page, "alice");
  await caption(page, "Signed in", "Landing on the personalized dashboard");
  await visit(page, "/", 1600);
  await beat(page, 3000);

  // ── Dashboard glance ─────────────────────────────────────────────────────
  await caption(
    page,
    "Your dashboard",
    "Activity, messages, billing and quick actions at a glance",
  );
  await beat(page, 3200);

  // ── Security center ──────────────────────────────────────────────────────
  await caption(page, "Security center", "Manage how you protect your account");
  await visit(page, "/security", 1800);
  await beat(page, 3000);

  // Walk the security surfaces. The SecurityPage exposes MFA devices, API keys,
  // active sessions and WebAuthn/passkeys — surface each via its tab/heading if
  // present (best-effort, tolerant to label variations).
  const surfaces: Array<{ name: string; cap: string; sub: string }> = [
    { name: "MFA", cap: "Multi-factor authentication", sub: "TOTP authenticator devices & recovery codes" },
    { name: "Passkey", cap: "Passkeys / WebAuthn", sub: "Hardware-backed, phishing-resistant sign-in" },
    { name: "API", cap: "API keys", sub: "Scoped, peppered keys for programmatic access" },
    { name: "Session", cap: "Active sessions", sub: "See and revoke signed-in devices" },
  ];
  for (const s of surfaces) {
    const tab = page
      .getByRole("tab", { name: new RegExp(s.name, "i") })
      .or(page.getByRole("button", { name: new RegExp(s.name, "i") }))
      .first();
    await caption(page, s.cap, s.sub);
    if (await tab.count().catch(() => 0)) {
      await tab.click().catch(() => {});
    }
    await beat(page, 2800);
  }

  // ── Outro caption ────────────────────────────────────────────────────────
  await caption(page, "Authentication ✓", "Next: real-time messaging");
  await beat(page, 2600);
  await clearCaption(page);
  await beat(page, 800);
});
