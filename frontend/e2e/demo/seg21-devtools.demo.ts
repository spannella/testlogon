/**
 * VIDEO SEGMENT 21 — Developer Tools  (~1 min)
 *
 * The standalone Dev Tools console (its own app on :3001, no auth) that makes the
 * mocked-services dev stack legible:
 *   - Email explorer — every outbound email (incl. MFA/verification codes)
 *   - SMS explorer — outbound texts, grouped into conversations
 *   - MFA (TOTP) — a fully client-side authenticator that generates live codes
 *   - Billing — the payment ledger with summary cards and raw payloads
 *
 * Seeding (off camera): append a couple of email + SMS records to the dev log
 * files the console reads, so the Email/SMS tabs have real content on screen.
 * The TOTP tab needs no data — we paste a secret and it generates live codes.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg21-devtools.demo.ts
 */
import { appendFileSync, mkdirSync } from "fs";
import { test } from "@playwright/test";
import { caption, clearCaption, titleCard, beat, reveal } from "./_demo";

const DEVTOOLS = "http://localhost:3001/devtools.html";
const LOG_DIR = "/home/ubuntu/testlogon/.logs/dev";

test("Segment 21 — Developer Tools", async ({ page }) => {
  test.setTimeout(600_000);

  // ── Seed the dev email + SMS logs the console reads ───────────────────────
  try {
    mkdirSync(LOG_DIR, { recursive: true });
    const emails = [
      "[2026-06-08T12:00:00Z] TO=demo.user@test.local PURPOSE=Registration\n" +
        "  Subject: Your verification code (Registration)\n" +
        "  Code: 481920\n" +
        "  Body: Your verification code is: 481920\n",
      "[2026-06-08T12:03:00Z] TO=alice@test.local PURPOSE=ALERT_EMAIL\n" +
        "  Subject: New sign-in to your account\n" +
        "  Body: We noticed a new sign-in from Chrome on macOS.\n",
      "[2026-06-08T12:06:00Z] TO=buyer@test.local PURPOSE=Receipt\n" +
        "  Subject: Your receipt — Gold subscription\n" +
        "  Body: Thanks! Your payment of $20.00 was received.\n",
    ];
    appendFileSync(`${LOG_DIR}/emails.log`, emails.join("\n") + "\n");
    const sms = [
      `{"sent_at":"2026-06-08T12:00:00Z","from":"+15550000000","to":"+15551234567","body":"Your verification code is 222333","code":"222333","conversation_id":"conv_demo_a"}`,
      `{"sent_at":"2026-06-08T12:04:00Z","from":"+15550000000","to":"+15559876543","body":"Reminder: your appointment is tomorrow at 10am","conversation_id":"conv_demo_b"}`,
    ];
    appendFileSync(`${LOG_DIR}/sms.log`, sms.join("\n") + "\n");
  } catch {
    /* tolerate — the MFA + structure beats still work without seeded logs */
  }

  // ── 1. Intro ──────────────────────────────────────────────────────────────
  await page.goto(DEVTOOLS, { waitUntil: "domcontentloaded" }).catch(async () => {
    await page.goto("http://localhost:3001/", { waitUntil: "domcontentloaded" });
  });
  await page.waitForTimeout(1400);
  await titleCard(
    page,
    21,
    "Developer Tools",
    "A console for the mocked dev stack — email · SMS · TOTP · billing",
  );

  const openTab = async (name: RegExp) => {
    await page
      .getByRole("tab", { name })
      .or(page.getByRole("button", { name }))
      .first()
      .click()
      .catch(() => {});
    await page.waitForTimeout(900);
  };

  await reveal(
    page,
    page.getByText(/dev tools log ui/i).first(),
    "The dev console",
    "No auth, its own app — read-only visibility into every mocked service",
    { ms: 3800 },
  ).catch(() => {});

  // ── 2. Email explorer ─────────────────────────────────────────────────────
  await openTab(/^email$/i);
  await reveal(
    page,
    page.getByText(/verification code/i).first(),
    "Every outbound email",
    "Inspect verification codes, alerts and receipts the stack 'sent'",
    { ms: 4500 },
  ).catch(() => {});

  // ── 3. SMS explorer ───────────────────────────────────────────────────────
  await openTab(/^sms$/i);
  await reveal(
    page,
    page.getByText(/conversations/i).first(),
    "Outbound SMS",
    "Texts grouped into conversations — codes, reminders, notifications",
    { ms: 4200 },
  ).catch(() => {});

  // ── 4. MFA (TOTP) — live authenticator ────────────────────────────────────
  await openTab(/mfa|totp/i);
  await page
    .getByPlaceholder(/otpauth|base32|secret/i)
    .or(page.getByRole("textbox").first())
    .first()
    .fill("JBSWY3DPEHPK3PXP")
    .catch(() => {});
  await page.waitForTimeout(1400);
  await reveal(
    page,
    page.getByText(/current code|live code/i).first(),
    "A live authenticator",
    "Paste a secret and it generates real TOTP codes — entirely in your browser",
    { ms: 5200 },
  ).catch(() => {});

  // ── 5. Billing ledger ─────────────────────────────────────────────────────
  await openTab(/^billing$/i);
  await reveal(
    page,
    page.getByText(/gross inflow/i).first(),
    "The payment ledger",
    "Gross inflow, fees and net — with the raw provider payload one click away",
    { ms: 4800 },
  ).catch(() => {});

  // ── 6. Outro ────────────────────────────────────────────────────────────────
  await caption(page, "Developer Tools ✓", "A transparent, debuggable dev stack");
  await beat(page, 3000);
  await clearCaption(page);
  await beat(page, 800);
});
