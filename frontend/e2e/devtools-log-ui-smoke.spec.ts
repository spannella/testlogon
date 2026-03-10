import { test, expect } from "@playwright/test";

const BASE_URL = "http://localhost:3001";

test.describe("Dev Tools Log UI smoke", () => {
  test.beforeEach(async ({ page }) => {
    await page.route("**/internal/dev-tools/email/messages**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          mailboxes: [
            { id: "mb1", id_strategy: "hash", mailbox: "qa@example.com", thread_count: 1, unread_count: 1 },
          ],
          threads: [
            {
              id: "th1",
              id_strategy: "hash",
              mailbox: "qa@example.com",
              subject: "Smoke email",
              message_count: 1,
              unread_count: 1,
              participant_emails: ["qa@example.com"],
              latest_message_at: "2026-01-01T12:00:00Z",
            },
          ],
          messages: [
            {
              id: "msg1",
              id_strategy: "hash",
              thread_id: "th1",
              mailbox: "qa@example.com",
              sent_at: "2026-01-01T12:00:00Z",
              event_kind: "mfa_email_code",
              direction: "outbound",
              from_email: "noreply@testlogon.dev",
              to_emails: ["qa@example.com"],
              subject: "Smoke email",
              body_text: "Your OTP code is 123456",
              status: "delivered",
              parse_warnings: [],
            },
          ],
          parse_warnings: [],
          next_cursor: null,
        }),
      });
    });

    await page.route("**/internal/dev-tools/sms/conversations**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          conversations: [
            {
              id: "conv-1",
              id_strategy: "hash",
              participant_numbers: ["+15550000001"],
              message_count: 2,
              latest_message_at: "2026-01-01T12:01:00Z",
              latest_preview: "Code: 654321",
            },
          ],
          messages: [
            {
              id: "sms-1",
              id_strategy: "hash",
              conversation_id: "conv-1",
              sent_at: "2026-01-01T12:00:00Z",
              from_number: "+15550000001",
              to_number: "+15559999999",
              direction: "inbound",
              body_text: "Code: 654321",
              status: "received",
              provider_message_id: "provider-1",
              event_kind: "mfa_sms_code",
              parse_warnings: [],
            },
            {
              id: "sms-2",
              id_strategy: "hash",
              conversation_id: "conv-1",
              sent_at: "2026-01-01T12:01:00Z",
              from_number: "+15559999999",
              to_number: "+15550000001",
              direction: "outbound",
              body_text: "Thanks",
              status: "sent",
              provider_message_id: "provider-2",
              event_kind: "alert_sms",
              parse_warnings: [],
            },
          ],
          parse_warnings: [],
          next_cursor: null,
        }),
      });
    });

    await page.route("**/internal/dev-tools/billing/ledger**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          entries: [
            {
              id: "bill-1",
              id_strategy: "hash",
              provider: "stripe",
              event_type: "charge.succeeded",
              status: "completed",
              occurred_at: "2026-01-01T12:02:00Z",
              external_id: "ch_123",
              amount: 10,
              fee: 0.5,
              net: 9.5,
              currency: "usd",
              source_path: "stripe.log",
              raw_payload: { ok: true },
              parse_warnings: [],
            },
          ],
          parse_warnings: [],
          next_cursor: null,
        }),
      });
    });

    await page.route("**/internal/dev-tools/billing/summary**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          gross_inflow: 10,
          fees: 0.5,
          net_total_balance: 9.5,
          transaction_count: 1,
          provider_counts: { stripe: 1 },
          status_counts: { completed: 1 },
          parse_warnings: [],
        }),
      });
    });
  });

  test("opens the route, visits each tab, and verifies read-only markers", async ({ page }) => {
    await page.goto(`${BASE_URL}`, { waitUntil: "domcontentloaded" });

    await expect(page.getByRole("heading", { name: "Dev Tools Log UI" })).toBeVisible();

    // Email
    await expect(page.getByText("All Inboxes")).toBeVisible();
    await expect(page.getByText("Smoke email").first()).toBeVisible();
    await expect(page.getByText("Your OTP code is 123456")).toBeVisible();
    await expect(page.getByRole("button", { name: /send/i })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /delete/i })).toHaveCount(0);

    // SMS
    await page.getByRole("tab", { name: "SMS" }).click();
    await expect(page.getByText("+15550000001").first()).toBeVisible();
    await expect(page.getByText("Code: 654321").first()).toBeVisible();
    await expect(page.getByText("Message metadata")).toBeVisible();
    await expect(page.getByRole("button", { name: /edit/i })).toHaveCount(0);

    // MFA
    await page.getByRole("tab", { name: "MFA (TOTP)" }).click();
    await expect(page.getByText(/Local-only tool:/)).toBeVisible();
    await expect(page.getByText("Provide a valid TOTP configuration to generate live codes.")).toBeVisible();

    // Billing
    await page.getByRole("tab", { name: "Billing" }).click();
    await expect(page.getByText("Gross inflow")).toBeVisible();
    await expect(page.getByText("charge.succeeded")).toBeVisible();
    await page.getByRole("button", { name: "View raw" }).click();
    await expect(page.getByText("Raw billing payload")).toBeVisible();
    await expect(page.getByRole("button", { name: /refund/i })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /charge/i })).toHaveCount(0);
  });
});
