import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import DevToolsLogUiPage from "@/pages/devtools/DevToolsLogUiPage";

const useDevtoolsEmailMessages = vi.fn();
const useDevtoolsSmsConversations = vi.fn();
const useDevtoolsBillingLedger = vi.fn();
const useDevtoolsBillingSummary = vi.fn();
const generateTotpCode = vi.fn();

vi.mock("@/hooks/useDevtoolsData", () => ({
  useDevtoolsEmailMessages: (...args: unknown[]) => useDevtoolsEmailMessages(...args),
  useDevtoolsSmsConversations: (...args: unknown[]) => useDevtoolsSmsConversations(...args),
  useDevtoolsBillingLedger: (...args: unknown[]) => useDevtoolsBillingLedger(...args),
  useDevtoolsBillingSummary: (...args: unknown[]) => useDevtoolsBillingSummary(...args),
}));

vi.mock("@/lib/totpGenerator", () => ({
  generateTotpCode: (...args: unknown[]) => generateTotpCode(...args),
}));

const emailHookBase = {
  mailboxes: [
    { id: "mb1", id_strategy: "hash", mailbox: "alpha@example.com", thread_count: 1, unread_count: 1 },
    { id: "mb2", id_strategy: "hash", mailbox: "beta@example.com", thread_count: 1, unread_count: 0 },
  ],
  threads: [
    {
      id: "th1",
      id_strategy: "hash",
      mailbox: "alpha@example.com",
      subject: "Your code",
      message_count: 1,
      unread_count: 1,
      participant_emails: ["alpha@example.com"],
      latest_message_at: "2026-01-01T12:00:00Z",
    },
  ],
  messages: [
    {
      id: "msg1",
      id_strategy: "hash",
      thread_id: "th1",
      mailbox: "alpha@example.com",
      sent_at: "2026-01-01T12:00:00Z",
      event_kind: "mfa_email_code",
      direction: "outbound",
      from_email: "noreply@testlogon.dev",
      to_emails: ["alpha@example.com"],
      subject: "Your code",
      body_text: "Your OTP code is 123456",
      status: "delivered",
      parse_warnings: [],
    },
  ],
  parseWarnings: [],
  errorMessage: null as string | null,
  isLoading: false,
};

const smsHookBase = {
  conversations: [
    {
      id: "conv-2",
      id_strategy: "hash",
      participant_numbers: ["+15550000002"],
      message_count: 1,
      latest_message_at: "2026-01-01T13:00:00Z",
      latest_preview: "Newest convo",
    },
    {
      id: "conv-1",
      id_strategy: "hash",
      participant_numbers: ["+15550000001"],
      message_count: 3,
      latest_message_at: "2026-01-01T12:00:00Z",
      latest_preview: "Code: 123456",
    },
  ],
  messages: [
    {
      id: "sms-1",
      id_strategy: "hash",
      conversation_id: "conv-1",
      sent_at: "2026-01-01T11:59:00Z",
      from_number: "+15550000001",
      to_number: "+15559999999",
      direction: "inbound",
      body_text: "Hello",
      status: "received",
      provider_message_id: "provider-1",
      event_kind: "alert_sms",
      parse_warnings: [],
    },
    {
      id: "sms-2",
      id_strategy: "hash",
      conversation_id: "conv-1",
      sent_at: "2026-01-01T12:00:00Z",
      from_number: "+15550000001",
      to_number: "+15559999999",
      direction: "inbound",
      body_text: "Code: 123456",
      status: "received",
      provider_message_id: "provider-2",
      event_kind: "mfa_sms_code",
      parse_warnings: [],
    },
    {
      id: "sms-3",
      id_strategy: "hash",
      conversation_id: "conv-1",
      sent_at: "2026-01-01T12:01:00Z",
      from_number: "+15559999999",
      to_number: "+15550000001",
      direction: "outbound",
      body_text: "Thanks",
      status: "sent",
      provider_message_id: "provider-3",
      event_kind: "alert_sms",
      parse_warnings: [],
    },
  ],
  parseWarnings: [],
  errorMessage: null as string | null,
  isLoading: false,
};

const billingLedgerBase = {
  entries: [
    {
      id: "b1",
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
  parseWarnings: [],
  summary: { gross_inflow: 10, fees: 0.5, net_total_balance: 9.5, transaction_count: 1, provider_counts: { stripe: 1 }, status_counts: { completed: 1 }, parse_warnings: [] },
  isLoading: false,
  isEmpty: false,
  errorMessage: null as string | null,
  hasNextPage: false,
  isFetchingNextPage: false,
  fetchNextPage: vi.fn(),
};

const billingSummaryBase = {
  data: { gross_inflow: 10, fees: 0.5, net_total_balance: 9.5, transaction_count: 1, provider_counts: { stripe: 1 }, status_counts: { completed: 1 }, parse_warnings: [] },
  parseWarnings: [],
  isLoading: false,
  isEmpty: false,
  errorMessage: null as string | null,
};

describe("DevToolsLogUiPage", () => {
  beforeEach(() => {
    vi.useRealTimers();
    useDevtoolsEmailMessages.mockReset();
    useDevtoolsSmsConversations.mockReset();
    useDevtoolsBillingLedger.mockReset();
    useDevtoolsBillingSummary.mockReset();
    generateTotpCode.mockReset();
    localStorage.clear();
  });

  const setupHooks = (overrides?: {
    email?: Partial<typeof emailHookBase>;
    sms?: Partial<typeof smsHookBase>;
    billingLedger?: Partial<typeof billingLedgerBase>;
    billingSummary?: Partial<typeof billingSummaryBase>;
  }) => {
    useDevtoolsEmailMessages.mockReturnValue({ ...emailHookBase, ...(overrides?.email ?? {}) });
    useDevtoolsSmsConversations.mockReturnValue({ ...smsHookBase, ...(overrides?.sms ?? {}) });
    useDevtoolsBillingLedger.mockReturnValue({ ...billingLedgerBase, ...(overrides?.billingLedger ?? {}) });
    useDevtoolsBillingSummary.mockReturnValue({ ...billingSummaryBase, ...(overrides?.billingSummary ?? {}) });
    generateTotpCode.mockResolvedValue({ code: "123456", counter: 1, secondsRemaining: 30, periodSeconds: 30 });
  };

  it("renders mailbox rail, thread list, and message detail", () => {
    setupHooks();

    render(<DevToolsLogUiPage />);

    expect(screen.getByText("All Inboxes")).toBeInTheDocument();
    expect(screen.getAllByText("alpha@example.com").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Your code").length).toBeGreaterThan(0);
    expect(screen.getByText("Your OTP code is 123456")).toBeInTheDocument();
  });

  it("passes mailbox/search/state filters to hook", async () => {
    const user = userEvent.setup();
    setupHooks();

    render(<DevToolsLogUiPage />);

    await user.click(screen.getByText("beta@example.com"));
    await user.type(screen.getByLabelText("Search email logs"), "invoice");

    expect(useDevtoolsEmailMessages).toHaveBeenLastCalledWith(
      expect.objectContaining({ mailbox: "beta@example.com", q: "invoice", state: "all", limit: 100 }),
      true,
    );
  });

  it("covers loading, empty, and error states across tabs", async () => {
    const user = userEvent.setup();
    setupHooks({
      email: { isLoading: true },
      sms: { conversations: [], messages: [], isLoading: false, errorMessage: "sms exploded" },
      billingLedger: { entries: [], isEmpty: true, errorMessage: "ledger exploded" },
      billingSummary: { errorMessage: "summary exploded" },
    });

    render(<DevToolsLogUiPage />);
    expect(screen.getByText("Loading email logs…")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "SMS" }));
    expect(screen.getByText(/Unable to load SMS logs: sms exploded/)).toBeInTheDocument();
    expect(screen.getByText("No conversations found.")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Billing" }));
    expect(screen.getByText(/Unable to load billing logs:/)).toBeInTheDocument();
    expect(screen.getByText("No ledger entries for selected filters.")).toBeInTheDocument();
  });

  it("renders iMessage-like thread with metadata and no mutating controls", async () => {
    const user = userEvent.setup();
    setupHooks();

    render(<DevToolsLogUiPage />);

    await user.click(screen.getByRole("tab", { name: "SMS" }));

    const convoButtons = screen.getAllByRole("button", { name: /\+1555000000/i });
    expect(convoButtons[0]).toHaveTextContent("+15550000002");
    await user.click(screen.getByRole("button", { name: /\+15550000001/i }));

    expect(screen.getAllByText("Code: 123456").length).toBeGreaterThan(0);
    expect(screen.getByText("Message metadata")).toBeInTheDocument();
    expect(screen.getByText("provider-3")).toBeInTheDocument();

    expect(screen.queryByRole("button", { name: /send/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /delete/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /edit/i })).not.toBeInTheDocument();
  });

  it("enforces read-only billing UX with raw inspection only", async () => {
    const user = userEvent.setup();
    setupHooks();

    render(<DevToolsLogUiPage />);
    await user.click(screen.getByRole("tab", { name: "Billing" }));

    expect(screen.getByText("Gross inflow")).toBeInTheDocument();
    expect(screen.getByText("charge.succeeded")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "View raw" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "View raw" }));
    expect(screen.getByText("Raw billing payload")).toBeInTheDocument();
    expect(screen.getByText(/ok/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close" }));

    expect(useDevtoolsBillingLedger).toHaveBeenCalledWith(
      expect.objectContaining({ provider: undefined, status: undefined, limit: 50 }),
      true,
    );

    expect(screen.queryByRole("button", { name: /refund/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /charge/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /delete/i })).not.toBeInTheDocument();
  });

  it("drives deterministic TOTP lifecycle: parse, countdown tick, rollover, and reset", async () => {
    const user = userEvent.setup();
    setupHooks();

    let call = 0;
    generateTotpCode.mockImplementation(async () => {
      call += 1;
      if (call === 1) return { code: "111111", counter: 1, secondsRemaining: 30, periodSeconds: 30 };
      if (call === 2) return { code: "111111", counter: 1, secondsRemaining: 29, periodSeconds: 30 };
      return { code: "222222", counter: 2, secondsRemaining: 30, periodSeconds: 30 };
    });

    render(<DevToolsLogUiPage />);
    await user.click(screen.getByRole("tab", { name: "MFA (TOTP)" }));

    vi.useFakeTimers();

    fireEvent.change(screen.getByRole("textbox", { name: "Paste TOTP configuration" }), {
      target: {
        value: "otpauth://totp/TestLogon:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=TestLogon",
      },
    });

    await vi.advanceTimersByTimeAsync(1);
    expect(screen.getByText("111111")).toBeInTheDocument();
    expect(screen.getAllByText("30s").length).toBeGreaterThan(0);

    await vi.advanceTimersByTimeAsync(1000);
    expect(screen.getByText("29s")).toBeInTheDocument();

    await vi.advanceTimersByTimeAsync(1000);
    expect(screen.getByText("222222")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Clear / Reset" }));
    expect(screen.getByRole("textbox", { name: "Paste TOTP configuration" })).toHaveValue("");
    expect(screen.getByText("Provide a valid TOTP configuration to generate live codes.")).toBeInTheDocument();
  }, 15000);
});
