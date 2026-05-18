import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { BillingOverview } from "../BillingOverview";

const getBalance = vi.fn();
const getSettings = vi.fn();
const getConfig = vi.fn();
const setAutopay = vi.fn();
const payBalance = vi.fn();
const getPaymentIssues = vi.fn();
const confirmAndRetryCharge = vi.fn();
const retryAutomaticPayment = vi.fn();
const setDefaultAndRetryAutomaticPayment = vi.fn();
const getPaymentMethods = vi.fn();

vi.mock("@/api/endpoints/billing", () => ({
  getBalance: (...args: unknown[]) => getBalance(...args),
  getSettings: (...args: unknown[]) => getSettings(...args),
  getConfig: (...args: unknown[]) => getConfig(...args),
  setAutopay: (...args: unknown[]) => setAutopay(...args),
  payBalance: (...args: unknown[]) => payBalance(...args),
  getPaymentIssues: (...args: unknown[]) => getPaymentIssues(...args),
  confirmAndRetryCharge: (...args: unknown[]) => confirmAndRetryCharge(...args),
  retryAutomaticPayment: (...args: unknown[]) => retryAutomaticPayment(...args),
  setDefaultAndRetryAutomaticPayment: (...args: unknown[]) => setDefaultAndRetryAutomaticPayment(...args),
  getPaymentMethods: (...args: unknown[]) => getPaymentMethods(...args),
}));

vi.mock("sonner", () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}));

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <BillingOverview />
    </QueryClientProvider>,
  );
}

describe("BillingOverview e2e provider retry matrix", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getBalance.mockResolvedValue({ currency: "usd", owed_settled_cents: 0, owed_pending_cents: 0, payments_settled_cents: 0, payments_pending_cents: 0 });
    getSettings.mockResolvedValue({ autopay_enabled: false, currency: "usd", default_payment_method_id: "pm_1" });
    getConfig.mockResolvedValue({ currency: "usd" });
    setAutopay.mockResolvedValue({ ok: true });
    payBalance.mockResolvedValue({ status: "succeeded" });
    getPaymentMethods.mockResolvedValue([{ payment_method_id: "pm_1", method_type: "card", priority: 1, label: "Visa ****1111" }]);
  });

  it("supports confirm+retry flow across providers", async () => {
    getPaymentIssues.mockResolvedValue({
      items: [
        { incident_id: "inc_s", provider: "stripe", status: "customer_action_required", requires_customer_action: true, customer_action_type: "confirm" },
        { incident_id: "inc_p", provider: "paypal", status: "customer_action_required", requires_customer_action: true, customer_action_type: "confirm" },
        { incident_id: "inc_c", provider: "ccbill", status: "customer_action_required", requires_customer_action: true, customer_action_type: "confirm" },
      ],
      count: 3,
    });
    confirmAndRetryCharge.mockResolvedValue({ ok: true, code: "ok", message: "retried" });

    renderPage();
    expect(await screen.findByText(/Payment issue needs confirmation/i)).toBeInTheDocument();

    const retryButtons = await screen.findAllByRole("button", { name: "Confirm and Retry Charge" });
    await userEvent.click(retryButtons[0]);
    await userEvent.click(await screen.findByRole("button", { name: "Retry Charge" }));

    await waitFor(() => {
      expect(confirmAndRetryCharge).toHaveBeenCalled();
    });
  });
});
