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

describe("BillingOverview payment issue flows", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getBalance.mockResolvedValue({
      currency: "usd",
      owed_settled_cents: 0,
      owed_pending_cents: 0,
      payments_settled_cents: 0,
      payments_pending_cents: 0,
      updated_at: 1700000000,
    });
    getSettings.mockResolvedValue({ autopay_enabled: false, currency: "usd", default_payment_method_id: "pm_1" });
    getConfig.mockResolvedValue({ currency: "usd" });
    setAutopay.mockResolvedValue({ ok: true });
    payBalance.mockResolvedValue({ status: "succeeded" });
    getPaymentMethods.mockResolvedValue([
      { payment_method_id: "pm_1", method_type: "card", priority: 1, label: "Visa ****1111" },
      { payment_method_id: "pm_2", method_type: "card", priority: 2, label: "Mastercard ****2222" },
    ]);
  });

  it("shows success guidance after confirm-and-retry succeeds", async () => {
    getPaymentIssues.mockResolvedValue({
      items: [{ incident_id: "inc_1", provider: "stripe", status: "customer_action_required", requires_customer_action: true, customer_action_type: "confirm" }],
      count: 1,
    });
    confirmAndRetryCharge.mockResolvedValue({ ok: true, code: "ok", message: "retried" });

    renderPage();

    expect(await screen.findByText("Payment issue needs confirmation")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Confirm and Retry Charge" }));
    await userEvent.click(await screen.findByRole("button", { name: "Retry Charge" }));

    await waitFor(() => {
      expect(confirmAndRetryCharge).toHaveBeenCalledWith("inc_1");
    });
    expect(await screen.findByText(/Retry submitted successfully/i)).toBeInTheDocument();
  });

  it("keeps retry-automatic button disabled until prerequisites are met, then clears issue on success", async () => {
    getPaymentIssues.mockResolvedValue({
      items: [{
        incident_id: "inc_auto_1",
        provider: "stripe",
        status: "customer_action_required",
        requires_customer_action: true,
        customer_action_type: "update_method",
        retry_attempts: [],
      }],
      count: 1,
    });
    setDefaultAndRetryAutomaticPayment.mockResolvedValue({ ok: true, code: "ok", message: "retried" });

    renderPage();

    expect(await screen.findByText("Automatic payment needs a method fix")).toBeInTheDocument();
    const retryButton = screen.getByRole("button", { name: "Retry automatic payment" });
    expect(retryButton).toBeDisabled();

    await userEvent.selectOptions(screen.getByLabelText("Payment method to use"), "pm_2");
    expect(retryButton).toBeDisabled();

    await userEvent.click(screen.getByLabelText("I updated/confirmed this payment method"));
    expect(retryButton).toBeEnabled();

    await userEvent.click(retryButton);
    await waitFor(() => {
      expect(setDefaultAndRetryAutomaticPayment).toHaveBeenCalledWith("pm_2", "inc_auto_1");
    });

    await waitFor(() => {
      expect(screen.queryByText("Automatic payment needs a method fix")).not.toBeInTheDocument();
    });
  });

  it("shows escalation guidance on repeated auto-payment failure", async () => {
    getPaymentIssues.mockResolvedValue({
      items: [{
        incident_id: "inc_auto_2",
        provider: "stripe",
        status: "customer_action_required",
        requires_customer_action: true,
        customer_action_type: "update_method",
        retry_attempts: [{ attempt_id: "a1" }, { attempt_id: "a2" }],
      }],
      count: 1,
    });

    renderPage();

    expect(await screen.findByText("Automatic payment needs a method fix")).toBeInTheDocument();
    expect(screen.getByText(/still can't process automatic payment/i)).toBeInTheDocument();
  });
});
