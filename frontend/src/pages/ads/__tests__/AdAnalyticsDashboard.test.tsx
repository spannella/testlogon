import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import AdAnalyticsDashboard from "../AdAnalyticsDashboard";

const listMyAdAccounts = vi.fn();
const getAnalyticsSummary = vi.fn();
const getAnalyticsTimeseries = vi.fn();
const getAnalyticsBreakdown = vi.fn();
const getAdRoasReport = vi.fn();

vi.mock("@/api/endpoints/ads", () => ({
  listMyAdAccounts: (...a: unknown[]) => listMyAdAccounts(...a),
  getAnalyticsSummary: (...a: unknown[]) => getAnalyticsSummary(...a),
  getAnalyticsTimeseries: (...a: unknown[]) => getAnalyticsTimeseries(...a),
  getAnalyticsBreakdown: (...a: unknown[]) => getAnalyticsBreakdown(...a),
  getAdRoasReport: (...a: unknown[]) => getAdRoasReport(...a),
  exportAnalyticsCsv: () => "http://example/export.csv",
}));

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <AdAnalyticsDashboard />
    </QueryClientProvider>,
  );
}

function account(id: string, name: string) {
  return {
    account_id: id,
    owner_sub: "u1",
    company_name: name,
    billing_email: "b@x.co",
    status: "active",
    balance_cents: 0,
    lifetime_spend_cents: 0,
    created_at: 0,
    updated_at: 0,
  };
}

describe("AdAnalyticsDashboard account picker (BUG 4)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Clear any ?account_id from a prior test.
    window.history.replaceState({}, "", "/");
    getAnalyticsSummary.mockResolvedValue({
      impressions: 10,
      clicks: 2,
      ctr_pct: 20,
      spend_cents: 500,
      cpc_cents: 250,
    });
    getAnalyticsTimeseries.mockResolvedValue([]);
    getAnalyticsBreakdown.mockResolvedValue([]);
    getAdRoasReport.mockResolvedValue({
      totals: { conversions: 0, conversion_value_cents: 0, spend_cents: 0, roas: 0 },
      campaigns: [],
    });
  });

  it("auto-selects the first account and drives the analytics queries (no dead-end)", async () => {
    listMyAdAccounts.mockResolvedValue([account("acct_1", "Acme"), account("acct_2", "Globex")]);

    renderPage();

    // The picker renders and analytics is fetched for the first account —
    // previously this page dead-ended on "No account selected".
    await waitFor(() => {
      expect(screen.getByTestId("account-select")).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(getAnalyticsSummary).toHaveBeenCalledWith("acct_1", expect.anything());
    });
    expect(screen.queryByText(/No account selected/i)).not.toBeInTheDocument();
  });

  it("shows a create-account hint when the user has no advertiser accounts", async () => {
    listMyAdAccounts.mockResolvedValue([]);

    renderPage();

    await waitFor(() => {
      expect(screen.getByTestId("no-accounts")).toBeInTheDocument();
    });
    expect(getAnalyticsSummary).not.toHaveBeenCalled();
  });
});
