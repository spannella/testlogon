import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// -- Controllable strategy hooks (isolate the invest-gating logic) --------
const strategyData: { current: any } = { current: undefined };
const investMutate = vi.fn();

function q(data: unknown, extra: Record<string, unknown> = {}) {
  return { data, isLoading: false, isError: false, ...extra };
}

vi.mock("@/hooks/useStrategies", () => ({
  useStrategy: () => q(strategyData.current),
  useStrategyNav: () => q({ nav_per_unit: 10000, aum_cents: strategyData.current?.aum_cents ?? 0 }),
  useStrategyHoldings: () => q(undefined, { isError: true }),
  useStrategyPosition: () => q(undefined),
  useStrategyFees: () => q(undefined),
  useInvestStrategy: () => ({ mutateAsync: investMutate, isPending: false }),
  useRedeemStrategy: () => ({ mutateAsync: vi.fn(), isPending: false }),
  usePublishStrategy: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));

vi.mock("@/hooks/useMarketData", () => ({
  useSymbols: () => q({ symbols: [] }),
}));

vi.mock("@/hooks/useWatchlist", () => ({
  useWatchlist: () => ({ has: () => false, toggle: vi.fn(), remove: vi.fn(), items: [] }),
}));

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (sel: (s: { userId: string | null }) => unknown) => sel({ userId: "viewer" }),
}));

vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));

import StrategyDetailPage from "./StrategyDetailPage";

function makeStrategy(over: Record<string, unknown> = {}) {
  return {
    strategy_id: "s1",
    creator_sub: "someone-else",
    name: "Blue Chip Basket",
    description: "",
    kind: "basket",
    status: "published",
    legs: [],
    rebalance: "none",
    min_investment_cents: 100_00, // $100 minimum
    max_aum_cents: 1_000_00, // $1,000 capacity
    aum_cents: 900_00, // $900 already in -> $100 remaining
    mgmt_fee_bps: 100,
    perf_fee_bps: 1000,
    high_water_mark: true,
    redemption: { type: "instant" },
    created_ts: 0,
    ...over,
  };
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/strategies/s1"]}>
      <Routes>
        <Route path="/strategies/:id" element={<StrategyDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

async function goToInvestTab(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("tab", { name: "Invest" }));
  return screen.getByTestId("invest-amount");
}

describe("StrategyDetailPage invest gating", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    strategyData.current = makeStrategy();
  });

  it("blocks investing below the fund minimum", async () => {
    const user = userEvent.setup();
    renderPage();
    const amt = await goToInvestTab(user);

    await user.type(amt, "50"); // $50 < $100 minimum
    expect(screen.getByText("Amount is below the fund's minimum investment.")).toBeInTheDocument();
    expect(screen.getByTestId("invest-review")).toBeDisabled();
  });

  it("blocks investing over the remaining capacity", async () => {
    const user = userEvent.setup();
    renderPage();
    const amt = await goToInvestTab(user);

    await user.type(amt, "500"); // $500 > $100 remaining capacity
    expect(screen.getByText("Amount exceeds the fund's remaining capacity.")).toBeInTheDocument();
    expect(screen.getByTestId("invest-review")).toBeDisabled();
  });

  it("enables invest for a valid in-range amount and opens the confirm", async () => {
    const user = userEvent.setup();
    renderPage();
    const amt = await goToInvestTab(user);

    investMutate.mockResolvedValue({ units: 1, nav_per_unit: 10000 });
    await user.type(amt, "100"); // exactly min, within remaining capacity
    const review = screen.getByTestId("invest-review");
    await waitFor(() => expect(review).toBeEnabled());
    await user.click(review);

    expect(await screen.findByText("Confirm investment")).toBeInTheDocument();
    await user.click(screen.getByTestId("invest-confirm"));
    await waitFor(() => expect(investMutate).toHaveBeenCalledWith({ amount_cents: 100_00 }));
  });

  it("disables the invest control entirely when the fund is not published", async () => {
    strategyData.current = makeStrategy({ status: "draft" });
    const user = userEvent.setup();
    renderPage();
    const amt = await goToInvestTab(user);

    expect(amt).toBeDisabled();
    expect(screen.getByTestId("invest-review")).toBeDisabled();
    expect(screen.getByText(/not open for investment yet/i)).toBeInTheDocument();
  });
});
