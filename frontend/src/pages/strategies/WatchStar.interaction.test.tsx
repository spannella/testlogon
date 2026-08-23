import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { loadWatchlist, isWatched, WATCHLIST_KEY } from "@/lib/watchlist";

// Minimal strategy hook stubs so the page renders; the watch star uses the
// REAL useWatchlist store so we can assert persistence + reflected state.
function q(data: unknown, extra: Record<string, unknown> = {}) {
  return { data, isLoading: false, isError: false, ...extra };
}
vi.mock("@/hooks/useStrategies", () => ({
  useStrategy: () => q({
    strategy_id: "s1",
    creator_sub: "other",
    name: "Blue Chip",
    description: "",
    kind: "basket",
    status: "published",
    legs: [],
    rebalance: "none",
    min_investment_cents: 0,
    max_aum_cents: 0,
    mgmt_fee_bps: 0,
    perf_fee_bps: 0,
    high_water_mark: false,
    redemption: { type: "instant" },
    created_ts: 0,
  }),
  useStrategyNav: () => q(undefined),
  useStrategyHoldings: () => q(undefined, { isError: true }),
  useStrategyPosition: () => q(undefined),
  useStrategyFees: () => q(undefined),
  useInvestStrategy: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useRedeemStrategy: () => ({ mutateAsync: vi.fn(), isPending: false }),
  usePublishStrategy: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));
vi.mock("@/hooks/useMarketData", () => ({ useSymbols: () => q({ symbols: [] }) }));
vi.mock("@/stores/authStore", () => ({
  useAuthStore: (sel: (s: { userId: string | null }) => unknown) => sel({ userId: "viewer" }),
}));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));

import StrategyDetailPage from "./StrategyDetailPage";

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/strategies/s1"]}>
      <Routes>
        <Route path="/strategies/:id" element={<StrategyDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("Watch-star toggle writes through to the watchlist store", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("clicking the star adds then removes the strategy from the store", async () => {
    const user = userEvent.setup();
    renderPage();

    const star = screen.getByRole("button", { name: /watch/i });
    expect(star).toHaveAttribute("aria-pressed", "false");
    expect(isWatched(loadWatchlist(), "strategy", "s1")).toBe(false);

    await user.click(star);
    await waitFor(() => expect(isWatched(loadWatchlist(), "strategy", "s1")).toBe(true));
    // The store persisted under the shared key.
    expect(JSON.parse(window.localStorage.getItem(WATCHLIST_KEY) as string)).toEqual([
      { kind: "strategy", id: "s1" },
    ]);
    // And the button reflects the watched state.
    expect(screen.getByRole("button", { name: /watching/i })).toHaveAttribute("aria-pressed", "true");

    await user.click(screen.getByRole("button", { name: /watching/i }));
    await waitFor(() => expect(isWatched(loadWatchlist(), "strategy", "s1")).toBe(false));
    expect(JSON.parse(window.localStorage.getItem(WATCHLIST_KEY) as string)).toEqual([]);
  });
});
