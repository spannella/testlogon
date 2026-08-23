import { describe, expect, it, vi, beforeEach, beforeAll } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { loadPriceAlerts, PRICE_ALERTS_KEY } from "@/lib/priceAlerts";

// jsdom lacks the pointer-capture / scroll APIs Radix Select relies on. Polyfill
// them locally (no global setup / config changes) so the real Select is drivable.
beforeAll(() => {
  const proto = window.HTMLElement.prototype as unknown as Record<string, unknown>;
  proto.hasPointerCapture = () => false;
  proto.setPointerCapture = () => {};
  proto.releasePointerCapture = () => {};
  proto.scrollIntoView = () => {};
});

function q(data: unknown) {
  return { data, isLoading: false, isError: false };
}

vi.mock("@/hooks/useMarketData", () => ({
  useSymbols: () => q({ symbols: [{ symbol_id: 1, symbol: "BTC-USD", price_scaler: 100 }] }),
  useCandles: () => q({ bars: [{ close: 6500000 }] }),
}));
vi.mock("@/hooks/useTokens", () => ({
  useTokenMarket: () => q({ tokens: [{ token_id: "tk1", ticker: "JANE", name: "Jane Revenue", clearing_price: 1250 }] }),
  useMyTokens: () => q({ tokens: [] }),
}));
vi.mock("@/hooks/useStrategies", () => ({
  useStrategyMarket: () => q({ strategies: [{ strategy_id: "st1", name: "Blue Chip Basket" }] }),
  useMyStrategies: () => q({ strategies: [] }),
  useStrategyNav: () => q({ nav_per_unit: 10500 }),
}));

import PriceAlertsPage from "./PriceAlertsPage";

function renderPage(initial = "/markets/price-alerts") {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <PriceAlertsPage />
    </MemoryRouter>,
  );
}

/** Drive a Radix Select by opening its trigger and clicking an option. */
async function selectOption(
  user: ReturnType<typeof userEvent.setup>,
  triggerLabel: string,
  optionName: RegExp,
) {
  await user.click(screen.getByLabelText(triggerLabel));
  await user.click(await screen.findByRole("option", { name: optionName }));
}

describe("PriceAlertsPage create-alert flow", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("shows the empty state before any alert exists", () => {
    renderPage();
    expect(screen.getByText("Active (0)")).toBeInTheDocument();
    expect(screen.getByText("No active alerts")).toBeInTheDocument();
  });

  it("creating a Creator-token alert (via deep-link prefill) adds it to the active list + store", async () => {
    const user = userEvent.setup();
    // Deep-link prefill selects the token kind + first token without touching the Select.
    renderPage("/markets/price-alerts?kind=token&id=tk1");

    await waitFor(() => expect(screen.getByLabelText(/Target price/i)).toBeInTheDocument());
    await user.type(screen.getByLabelText(/Target price/i), "20");
    await user.click(screen.getByRole("button", { name: /Add alert/i }));

    await waitFor(() => expect(screen.getByText("Active (1)")).toBeInTheDocument());
    expect(screen.getByText("JANE")).toBeInTheDocument();

    const stored = loadPriceAlerts();
    expect(stored).toHaveLength(1);
    expect(stored[0]!.subjectKind).toBe("token");
    expect(stored[0]!.subjectId).toBe("tk1");
    expect(stored[0]!.price).toBe(2000); // $20 -> 2000 cents
    expect(window.localStorage.getItem(PRICE_ALERTS_KEY)).toBeTruthy();
  });

  it("creating a Strategy NAV alert (via deep-link prefill) adds it to the active list", async () => {
    const user = userEvent.setup();
    renderPage("/markets/price-alerts?kind=strategy&id=st1");

    await waitFor(() => expect(screen.getByLabelText(/Target NAV/i)).toBeInTheDocument());
    await user.type(screen.getByLabelText(/Target NAV/i), "110");
    await user.click(screen.getByRole("button", { name: /Add alert/i }));

    await waitFor(() => expect(screen.getByText("Active (1)")).toBeInTheDocument());
    // The name shows in both the Select value and the alert row -> assert >=1 + a delete control.
    expect(screen.getAllByText("Blue Chip Basket").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole("button", { name: "Delete alert" })).toBeInTheDocument();

    const stored = loadPriceAlerts();
    expect(stored[0]!.subjectKind).toBe("strategy");
    expect(stored[0]!.subjectId).toBe("st1");
    expect(stored[0]!.field).toBe("nav");
    expect(stored[0]!.price).toBe(11000);
  });

  it("switching the Watch kind via the Select changes the target-field label", async () => {
    const user = userEvent.setup();
    renderPage(); // defaults to symbol
    expect(screen.getByLabelText(/Target price/i)).toBeInTheDocument();

    await selectOption(user, "Watch", /^Strategy$/);
    await waitFor(() => expect(screen.getByLabelText(/Target NAV/i)).toBeInTheDocument());
  });

  it("blocks submit with an invalid price and surfaces an inline error", async () => {
    const user = userEvent.setup();
    renderPage("/markets/price-alerts?kind=token&id=tk1");

    await waitFor(() => expect(screen.getByLabelText(/Target price/i)).toBeInTheDocument());
    // Leave the price empty -> validation error, no alert added.
    await user.click(screen.getByRole("button", { name: /Add alert/i }));
    expect(await screen.findByText(/Enter a valid price/i)).toBeInTheDocument();
    expect(loadPriceAlerts()).toHaveLength(0);
    expect(screen.getByText("Active (0)")).toBeInTheDocument();
  });
});
