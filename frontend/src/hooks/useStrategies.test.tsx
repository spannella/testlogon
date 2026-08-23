import type { ReactNode } from "react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import { ApiError } from "@/api/client";
import {
  useMyStrategies,
  useStrategyMarket,
  useStrategy,
  isPendingBackend,
} from "./useStrategies";

const getMyStrategies = vi.fn();
const getStrategyMarket = vi.fn();
const getStrategy = vi.fn();

vi.mock("@/api/endpoints/strategies", () => ({
  getMyStrategies: (...a: unknown[]) => getMyStrategies(...a),
  getStrategyMarket: (...a: unknown[]) => getStrategyMarket(...a),
  getStrategy: (...a: unknown[]) => getStrategy(...a),
  createStrategy: vi.fn(),
  updateStrategy: vi.fn(),
  publishStrategy: vi.fn(),
  getStrategyNav: vi.fn(),
  getStrategyHoldings: vi.fn(),
  investStrategy: vi.fn(),
  redeemStrategy: vi.fn(),
  getStrategyPosition: vi.fn(),
  getStrategyFees: vi.fn(),
}));

vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));

function wrapper(client: QueryClient) {
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
}
function newClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
}

describe("useStrategies data hooks", () => {
  beforeEach(() => {
    getMyStrategies.mockReset();
    getStrategyMarket.mockReset();
    getStrategy.mockReset();
  });

  it("useMyStrategies degrades on 404 (error, no throw)", async () => {
    getMyStrategies.mockRejectedValue(new ApiError(404, "Not found"));
    const { result } = renderHook(() => useMyStrategies(), { wrapper: wrapper(newClient()) });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.data).toBeUndefined();
    expect(isPendingBackend(result.current.error)).toBe(true);
  });

  it("useMyStrategies happy path returns the strategies", async () => {
    getMyStrategies.mockResolvedValue({ strategies: [{ strategy_id: "s1", name: "Blue Chip" }] });
    const { result } = renderHook(() => useMyStrategies(), { wrapper: wrapper(newClient()) });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.strategies?.[0]?.name).toBe("Blue Chip");
  });

  it("useStrategyMarket degrades on 404", async () => {
    getStrategyMarket.mockRejectedValue(new ApiError(404, "Not found"));
    const { result } = renderHook(() => useStrategyMarket(), { wrapper: wrapper(newClient()) });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.data).toBeUndefined();
  });

  it("useStrategy is idle without an id and fetches by id", async () => {
    const client = newClient();
    getStrategy.mockResolvedValue({ strategy_id: "s7", name: "Momentum" });

    const disabled = renderHook(() => useStrategy(undefined), { wrapper: wrapper(client) });
    expect(disabled.result.current.fetchStatus).toBe("idle");
    expect(getStrategy).not.toHaveBeenCalled();

    const enabled = renderHook(() => useStrategy("s7"), { wrapper: wrapper(client) });
    await waitFor(() => expect(enabled.result.current.isSuccess).toBe(true));
    expect(getStrategy).toHaveBeenCalledWith("s7");
    expect(enabled.result.current.data?.name).toBe("Momentum");
  });
});
