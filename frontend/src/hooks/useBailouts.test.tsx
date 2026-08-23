import type { ReactNode } from "react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import { ApiError } from "@/api/client";
import {
  useDistress,
  useBailoutBoard,
  usePositionBailout,
  isPendingBackend,
} from "./useBailouts";

const getDistress = vi.fn();
const getBailouts = vi.fn();
const getPositionBailout = vi.fn();

vi.mock("@/api/endpoints/bailouts", () => ({
  getDistress: (...a: unknown[]) => getDistress(...a),
  getBailouts: (...a: unknown[]) => getBailouts(...a),
  getPositionBailout: (...a: unknown[]) => getPositionBailout(...a),
  getBailoutPrefs: vi.fn(),
  openBailout: vi.fn(),
  placeRescueBid: vi.fn(),
  clearBailout: vi.fn(),
  putBailoutPrefs: vi.fn(),
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

describe("useBailouts data hooks", () => {
  beforeEach(() => {
    getDistress.mockReset();
    getBailouts.mockReset();
    getPositionBailout.mockReset();
  });

  it("useDistress degrades on 404 without throwing (never fabricates distress)", async () => {
    getDistress.mockRejectedValue(new ApiError(404, "Not found"));
    const { result } = renderHook(() => useDistress(), { wrapper: wrapper(newClient()) });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.data).toBeUndefined();
    expect(isPendingBackend(result.current.error)).toBe(true);
  });

  it("useDistress happy path returns the server-computed distress read", async () => {
    getDistress.mockResolvedValue({ positions: [{ symbol_id: 1, in_band: true }] });
    const { result } = renderHook(() => useDistress(), { wrapper: wrapper(newClient()) });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.positions).toHaveLength(1);
  });

  it("useBailoutBoard degrades on 404", async () => {
    getBailouts.mockRejectedValue(new ApiError(404, "Not found"));
    const { result } = renderHook(() => useBailoutBoard(), { wrapper: wrapper(newClient()) });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.data).toBeUndefined();
  });

  it("usePositionBailout is idle for a nullish symbol and fetches for a finite one", async () => {
    const client = newClient();
    getPositionBailout.mockResolvedValue({ auction_id: "a1", status: "open" });

    const disabled = renderHook(() => usePositionBailout(undefined), { wrapper: wrapper(client) });
    expect(disabled.result.current.fetchStatus).toBe("idle");
    expect(getPositionBailout).not.toHaveBeenCalled();

    const enabled = renderHook(() => usePositionBailout(42), { wrapper: wrapper(client) });
    await waitFor(() => expect(enabled.result.current.isSuccess).toBe(true));
    expect(getPositionBailout).toHaveBeenCalledWith(42);
    expect(enabled.result.current.data?.auction_id).toBe("a1");
  });
});
