import type { ReactNode } from "react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import { ApiError } from "@/api/client";
import { useMyTokens, useTokenMarket, useToken, isPendingBackend } from "./useTokens";

const getMyTokens = vi.fn();
const getTokenMarket = vi.fn();
const getToken = vi.fn();

vi.mock("@/api/endpoints/tokens", () => ({
  getMyTokens: (...a: unknown[]) => getMyTokens(...a),
  getTokenMarket: (...a: unknown[]) => getTokenMarket(...a),
  getToken: (...a: unknown[]) => getToken(...a),
  // Other endpoints referenced by the hook module (mutations) — never called here.
  mintToken: vi.fn(),
  listToken: vi.fn(),
  getCapTable: vi.fn(),
  getAuction: vi.fn(),
  placeAuctionBid: vi.fn(),
  clearAuction: vi.fn(),
  getRevenue: vi.fn(),
  claimRevenue: vi.fn(),
  getUpkeep: vi.fn(),
  payUpkeep: vi.fn(),
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

describe("useTokens data hooks", () => {
  beforeEach(() => {
    getMyTokens.mockReset();
    getTokenMarket.mockReset();
    getToken.mockReset();
  });

  it("useMyTokens degrades on 404 (error, no throw, empty data)", async () => {
    getMyTokens.mockRejectedValue(new ApiError(404, "Not found"));
    const { result } = renderHook(() => useMyTokens(), { wrapper: wrapper(newClient()) });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.data).toBeUndefined();
    expect(isPendingBackend(result.current.error)).toBe(true);
  });

  it("useMyTokens happy path returns the fetched tokens", async () => {
    getMyTokens.mockResolvedValue({ tokens: [{ token_id: "t1", ticker: "JANE" }] });
    const { result } = renderHook(() => useMyTokens(), { wrapper: wrapper(newClient()) });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.tokens).toHaveLength(1);
    expect(result.current.data?.tokens?.[0]?.ticker).toBe("JANE");
  });

  it("useTokenMarket degrades on 404", async () => {
    getTokenMarket.mockRejectedValue(new ApiError(404, "Not found"));
    const { result } = renderHook(() => useTokenMarket(), { wrapper: wrapper(newClient()) });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.data).toBeUndefined();
  });

  it("useToken is disabled when id is undefined and enabled+fetches with an id", async () => {
    const client = newClient();
    getToken.mockResolvedValue({ token_id: "t9", ticker: "ACME" });

    const disabled = renderHook(() => useToken(undefined), { wrapper: wrapper(client) });
    expect(disabled.result.current.fetchStatus).toBe("idle");
    expect(getToken).not.toHaveBeenCalled();

    const enabled = renderHook(() => useToken("t9"), { wrapper: wrapper(client) });
    await waitFor(() => expect(enabled.result.current.isSuccess).toBe(true));
    expect(getToken).toHaveBeenCalledWith("t9");
    expect(enabled.result.current.data?.ticker).toBe("ACME");
  });
});
