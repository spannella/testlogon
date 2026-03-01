import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";

import {
  useDevtoolsBillingLedger,
  useDevtoolsBillingSummary,
  useDevtoolsEmailMessages,
  useDevtoolsSmsConversations,
} from "@/hooks/useDevtoolsData";

const getDevtoolsEmailMessages = vi.fn();
const getDevtoolsSmsConversations = vi.fn();
const getDevtoolsBillingLedger = vi.fn();
const getDevtoolsBillingSummary = vi.fn();

vi.mock("@/api/endpoints/devtools", () => ({
  getDevtoolsEmailMessages: (...args: unknown[]) => getDevtoolsEmailMessages(...args),
  getDevtoolsSmsConversations: (...args: unknown[]) => getDevtoolsSmsConversations(...args),
  getDevtoolsBillingLedger: (...args: unknown[]) => getDevtoolsBillingLedger(...args),
  getDevtoolsBillingSummary: (...args: unknown[]) => getDevtoolsBillingSummary(...args),
}));

function wrapper(client: QueryClient) {
  return ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("useDevtoolsData", () => {
  beforeEach(() => {
    getDevtoolsEmailMessages.mockReset();
    getDevtoolsSmsConversations.mockReset();
    getDevtoolsBillingLedger.mockReset();
    getDevtoolsBillingSummary.mockReset();
  });

  it("uses collision-safe cache keys per filter set", async () => {
    getDevtoolsEmailMessages.mockResolvedValue({ mailboxes: [], threads: [], messages: [], parse_warnings: [] });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const first = renderHook(() => useDevtoolsEmailMessages({ mailbox: "a@example.com", state: "all", limit: 10 }, true), { wrapper: wrapper(client) });
    await waitFor(() => expect(first.result.current.isSuccess).toBe(true));

    const second = renderHook(() => useDevtoolsEmailMessages({ mailbox: "b@example.com", state: "all", limit: 10 }, true), { wrapper: wrapper(client) });
    await waitFor(() => expect(second.result.current.isSuccess).toBe(true));

    const queries = client.getQueryCache().findAll({ queryKey: ["devtools", "email"] });
    const keys = queries.map((q) => q.queryKey.join("|"));
    expect(keys.some((k) => k.includes("|a@example.com|"))).toBe(true);
    expect(keys.some((k) => k.includes("|b@example.com|"))).toBe(true);
  });

  it("passes cursor for infinite paging and exposes empty state", async () => {
    getDevtoolsSmsConversations
      .mockResolvedValueOnce({ conversations: [], messages: [], next_cursor: "next-1", parse_warnings: [] })
      .mockResolvedValueOnce({ conversations: [], messages: [], parse_warnings: [] });

    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { result } = renderHook(() => useDevtoolsSmsConversations({ participant: "+14155550123", limit: 5 }, true), {
      wrapper: wrapper(client),
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.isEmpty).toBe(true);
    await result.current.fetchNextPage();

    expect(getDevtoolsSmsConversations).toHaveBeenNthCalledWith(1, expect.objectContaining({ cursor: undefined, limit: 5 }));
    expect(getDevtoolsSmsConversations).toHaveBeenNthCalledWith(2, expect.objectContaining({ cursor: "next-1", limit: 5 }));
  });

  it("provides actionable error text and separate billing cache keys", async () => {
    getDevtoolsBillingLedger
      .mockRejectedValueOnce(new Error("ledger exploded"))
      .mockResolvedValue({ entries: [], summary: { gross_inflow: 0, fees: 0, net_total_balance: 0, transaction_count: 0, provider_counts: {}, status_counts: {}, parse_warnings: [] }, parse_warnings: [] });
    getDevtoolsBillingSummary.mockResolvedValue({ gross_inflow: 0, fees: 0, net_total_balance: 0, transaction_count: 0, provider_counts: {}, status_counts: {}, parse_warnings: [] });

    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const bad = renderHook(() => useDevtoolsBillingLedger({ provider: "stripe", status: "failed", limit: 10 }, true), {
      wrapper: wrapper(client),
    });
    await waitFor(() => expect(bad.result.current.isError).toBe(true));
    expect(bad.result.current.errorMessage).toContain("ledger exploded");

    const good = renderHook(() => useDevtoolsBillingLedger({ provider: "stripe", status: "completed", limit: 10 }, true), {
      wrapper: wrapper(client),
    });
    await waitFor(() => expect(good.result.current.isSuccess).toBe(true));

    const summary = renderHook(() => useDevtoolsBillingSummary({ provider: "stripe", status: "completed" }, true), {
      wrapper: wrapper(client),
    });
    await waitFor(() => expect(summary.result.current.isSuccess).toBe(true));

    const ledgerQueries = client.getQueryCache().findAll({ queryKey: ["devtools", "billing", "ledger", "stripe"] });
    expect(ledgerQueries.length).toBeGreaterThanOrEqual(2);
    const summaryQueries = client.getQueryCache().findAll({ queryKey: ["devtools", "billing", "summary", "stripe", "completed"] });
    expect(summaryQueries.length).toBe(1);
  });
});
