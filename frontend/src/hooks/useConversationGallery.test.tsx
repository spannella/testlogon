import type { ReactNode } from "react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import { useConversationGallery } from "./useConversationGallery";

const getConversationGallery = vi.fn();
vi.mock("@/api/endpoints/messaging", () => ({
  getConversationGallery: (...args: unknown[]) => getConversationGallery(...args),
}));

function wrapper(client: QueryClient) {
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
}

describe("useConversationGallery", () => {
  beforeEach(() => {
    getConversationGallery.mockReset();
  });

  it("uses cache keys scoped by conversation + type", async () => {
    getConversationGallery.mockResolvedValue({ items: [] });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    const first = renderHook(() => useConversationGallery("c1", "image", true), { wrapper: wrapper(client) });
    await waitFor(() => expect(first.result.current.isSuccess).toBe(true));

    const second = renderHook(() => useConversationGallery("c1", "video", true), { wrapper: wrapper(client) });
    await waitFor(() => expect(second.result.current.isSuccess).toBe(true));

    const galleryQueries = client.getQueryCache().findAll({ queryKey: ["conversation-gallery", "c1"] });
    const keys = galleryQueries.map((q) => q.queryKey.join("|"));

    expect(keys.some((k) => k.includes("|image|"))).toBe(true);
    expect(keys.some((k) => k.includes("|video|"))).toBe(true);
  });

  it("passes next_cursor as cursor when fetching next page", async () => {
    getConversationGallery
      .mockResolvedValueOnce({ items: [{ message_id: "m1" }], next_cursor: "next-1" })
      .mockResolvedValueOnce({ items: [{ message_id: "m0" }] });

    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { result } = renderHook(() => useConversationGallery("c1", "image", true), { wrapper: wrapper(client) });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    await result.current.fetchNextPage();

    expect(getConversationGallery).toHaveBeenNthCalledWith(1, "c1", expect.objectContaining({ type: "image", cursor: undefined }));
    expect(getConversationGallery).toHaveBeenNthCalledWith(2, "c1", expect.objectContaining({ type: "image", cursor: "next-1" }));
  });
});
