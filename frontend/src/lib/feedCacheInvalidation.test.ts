import { describe, expect, it, vi } from "vitest";
import type { QueryClient } from "@tanstack/react-query";
import { feedQueryKeys } from "./feedQueryKeys";
import { invalidateFeedCaches } from "./feedCacheInvalidation";

describe("invalidateFeedCaches", () => {
  it("invalidates all feed queries", async () => {
    const invalidateQueries = vi.fn(async () => undefined);
    const queryClient = { invalidateQueries } as unknown as QueryClient;

    await invalidateFeedCaches(queryClient);

    expect(invalidateQueries).toHaveBeenCalledTimes(1);
    expect(invalidateQueries).toHaveBeenCalledWith({ queryKey: feedQueryKeys.all });
  });

  it("also invalidates the author timeline when authorId is provided", async () => {
    const invalidateQueries = vi.fn(async () => undefined);
    const queryClient = { invalidateQueries } as unknown as QueryClient;

    await invalidateFeedCaches(queryClient, "user-123");

    expect(invalidateQueries).toHaveBeenCalledTimes(2);
    expect(invalidateQueries).toHaveBeenNthCalledWith(1, { queryKey: feedQueryKeys.all });
    expect(invalidateQueries).toHaveBeenNthCalledWith(2, {
      queryKey: feedQueryKeys.timeline({ authorId: "user-123" }),
      exact: false,
    });
  });
});
