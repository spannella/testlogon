import { useInfiniteQuery } from "@tanstack/react-query";
import { getForYouFeed } from "@/api/endpoints/newsfeed";

/**
 * NRS-011: Infinite query for the ranked "For You" newsfeed (`GET /feed/for-you`).
 * Cached under a distinct query key (`["feed", "for-you"]`) so the For You tab
 * caches independently from the chronological timeline. The backend returns the
 * same `{ items, next_cursor }` shape as the chronological feed plus a `source`
 * field; we expose the first page's `source` to drive the cold-start / fallback
 * hint in the UI.
 */
export function useForYouFeedQuery(limit = 20) {
  return useInfiniteQuery({
    queryKey: ["feed", "for-you", { limit }] as const,
    queryFn: ({ pageParam }) =>
      getForYouFeed({ cursor: pageParam as string | undefined, limit }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
  });
}
