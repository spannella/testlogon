import { useInfiniteQuery } from "@tanstack/react-query";
import { getFeed } from "@/api/endpoints/newsfeed";
import { ApiError } from "@/api/client";
import type { FeedScopeParams } from "@/lib/feedQueryKeys";
import { feedQueryKeys } from "@/lib/feedQueryKeys";

type FeedRequestParams = {
  cursor?: string;
  author_id?: string;
  q?: string;
  from?: string;
  to?: string;
  has_media?: boolean;
};

const DATE_ONLY_RE = /^\d{4}-\d{2}-\d{2}$/;

function normalizeDateBound(value: string | undefined, bound: "from" | "to"): string | undefined {
  if (!value) return undefined;
  if (!DATE_ONLY_RE.test(value)) return value;
  return bound === "from" ? `${value}T00:00:00Z` : `${value}T23:59:59Z`;
}

export function buildFeedRequestParams(params: FeedScopeParams, pageParam?: string): FeedRequestParams {
  const from = normalizeDateBound(params.from, "from");
  const to = normalizeDateBound(params.to, "to");
  return {
    ...(pageParam ? { cursor: pageParam } : {}),
    ...(params.authorId ? { author_id: params.authorId } : {}),
    ...(params.q ? { q: params.q } : {}),
    ...(from ? { from } : {}),
    ...(to ? { to } : {}),
    ...(typeof params.hasMedia === "boolean" ? { has_media: params.hasMedia } : {}),
  };
}

export function isInvalidCursorError(error: unknown): boolean {
  if (!(error instanceof ApiError)) return false;
  const detail = (error.body as { detail?: unknown } | undefined)?.detail;
  if (!detail || typeof detail !== "object") return false;
  return (detail as { code?: unknown }).code === "invalid_cursor";
}

export function useFeedTimelineQuery(params: FeedScopeParams = {}) {
  return useInfiniteQuery({
    queryKey: feedQueryKeys.timeline(params),
    queryFn: async ({ pageParam }) => {
      const cursor = pageParam as string | undefined;
      const requestParams = buildFeedRequestParams(params, cursor);

      try {
        return await getFeed(requestParams);
      } catch (error) {
        if (cursor && params.cursor === cursor && isInvalidCursorError(error)) {
          return getFeed(buildFeedRequestParams(params, undefined));
        }
        throw error;
      }
    },
    initialPageParam: params.cursor as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
  });
}
