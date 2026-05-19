export interface FeedScopeParams {
  authorId?: string;
  q?: string;
  from?: string;
  to?: string;
  hasMedia?: boolean;
  cursor?: string;
}

export const feedQueryKeys = {
  all: ["feed"] as const,
  timeline: (params: FeedScopeParams = {}) =>
    [
      "feed",
      "timeline",
      {
        authorId: params.authorId ?? "",
        q: params.q ?? "",
        from: params.from ?? "",
        to: params.to ?? "",
        hasMedia: typeof params.hasMedia === "boolean" ? String(params.hasMedia) : "",
        cursor: params.cursor ?? "",
      },
    ] as const,
};
