import type { FeedPost } from "@/api/types";

export interface FeedPage {
  items: FeedPost[];
  next_cursor?: string;
}

export function mergeFeedPages(pages: FeedPage[]): FeedPost[] {
  const seen = new Set<string>();
  const out: FeedPost[] = [];
  for (const page of pages) {
    for (const post of page.items ?? []) {
      if (!post?.post_id || seen.has(post.post_id)) continue;
      seen.add(post.post_id);
      out.push(post);
    }
  }
  return out;
}
