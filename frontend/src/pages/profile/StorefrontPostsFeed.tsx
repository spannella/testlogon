import { useInfiniteQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Sparkles, ImageIcon, Video, Type } from "lucide-react";
import { Heart, MessageCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { getProfilePosts } from "@/api/endpoints/profile";
import type { ProfilePostItem } from "@/api/types";

type PostFilter = "all" | "text" | "image" | "video";

interface StorefrontPostsFeedProps {
  identifier: string;
}

function StorefrontPostCard({ post }: { post: ProfilePostItem }) {
  return (
    <div className="rounded-lg border bg-card p-4 space-y-2" data-testid="post-card">
      {post.locked && (
        <span className="inline-block rounded bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800 dark:bg-amber-900/30 dark:text-amber-300">
          Locked{post.unlock_price_cents ? ` - $${(post.unlock_price_cents / 100).toFixed(2)}` : ""}
        </span>
      )}

      {post.body_preview && (
        <p className="text-sm leading-relaxed line-clamp-4">{post.body_preview}</p>
      )}

      {post.image_urls.length > 0 && (
        <div className="overflow-hidden rounded-md">
          <img
            src={post.image_urls[0]}
            alt="Post image"
            className="w-full max-h-64 object-cover"
            loading="lazy"
          />
        </div>
      )}

      {post.has_video && (
        <div className="flex items-center gap-1 text-xs text-muted-foreground">
          <Video className="h-3 w-3" />
          <span>Video post</span>
        </div>
      )}

      <div className="flex items-center gap-4 text-xs text-muted-foreground pt-1">
        <span className="flex items-center gap-1">
          <Heart className="h-3 w-3" />
          {post.like_count}
        </span>
        <span className="flex items-center gap-1">
          <MessageCircle className="h-3 w-3" />
          {post.comment_count}
        </span>
      </div>
    </div>
  );
}

export function StorefrontPostsFeed({ identifier }: StorefrontPostsFeedProps) {
  const [filter, setFilter] = useState<PostFilter>("all");

  const {
    data,
    isLoading,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery({
    queryKey: ["profile-posts", identifier, filter],
    queryFn: ({ pageParam }) =>
      getProfilePosts(identifier, {
        limit: 12,
        cursor: pageParam,
        filter: filter === "all" ? undefined : filter,
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor || undefined,
    enabled: !!identifier,
    staleTime: 60_000,
  });

  const allPosts = data?.pages.flatMap((page) => page.items ?? []) ?? [];

  const filters: { value: PostFilter; label: string; icon: React.ReactNode }[] = [
    { value: "all", label: "All", icon: null },
    { value: "image", label: "Images", icon: <ImageIcon className="h-3 w-3" /> },
    { value: "video", label: "Videos", icon: <Video className="h-3 w-3" /> },
    { value: "text", label: "Text", icon: <Type className="h-3 w-3" /> },
  ];

  return (
    <div className="space-y-4">
      {/* Filter pills */}
      <div className="flex gap-2" data-testid="post-filter-pills">
        {filters.map((f) => (
          <button
            key={f.value}
            onClick={() => setFilter(f.value)}
            className={`flex items-center gap-1 rounded-full px-3 py-1 text-xs transition
              ${filter === f.value
                ? "bg-primary text-primary-foreground"
                : "bg-muted text-muted-foreground hover:bg-muted/80"
              }`}
            data-testid={`filter-${f.value}`}
            aria-pressed={filter === f.value}
          >
            {f.icon}
            {f.label}
          </button>
        ))}
      </div>

      {/* Posts list */}
      {isLoading ? (
        <div className="space-y-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-32 w-full rounded-lg" />
          ))}
        </div>
      ) : allPosts.length === 0 ? (
        <div className="flex flex-col items-center gap-2 py-12 text-center text-muted-foreground" data-testid="posts-empty">
          <Sparkles className="h-8 w-8" />
          <p className="text-sm">No posts yet</p>
        </div>
      ) : (
        <div className="space-y-3">
          {allPosts.map((post) => (
            <StorefrontPostCard key={post.post_id} post={post} />
          ))}
        </div>
      )}

      {/* Load more */}
      {hasNextPage && (
        <div className="flex justify-center pt-4">
          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchNextPage()}
            disabled={isFetchingNextPage}
            data-testid="load-more"
          >
            {isFetchingNextPage ? "Loading..." : "Load more"}
          </Button>
        </div>
      )}
    </div>
  );
}
