import { useInfiniteQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Sparkles, ImageIcon, Video, Type, Lock } from "lucide-react";
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
  const navigate = useNavigate();

  return (
    <div
      className="rounded-lg border bg-card overflow-hidden cursor-pointer hover:shadow-md transition-shadow group"
      data-testid="post-card"
      role="listitem"
      onClick={() => navigate(`/feed/${post.post_id}`)}
    >
      {/* Image thumbnail */}
      {post.image_urls.length > 0 && (
        <div className="relative aspect-square">
          <img
            src={post.image_urls[0]}
            alt="Post image"
            className="w-full h-full object-cover"
            loading="lazy"
          />
          {/* Hover overlay with stats */}
          <div className="absolute inset-0 bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center gap-4 text-white">
            {post.like_count > 0 && (
              <span className="flex items-center gap-1">
                <Heart className="h-4 w-4" /> {post.like_count}
              </span>
            )}
            {post.comment_count > 0 && (
              <span className="flex items-center gap-1">
                <MessageCircle className="h-4 w-4" /> {post.comment_count}
              </span>
            )}
          </div>
          {/* Lock badge */}
          {post.locked && (
            <div className="absolute top-2 right-2 bg-amber-500/90 text-white text-xs px-2 py-1 rounded flex items-center gap-1">
              <Lock className="h-3 w-3" />
              {post.unlock_price_cents ? `$${(post.unlock_price_cents / 100).toFixed(2)}` : "Locked"}
            </div>
          )}
        </div>
      )}

      {/* Video placeholder */}
      {!post.image_urls.length && post.has_video && (
        <div className="aspect-square bg-muted flex items-center justify-center">
          <Video className="h-8 w-8 text-muted-foreground" />
        </div>
      )}

      {/* Card body */}
      <div className="p-3 space-y-2">
        {post.locked && !post.image_urls.length && (
          <span className="inline-flex items-center gap-1 rounded bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800 dark:bg-amber-900/30 dark:text-amber-300">
            <Lock className="h-3 w-3" />
            Locked{post.unlock_price_cents ? ` - $${(post.unlock_price_cents / 100).toFixed(2)}` : ""}
          </span>
        )}

        {post.body_preview && (
          <p className="text-sm leading-relaxed line-clamp-3">{post.body_preview}</p>
        )}

        {/* Stats row for text-only posts (no hover overlay) */}
        {!post.image_urls.length && !post.has_video && (
          <div className="flex items-center gap-4 text-xs text-muted-foreground pt-1">
            {post.like_count > 0 && (
              <span className="flex items-center gap-1">
                <Heart className="h-3 w-3" />
                {post.like_count}
              </span>
            )}
            {post.comment_count > 0 && (
              <span className="flex items-center gap-1">
                <MessageCircle className="h-3 w-3" />
                {post.comment_count}
              </span>
            )}
          </div>
        )}
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

      {/* Posts grid */}
      {isLoading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="aspect-square w-full rounded-lg" />
          ))}
        </div>
      ) : allPosts.length === 0 ? (
        <div className="flex flex-col items-center gap-2 py-12 text-center text-muted-foreground" data-testid="posts-empty">
          <Sparkles className="h-8 w-8" />
          <p className="text-sm">No posts yet</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4" role="list" data-testid="posts-grid">
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
