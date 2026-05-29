import { useInfiniteQuery } from "@tanstack/react-query";
import { Loader2, UserCheck } from "lucide-react";
import { getFollowing } from "@/api/endpoints/social";
import type { FollowUser, FollowListResponse } from "@/api/endpoints/social";
import { FollowButton } from "@/components/shared/FollowButton";
import { useAuthStore } from "@/stores/authStore";

interface FollowingTabProps {
  userId: string;
}

export function FollowingTab({ userId }: FollowingTabProps) {
  const viewerUserId = useAuthStore((s: { userId: string | null }) => s.userId);

  const {
    data,
    isLoading,
    isFetchingNextPage,
    hasNextPage,
    fetchNextPage,
  } = useInfiniteQuery({
    queryKey: ["following", userId],
    queryFn: ({ pageParam }: { pageParam: string | undefined }) =>
      getFollowing(userId, pageParam ? { cursor: pageParam, limit: "20" } : { limit: "20" }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage: FollowListResponse) => lastPage.next_cursor ?? undefined,
    staleTime: 30_000,
  });

  const allItems: FollowUser[] = data?.pages.flatMap((p: FollowListResponse) => p.items) ?? [];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (allItems.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-12 text-muted-foreground">
        <UserCheck className="h-10 w-10" />
        <p className="text-sm">Not following anyone yet</p>
      </div>
    );
  }

  return (
    <div className="space-y-2" role="list" data-testid="following-list">
      {allItems.map((user) => (
        <div
          key={user.user_id}
          role="listitem"
          className="flex items-center gap-3 rounded-lg border bg-card p-3"
        >
          {user.profile_photo_url ? (
            <img
              src={user.profile_photo_url}
              alt={user.display_name ?? user.user_id}
              className="h-10 w-10 rounded-full object-cover"
            />
          ) : (
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-muted text-sm font-semibold text-muted-foreground">
              {(user.display_name ?? user.user_id).slice(0, 1).toUpperCase()}
            </div>
          )}
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">{user.display_name ?? user.user_id}</p>
            {user.is_mutual && (
              <span
                className="inline-block rounded-full bg-primary/10 px-2 py-0.5 text-xs text-primary"
                aria-label="Mutual follower"
              >
                Mutual
              </span>
            )}
          </div>
          {viewerUserId && viewerUserId !== user.user_id && (
            <FollowButton targetUserId={user.user_id} isFollowing={user.is_following} size="sm" />
          )}
        </div>
      ))}
      {hasNextPage && (
        <button
          onClick={() => fetchNextPage()}
          disabled={isFetchingNextPage}
          className="mx-auto flex items-center gap-2 rounded-lg px-4 py-2 text-sm text-muted-foreground hover:text-foreground"
          data-testid="load-more-following"
        >
          {isFetchingNextPage ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            "Load more"
          )}
        </button>
      )}
    </div>
  );
}
