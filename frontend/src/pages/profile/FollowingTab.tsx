import { useState } from "react";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { BellOff, Loader2, UserCheck } from "lucide-react";
import { toast } from "sonner";
import {
  getFollowing,
  snoozeFollowing,
  unsnoozeFollowing,
} from "@/api/endpoints/social";
import type { FollowUser, FollowListResponse } from "@/api/endpoints/social";
import { FollowButton } from "@/components/shared/FollowButton";
import { SnoozeDurationPicker } from "@/components/shared/SnoozeDurationPicker";
import { Button } from "@/components/ui/button";
import { useAuthStore } from "@/stores/authStore";

interface FollowingTabProps {
  userId: string;
}

function snoozeUntilLabel(ts: number): string {
  try {
    return new Date(ts * 1000).toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
    });
  } catch {
    return "";
  }
}

export function FollowingTab({ userId }: FollowingTabProps) {
  const viewerUserId = useAuthStore((s: { userId: string | null }) => s.userId);
  const queryClient = useQueryClient();
  const [pickerFor, setPickerFor] = useState<FollowUser | null>(null);
  const isOwnList = viewerUserId === userId;

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

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["following", userId] });
    queryClient.invalidateQueries({ queryKey: ["social", "snoozed"] });
    queryClient.invalidateQueries({ queryKey: ["feed"] });
  };

  const snoozeMut = useMutation({
    mutationFn: ({ id, days }: { id: string; days: number }) => snoozeFollowing(id, days),
    onSuccess: () => {
      toast.success("User snoozed");
      setPickerFor(null);
      invalidate();
    },
    onError: () => toast.error("Failed to snooze"),
  });

  const unsnoozeMut = useMutation({
    mutationFn: (id: string) => unsnoozeFollowing(id),
    onSuccess: () => {
      toast.success("User unsnoozed");
      invalidate();
    },
    onError: () => toast.error("Failed to unsnooze"),
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
          data-testid={`following-row-${user.user_id}`}
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
            <div className="flex items-center gap-2">
              {user.is_mutual && (
                <span
                  className="inline-block rounded-full bg-primary/10 px-2 py-0.5 text-xs text-primary"
                  aria-label="Mutual follower"
                >
                  Mutual
                </span>
              )}
              {user.is_snoozed && user.snoozed_until && (
                <span
                  data-testid={`snooze-badge-${user.user_id}`}
                  className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2 py-0.5 text-xs text-amber-600"
                >
                  <BellOff className="h-3 w-3" />
                  Snoozed until {snoozeUntilLabel(user.snoozed_until)}
                </span>
              )}
            </div>
          </div>
          {isOwnList && viewerUserId !== user.user_id && (
            user.is_snoozed ? (
              <Button
                size="sm"
                variant="outline"
                data-testid={`unsnooze-btn-${user.user_id}`}
                disabled={unsnoozeMut.isPending}
                onClick={() => unsnoozeMut.mutate(user.user_id)}
              >
                Unsnooze
              </Button>
            ) : (
              <Button
                size="sm"
                variant="outline"
                data-testid={`snooze-btn-${user.user_id}`}
                onClick={() => setPickerFor(user)}
              >
                <BellOff className="mr-1 h-3.5 w-3.5" />
                Snooze
              </Button>
            )
          )}
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

      {pickerFor && (
        <SnoozeDurationPicker
          userId={pickerFor.user_id}
          userName={pickerFor.display_name ?? pickerFor.user_id}
          open={!!pickerFor}
          onClose={() => setPickerFor(null)}
          isPending={snoozeMut.isPending}
          onSnooze={(days) => snoozeMut.mutate({ id: pickerFor.user_id, days })}
        />
      )}
    </div>
  );
}
