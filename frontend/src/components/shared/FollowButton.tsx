import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { followUser, unfollowUser, getFollowStatus } from "@/api/endpoints/social";
import { cn } from "@/lib/utils";
import { Loader2 } from "lucide-react";

interface FollowButtonProps {
  targetUserId: string;
  isFollowing?: boolean;
  className?: string;
  size?: "sm" | "default" | "lg";
  onFollowChange?: (isFollowing: boolean) => void;
}

export function FollowButton({
  targetUserId,
  isFollowing: initialFollowing,
  className,
  size = "default",
  onFollowChange,
}: FollowButtonProps) {
  const [isHovered, setIsHovered] = useState(false);
  const queryClient = useQueryClient();

  const { data: status } = useQuery({
    queryKey: ["follow-status", targetUserId],
    queryFn: () => getFollowStatus(targetUserId),
    initialData:
      initialFollowing !== undefined
        ? { is_following: initialFollowing, is_followed_by: false, is_mutual: false }
        : undefined,
  });

  const following = status?.is_following ?? false;

  const invalidateAll = () => {
    queryClient.invalidateQueries({ queryKey: ["follow-status", targetUserId] });
    queryClient.invalidateQueries({ queryKey: ["follow-counts"] });
    queryClient.invalidateQueries({ queryKey: ["followers"] });
    queryClient.invalidateQueries({ queryKey: ["following"] });
  };

  const followMut = useMutation({
    mutationFn: () => followUser(targetUserId),
    onMutate: async () => {
      await queryClient.cancelQueries({ queryKey: ["follow-status", targetUserId] });
      queryClient.setQueryData(
        ["follow-status", targetUserId],
        (old: typeof status) => ({
          ...old,
          is_following: true,
          is_mutual: old?.is_followed_by ?? false,
        }),
      );
    },
    onSuccess: () => {
      onFollowChange?.(true);
    },
    onSettled: invalidateAll,
  });

  const unfollowMut = useMutation({
    mutationFn: () => unfollowUser(targetUserId),
    onMutate: async () => {
      await queryClient.cancelQueries({ queryKey: ["follow-status", targetUserId] });
      queryClient.setQueryData(
        ["follow-status", targetUserId],
        (old: typeof status) => ({
          ...old,
          is_following: false,
          is_mutual: false,
        }),
      );
    },
    onSuccess: () => {
      onFollowChange?.(false);
    },
    onSettled: invalidateAll,
  });

  const isPending = followMut.isPending || unfollowMut.isPending;

  const handleClick = () => {
    if (following) {
      unfollowMut.mutate();
    } else {
      followMut.mutate();
    }
  };

  const label = following ? (isHovered ? "Unfollow" : "Following") : "Follow";
  const variant = following
    ? isHovered
      ? "destructive"
      : "outline"
    : "default";

  return (
    <Button
      variant={variant as "default" | "outline" | "destructive"}
      size={size}
      className={cn("min-w-[100px]", className)}
      onClick={handleClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      disabled={isPending}
      aria-pressed={following}
      aria-label={following ? "Unfollow user" : "Follow user"}
    >
      {isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : label}
    </Button>
  );
}
