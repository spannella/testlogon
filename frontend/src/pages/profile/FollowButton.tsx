import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { UserPlus, UserCheck, UserMinus } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { followUser, unfollowUser } from "@/api/endpoints/social";

interface FollowButtonProps {
  userId: string;
  isFollowing: boolean;
  onToggle?: () => void;
}

export function FollowButton({ userId, isFollowing: initialFollowing, onToggle }: FollowButtonProps) {
  const [isFollowing, setIsFollowing] = useState(initialFollowing);
  const [isHovered, setIsHovered] = useState(false);

  const followMut = useMutation({
    mutationFn: () => followUser(userId),
    onMutate: () => {
      setIsFollowing(true);
    },
    onSuccess: () => {
      toast.success("Following");
      onToggle?.();
    },
    onError: () => {
      setIsFollowing(false);
      toast.error("Unable to follow right now");
    },
  });

  const unfollowMut = useMutation({
    mutationFn: () => unfollowUser(userId),
    onMutate: () => {
      setIsFollowing(false);
    },
    onSuccess: () => {
      toast.success("Unfollowed");
      onToggle?.();
    },
    onError: () => {
      setIsFollowing(true);
      toast.error("Unable to unfollow right now");
    },
  });

  const isPending = followMut.isPending || unfollowMut.isPending;

  if (isFollowing) {
    return (
      <Button
        variant={isHovered ? "destructive" : "secondary"}
        size="sm"
        disabled={isPending}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        onClick={() => unfollowMut.mutate()}
        data-testid="follow-button"
      >
        {isHovered ? (
          <>
            <UserMinus className="mr-1 h-4 w-4" />
            Unfollow
          </>
        ) : (
          <>
            <UserCheck className="mr-1 h-4 w-4" />
            Following
          </>
        )}
      </Button>
    );
  }

  return (
    <Button
      variant="default"
      size="sm"
      disabled={isPending}
      onClick={() => followMut.mutate()}
      data-testid="follow-button"
    >
      <UserPlus className="mr-1 h-4 w-4" />
      Follow
    </Button>
  );
}
