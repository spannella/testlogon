import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Lock, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { PostCard } from "@/pages/feed/PostCard";
import { getSyndicateFeed, deleteSyndicatePost } from "@/api/endpoints/syndicateFeed";
import type { FeedPost, SyndicatePost } from "@/api/types";

interface SyndicateFeedProps {
  syndicateId: string;
  syndicateName: string;
  isAdmin: boolean;
  currentUserId: string | null;
}

/** Map a syndicate post onto the FeedPost shape so PostCard can render it. */
function toFeedPost(p: SyndicatePost): FeedPost {
  return {
    post_id: p.post_id,
    author_id: p.author_id,
    body: p.text,
    body_plain: p.text,
    image_urls: p.image_url ? [p.image_url] : [],
    like_count: 0,
    comment_count: p.comment_count,
    tip_total_cents: p.tip_total_cents,
    reactions_counts: p.reaction_counts,
    created_at: new Date((p.created_at || 0) * 1000).toISOString(),
  } as FeedPost;
}

export function SyndicateFeed({
  syndicateId,
  syndicateName,
  isAdmin,
  currentUserId,
}: SyndicateFeedProps) {
  const qc = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["syndicate-feed", syndicateId],
    queryFn: () => getSyndicateFeed(syndicateId, { limit: 20 }),
  });

  const deleteMutation = useMutation({
    mutationFn: (postId: string) => deleteSyndicatePost(syndicateId, postId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["syndicate-feed", syndicateId] });
      qc.invalidateQueries({ queryKey: ["syndicate-profile", syndicateId] });
      toast.success("Post deleted");
    },
    onError: () => toast.error("Failed to delete post"),
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-32 w-full" />
      </div>
    );
  }

  const posts = data?.posts ?? [];

  if (posts.length === 0) {
    return (
      <Card className="p-8 text-center text-muted-foreground" data-testid="syndicate-feed-empty">
        No posts yet.
      </Card>
    );
  }

  return (
    <div className="space-y-4" data-testid="syndicate-feed">
      {posts.map((p) => {
        const canDelete = isAdmin || p.author_id === currentUserId;
        return (
          <div key={p.post_id} className="relative" data-testid={`syndicate-post-${p.post_id}`}>
            <div className="mb-1 flex items-center justify-between px-1">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span data-testid="syndicate-post-context">Posted in {syndicateName}</span>
                {p.visibility === "members_only" && (
                  <Badge variant="secondary" className="gap-1" data-testid="syndicate-members-only-badge">
                    <Lock className="h-3 w-3" />
                    Members Only
                  </Badge>
                )}
              </div>
              {canDelete && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => deleteMutation.mutate(p.post_id)}
                  disabled={deleteMutation.isPending}
                  data-testid="syndicate-post-delete"
                  aria-label="Delete post"
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              )}
            </div>
            <PostCard post={toFeedPost(p)} />
          </div>
        );
      })}
    </div>
  );
}

export default SyndicateFeed;
