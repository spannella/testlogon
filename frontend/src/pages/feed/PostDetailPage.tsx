import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { getPost } from "@/api/endpoints/newsfeed";
import { PostCard } from "./PostCard";

export default function PostDetailPage() {
  const { postId } = useParams<{ postId: string }>();
  const navigate = useNavigate();

  const { data: post, isLoading, error } = useQuery({
    queryKey: ["post", postId],
    queryFn: () => getPost(postId!),
    enabled: !!postId,
  });

  return (
    <div className="mx-auto max-w-xl px-4 py-6">
      <Button
        variant="ghost"
        size="sm"
        className="mb-4 -ml-2 gap-1.5"
        onClick={() => navigate(-1)}
      >
        <ArrowLeft className="h-4 w-4" />
        Back
      </Button>

      {isLoading && (
        <div className="space-y-3">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-32 w-full" />
        </div>
      )}

      {!isLoading && error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/5 p-6 text-center">
          <p className="text-sm font-medium text-destructive">
            {(error as { status?: number })?.status === 404
              ? "Post not found"
              : (error as { status?: number })?.status === 403
              ? "Subscription required to view this post"
              : "Failed to load post"}
          </p>
        </div>
      )}

      {post && <PostCard post={post} defaultShowComments />}
    </div>
  );
}
