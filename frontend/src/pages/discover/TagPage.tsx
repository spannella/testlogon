import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Hash, Loader2 } from "lucide-react";
import { getPostsByTag } from "@/api/endpoints/discovery";
import { PostCard } from "@/pages/feed/PostCard";

export default function TagPage() {
  const { tag } = useParams<{ tag: string }>();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["discover", "tags", tag],
    queryFn: () => getPostsByTag(tag!, 50),
    enabled: !!tag,
    staleTime: 120_000,
  });

  const posts = data?.posts ?? [];

  return (
    <div className="container max-w-3xl py-6 space-y-6">
      <div className="flex items-center gap-2">
        <Hash className="h-6 w-6" />
        <h1 className="text-2xl font-bold">#{tag}</h1>
      </div>

      <p className="text-muted-foreground">
        {isLoading ? "Loading..." : `${posts.length} post${posts.length !== 1 ? "s" : ""}`}
      </p>

      {isLoading && (
        <div className="flex justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      )}

      {isError && (
        <p className="text-sm text-destructive">Failed to load tagged posts.</p>
      )}

      {!isLoading && posts.length === 0 && (
        <div className="flex flex-col items-center gap-2 py-12 text-muted-foreground">
          <Hash className="h-10 w-10" />
          <p className="text-sm">No posts tagged #{tag} yet</p>
        </div>
      )}

      {posts.map((post) => (
        <PostCard key={post.post_id} post={post} />
      ))}
    </div>
  );
}
