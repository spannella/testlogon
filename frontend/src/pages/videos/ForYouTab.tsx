import { useQuery } from "@tanstack/react-query";
import { Loader2, Sparkles } from "lucide-react";
import { getForYou } from "@/api/endpoints/recommendations";
import type { RecommendedVideo } from "@/api/endpoints/recommendations";
import GalleryVideoCard from "@/pages/gallery/GalleryVideoCard";
import type { GalleryVideoItem } from "@/api/endpoints/gallery";

function toGalleryItem(v: RecommendedVideo): GalleryVideoItem {
  return {
    video_id: v.video_id,
    title: v.title,
    description: v.description,
    thumbnail_url: v.thumbnail_url,
    duration_seconds: v.duration_seconds,
    category: v.category,
    tags: [],
    view_count: v.view_count,
    like_count: v.like_count,
    comment_count: 0,
    owner_user_id: v.creator_id,
    created_at: v.created_at,
  };
}

export default function ForYouTab() {
  const q = useQuery({
    queryKey: ["recommendations", "for-you"],
    queryFn: () => getForYou({ limit: 24 }),
    staleTime: 5 * 60_000,
  });

  const videos = q.data?.videos ?? [];
  const source = q.data?.source ?? "for_you";

  if (q.isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (videos.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
        <Sparkles className="h-8 w-8 mb-2" />
        <p className="text-lg font-medium">No recommendations yet</p>
        <p className="text-sm">
          Watch some videos and we will start suggesting content for you.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {source === "trending_fallback" && (
        <p className="text-sm text-muted-foreground">
          Showing trending videos. Watch more to get personalized recommendations.
        </p>
      )}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4">
        {videos.map((v) => (
          <GalleryVideoCard key={v.video_id} video={toGalleryItem(v)} />
        ))}
      </div>
    </div>
  );
}
