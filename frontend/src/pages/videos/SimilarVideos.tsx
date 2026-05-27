import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { Link } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getSimilarVideos } from "@/api/endpoints/recommendations";

interface Props {
  videoId: string;
}

export default function SimilarVideos({ videoId }: Props) {
  const q = useQuery({
    queryKey: ["recommendations", "similar", videoId],
    queryFn: () => getSimilarVideos(videoId, 8),
    enabled: !!videoId,
    staleTime: 10 * 60_000,
  });

  const videos = q.data?.videos ?? [];

  if (q.isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Similar Videos</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (videos.length === 0) {
    return null;
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Similar Videos</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 md:grid-cols-4">
          {videos.map((v) => (
            <Link
              key={v.video_id}
              to={`/gallery/${v.video_id}`}
              className="group block"
            >
              <div className="relative aspect-video rounded-md bg-muted overflow-hidden">
                {v.thumbnail_url ? (
                  <img
                    src={v.thumbnail_url}
                    alt={v.title}
                    className="h-full w-full object-cover"
                  />
                ) : (
                  <div className="flex h-full w-full items-center justify-center text-xs text-muted-foreground">
                    No thumbnail
                  </div>
                )}
              </div>
              <p className="mt-1 text-sm font-medium line-clamp-2 group-hover:text-primary transition-colors">
                {v.title}
              </p>
              <p className="text-xs text-muted-foreground">{v.creator_name}</p>
            </Link>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
