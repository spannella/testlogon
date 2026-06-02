import { useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Helmet } from "react-helmet-async";
import { Eye, Share2, Clock, Scissors, Radio } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import {
  getPublicClip,
  recordPublicClipView,
  recordPublicClipShare,
} from "@/api/endpoints/clips";

function formatRelativeTime(ts: number): string {
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

/**
 * Public shareable clip page (ENGAGE-005 §4.5). No auth required.
 * Renders the embedded player placeholder, broadcaster attribution, share
 * button, and Open Graph / Twitter Card meta tags for social previews.
 */
export default function PublicClipPage() {
  const { clipId } = useParams<{ clipId: string }>();

  const clipQuery = useQuery({
    queryKey: ["public-clip", clipId],
    queryFn: () => getPublicClip(clipId!),
    enabled: !!clipId,
    retry: false,
  });

  // Record a view on mount (fire-and-forget).
  useEffect(() => {
    if (clipId) {
      recordPublicClipView(clipId).catch(() => {});
    }
  }, [clipId]);

  const shareMut = useMutation({
    mutationFn: () => recordPublicClipShare(clipId!),
    onSuccess: (data) => {
      const url = `${window.location.origin}${data.share_url}`;
      navigator.clipboard
        .writeText(url)
        .then(() => toast.success("Clip link copied to clipboard!"))
        .catch(() => toast.success("Clip shared!"));
    },
  });

  const clip = clipQuery.data;

  if (clipQuery.isLoading) {
    return (
      <div className="container mx-auto p-6 max-w-3xl">
        <p className="text-muted-foreground">Loading clip...</p>
      </div>
    );
  }

  if (!clip) {
    return (
      <div className="container mx-auto p-6 max-w-3xl" data-testid="clip-not-found">
        <p className="text-destructive">Clip not found.</p>
      </div>
    );
  }

  const ogDescription = `Clip from ${clip.broadcaster_display_name || "broadcast"}`;

  return (
    <div className="container mx-auto p-6 max-w-3xl">
      <Helmet>
        <title>{clip.title} · Clip</title>
        <meta property="og:title" content={clip.title} />
        <meta property="og:description" content={ogDescription} />
        <meta property="og:type" content="video.other" />
        <meta property="og:image" content={clip.thumbnail_url || ""} />
        <meta name="twitter:card" content="player" />
        <meta name="twitter:title" content={clip.title} />
      </Helmet>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Scissors className="h-5 w-5" />
            {clip.title}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="aspect-video bg-muted rounded-lg flex items-center justify-center mb-4">
            {clip.thumbnail_url ? (
              <img
                src={clip.thumbnail_url}
                alt={clip.title}
                className="w-full h-full object-cover rounded-lg"
              />
            ) : (
              <div className="text-muted-foreground">
                {clip.status === "processing"
                  ? "Clip is processing..."
                  : "Video player placeholder"}
              </div>
            )}
          </div>

          <div className="flex flex-col gap-3">
            {/* Attribution: link back to the original broadcaster */}
            <div
              className="flex items-center gap-2 text-sm"
              data-testid="clip-attribution"
            >
              <Radio className="h-4 w-4 text-primary" />
              <span>
                Clipped from{" "}
                <span className="font-medium">
                  {clip.broadcaster_display_name || "a broadcast"}
                </span>
                {clip.profile_id && (
                  <>
                    {" · "}
                    <Link
                      to={`/live/${clip.session_id}`}
                      className="text-primary underline"
                    >
                      View broadcast
                    </Link>
                  </>
                )}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                Created by {clip.creator_display_name} · {clip.duration_seconds.toFixed(1)}s
              </p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => shareMut.mutate()}
                disabled={shareMut.isPending}
              >
                <Share2 className="h-4 w-4 mr-1" />
                Share
              </Button>
            </div>

            <div className="flex items-center gap-4 text-sm text-muted-foreground">
              <span className="flex items-center gap-1">
                <Eye className="h-4 w-4" /> {clip.view_count} views
              </span>
              <span className="flex items-center gap-1">
                <Share2 className="h-4 w-4" /> {clip.share_count} shares
              </span>
              <span className="flex items-center gap-1">
                <Clock className="h-4 w-4" /> {formatRelativeTime(clip.created_at)}
              </span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
