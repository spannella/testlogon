import { useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation } from "@tanstack/react-query";
import { getClip, recordClipView, recordClipShare } from "@/api/endpoints/clips";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Eye, Share2, Clock, ArrowLeft, Scissors } from "lucide-react";
import { toast } from "sonner";

export default function ClipPlayerPage() {
  const { clipId } = useParams<{ clipId: string }>();

  const clipQuery = useQuery({
    queryKey: ["clip", clipId],
    queryFn: () => getClip(clipId!),
    enabled: !!clipId,
  });

  // Record view on mount
  useEffect(() => {
    if (clipId) {
      recordClipView(clipId).catch(() => {});
    }
  }, [clipId]);

  const shareMut = useMutation({
    mutationFn: () => recordClipShare(clipId!),
    onSuccess: (data) => {
      const url = `${window.location.origin}${data.share_url}`;
      navigator.clipboard.writeText(url).then(() => {
        toast.success("Clip link copied to clipboard!");
      }).catch(() => {
        toast.success("Clip shared!");
      });
    },
  });

  const clip = clipQuery.data;

  if (clipQuery.isLoading) {
    return (
      <div className="container mx-auto p-6 max-w-4xl">
        <p className="text-muted-foreground">Loading clip...</p>
      </div>
    );
  }

  if (!clip) {
    return (
      <div className="container mx-auto p-6 max-w-4xl">
        <p className="text-destructive">Clip not found.</p>
        <Link to="/clips" className="text-primary underline mt-2 inline-block">
          Back to Gallery
        </Link>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 max-w-4xl">
      <Link to="/clips" className="flex items-center gap-1 text-sm text-muted-foreground hover:text-primary mb-4">
        <ArrowLeft className="h-4 w-4" /> Back to Gallery
      </Link>

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
              <img src={clip.thumbnail_url} alt={clip.title} className="w-full h-full object-cover rounded-lg" />
            ) : (
              <div className="text-muted-foreground">
                {clip.status === "processing" ? "Clip is processing..." : "Video player placeholder"}
              </div>
            )}
          </div>

          <div className="flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">Created by {clip.creator_display_name}</p>
                <p className="text-xs text-muted-foreground">
                  Duration: {clip.duration_seconds.toFixed(1)}s | Status: {clip.status}
                </p>
              </div>
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

function formatRelativeTime(ts: number): string {
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
