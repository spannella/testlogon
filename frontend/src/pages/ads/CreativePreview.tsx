import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import type { AdCreative } from "@/api/types";

interface CreativePreviewProps {
  creative: AdCreative;
  surface?: "banner" | "video" | "feed";
}

export default function CreativePreview({ creative, surface }: CreativePreviewProps) {
  const effectiveSurface =
    surface ??
    (creative.format === "video" ? "video" : creative.format === "native_post" ? "feed" : "banner");

  return (
    <div data-testid="creative-preview" className="space-y-2">
      {effectiveSurface === "banner" && creative.image_url && (
        <div className="overflow-hidden rounded-lg border">
          <img
            src={creative.image_url}
            alt={creative.alt_text ?? creative.title}
            className="w-full object-contain"
            style={{
              maxHeight: 400,
              aspectRatio:
                creative.width && creative.height
                  ? `${creative.width}/${creative.height}`
                  : undefined,
            }}
          />
        </div>
      )}

      {effectiveSurface === "video" && creative.video_url && (
        <div className="overflow-hidden rounded-lg border">
          <video
            src={creative.video_url}
            poster={creative.thumbnail_url ?? undefined}
            controls
            className="w-full"
            style={{ maxHeight: 400 }}
          />
          {(creative.skip_after_seconds ?? 0) > 0 && (
            <p className="text-xs text-muted-foreground p-2">
              Skippable after {creative.skip_after_seconds}s
            </p>
          )}
        </div>
      )}

      {effectiveSurface === "feed" && (
        <Card className="border-l-4 border-l-blue-500">
          <CardContent className="py-4 space-y-2">
            <Badge variant="secondary" className="text-xs">Sponsored</Badge>
            {creative.headline && (
              <h3 className="font-semibold text-lg">{creative.headline}</h3>
            )}
            {creative.body_text && (
              <p className="text-sm text-muted-foreground">{creative.body_text}</p>
            )}
            {creative.image_url && (
              <img
                src={creative.image_url}
                alt={creative.alt_text ?? creative.title}
                className="rounded-md w-full object-cover"
                style={{ maxHeight: 300 }}
              />
            )}
            {creative.cta_text && creative.cta_url && (
              <a
                href={creative.cta_url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-block mt-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90"
              >
                {creative.cta_text}
              </a>
            )}
          </CardContent>
        </Card>
      )}

      {/* Fallback: show metadata if no asset uploaded yet */}
      {effectiveSurface === "banner" && !creative.image_url && (
        <div className="rounded-lg border border-dashed p-8 text-center text-muted-foreground">
          No image uploaded yet
        </div>
      )}
      {effectiveSurface === "video" && !creative.video_url && (
        <div className="rounded-lg border border-dashed p-8 text-center text-muted-foreground">
          No video uploaded yet
        </div>
      )}
    </div>
  );
}
