import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  createCreative,
  uploadCreativeAsset,
  submitCreativeForReview,
} from "@/api/endpoints/ads";
import type { AdCreative } from "@/api/types";

interface CreativeEditorProps {
  campaignId: string;
  creative?: AdCreative;
  onSaved: (creative: AdCreative) => void;
}

export default function CreativeEditor({ campaignId, creative, onSaved }: CreativeEditorProps) {
  const queryClient = useQueryClient();
  const [format, setFormat] = useState<string>(creative?.format ?? "image");
  const [title, setTitle] = useState(creative?.title ?? "");
  const [headline, setHeadline] = useState(creative?.headline ?? "");
  const [bodyText, setBodyText] = useState(creative?.body_text ?? "");
  const [ctaText, setCtaText] = useState(creative?.cta_text ?? "");
  const [ctaUrl, setCtaUrl] = useState(creative?.cta_url ?? "");
  const [altText, setAltText] = useState(creative?.alt_text ?? "");
  const [width, setWidth] = useState<string>(creative?.width?.toString() ?? "");
  const [height, setHeight] = useState<string>(creative?.height?.toString() ?? "");
  const [durationSeconds, setDurationSeconds] = useState<string>(
    creative?.duration_seconds?.toString() ?? ""
  );
  const [skipAfterSeconds, setSkipAfterSeconds] = useState<string>(
    creative?.skip_after_seconds?.toString() ?? "5"
  );
  const [rotationWeight, setRotationWeight] = useState(creative?.rotation_weight ?? 50);
  const [imageFile, setImageFile] = useState<File | null>(null);

  const createMut = useMutation({
    mutationFn: async () => {
      const data: Record<string, unknown> = {
        format,
        title,
        rotation_weight: rotationWeight,
      };
      if (format === "image" || format === "video") {
        if (altText) data.alt_text = altText;
        if (width) data.width = parseInt(width, 10);
        if (height) data.height = parseInt(height, 10);
      }
      if (format === "video") {
        if (durationSeconds) data.duration_seconds = parseInt(durationSeconds, 10);
        data.skip_after_seconds = parseInt(skipAfterSeconds, 10);
      }
      if (format === "native_post") {
        if (headline) data.headline = headline;
        if (bodyText) data.body_text = bodyText;
        if (ctaText) data.cta_text = ctaText;
        if (ctaUrl) data.cta_url = ctaUrl;
      }
      const cr = await createCreative(campaignId, data as Parameters<typeof createCreative>[1]);

      if (imageFile && cr.creative_id) {
        const assetType = format === "video" ? "video" : "image";
        await uploadCreativeAsset(campaignId, cr.creative_id, imageFile, assetType);
      }
      return cr;
    },
    onSuccess: (cr) => {
      queryClient.invalidateQueries({ queryKey: ["ad-creatives", campaignId] });
      onSaved(cr);
    },
  });

  const submitMut = useMutation({
    mutationFn: (creativeId: string) => submitCreativeForReview(campaignId, creativeId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ad-creatives", campaignId] });
    },
  });

  return (
    <div data-testid="creative-editor" className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>{creative ? "Edit Creative" : "Create Creative"}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Format selector */}
          <div>
            <Label>Format</Label>
            <Select value={format} onValueChange={setFormat}>
              <SelectTrigger>
                <SelectValue placeholder="Select format" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="image">Image</SelectItem>
                <SelectItem value="video">Video</SelectItem>
                <SelectItem value="native_post">Native Post</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Title */}
          <div>
            <Label htmlFor="creative-title">Title</Label>
            <Input
              id="creative-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Creative title"
              maxLength={200}
            />
          </div>

          {/* Image fields */}
          {format === "image" && (
            <div className="space-y-4">
              <div>
                <Label htmlFor="creative-alt">Alt Text</Label>
                <Input
                  id="creative-alt"
                  value={altText}
                  onChange={(e) => setAltText(e.target.value)}
                  placeholder="Descriptive alt text"
                  maxLength={200}
                />
              </div>
              <div className="flex gap-4">
                <div className="flex-1">
                  <Label htmlFor="creative-width">Width</Label>
                  <Input
                    id="creative-width"
                    type="number"
                    value={width}
                    onChange={(e) => setWidth(e.target.value)}
                    placeholder="1200"
                    min={100}
                    max={4096}
                  />
                </div>
                <div className="flex-1">
                  <Label htmlFor="creative-height">Height</Label>
                  <Input
                    id="creative-height"
                    type="number"
                    value={height}
                    onChange={(e) => setHeight(e.target.value)}
                    placeholder="628"
                    min={100}
                    max={4096}
                  />
                </div>
              </div>
              <div>
                <Label htmlFor="creative-image-file">Upload Image</Label>
                <Input
                  id="creative-image-file"
                  type="file"
                  accept=".jpg,.jpeg,.png,.webp"
                  onChange={(e) => setImageFile(e.target.files?.[0] ?? null)}
                />
              </div>
            </div>
          )}

          {/* Video fields */}
          {format === "video" && (
            <div className="space-y-4">
              <div>
                <Label htmlFor="creative-duration">Duration (seconds)</Label>
                <Input
                  id="creative-duration"
                  type="number"
                  value={durationSeconds}
                  onChange={(e) => setDurationSeconds(e.target.value)}
                  placeholder="15"
                  min={5}
                  max={60}
                />
              </div>
              <div>
                <Label>Skip After (seconds)</Label>
                <Select value={skipAfterSeconds} onValueChange={setSkipAfterSeconds}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="0">Non-skippable</SelectItem>
                    <SelectItem value="5">5 seconds</SelectItem>
                    <SelectItem value="15">15 seconds</SelectItem>
                    <SelectItem value="30">30 seconds</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label htmlFor="creative-video-file">Upload Video</Label>
                <Input
                  id="creative-video-file"
                  type="file"
                  accept=".mp4"
                  onChange={(e) => setImageFile(e.target.files?.[0] ?? null)}
                />
              </div>
            </div>
          )}

          {/* Native post fields */}
          {format === "native_post" && (
            <div className="space-y-4">
              <div>
                <Label htmlFor="creative-headline">Headline</Label>
                <Input
                  id="creative-headline"
                  value={headline}
                  onChange={(e) => setHeadline(e.target.value)}
                  placeholder="Headline text"
                  maxLength={100}
                />
              </div>
              <div>
                <Label htmlFor="creative-body">Body Text</Label>
                <Textarea
                  id="creative-body"
                  value={bodyText}
                  onChange={(e) => setBodyText(e.target.value)}
                  placeholder="Ad body text"
                  maxLength={300}
                />
              </div>
              <div>
                <Label htmlFor="creative-cta-text">CTA Text</Label>
                <Input
                  id="creative-cta-text"
                  value={ctaText}
                  onChange={(e) => setCtaText(e.target.value)}
                  placeholder="Shop Now"
                  maxLength={25}
                />
              </div>
              <div>
                <Label htmlFor="creative-cta-url">CTA URL</Label>
                <Input
                  id="creative-cta-url"
                  value={ctaUrl}
                  onChange={(e) => setCtaUrl(e.target.value)}
                  placeholder="https://example.com"
                />
              </div>
            </div>
          )}

          {/* Rotation weight */}
          <div>
            <Label htmlFor="creative-weight">Rotation Weight (0-100)</Label>
            <Input
              id="creative-weight"
              type="number"
              value={rotationWeight}
              onChange={(e) => setRotationWeight(Math.min(100, Math.max(0, parseInt(e.target.value, 10) || 0)))}
              min={0}
              max={100}
            />
          </div>
        </CardContent>
      </Card>

      <div className="flex gap-2">
        <Button
          onClick={() => createMut.mutate()}
          disabled={!title || createMut.isPending}
        >
          {createMut.isPending ? "Saving..." : "Save Draft"}
        </Button>
        {creative && creative.status === "draft" && (
          <Button
            variant="secondary"
            onClick={() => submitMut.mutate(creative.creative_id)}
            disabled={submitMut.isPending}
          >
            {submitMut.isPending ? "Submitting..." : "Submit for Review"}
          </Button>
        )}
      </div>
    </div>
  );
}
