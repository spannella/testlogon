import { useState, useEffect, useRef, useCallback } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Tag, MoreHorizontal, ExternalLink } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { submitAdFeedback } from "@/api/endpoints/ads";
import { WhyThisAdDialog } from "./WhyThisAdDialog";
import type { FeedPost } from "@/api/types";

interface SponsoredPostCardProps {
  post: FeedPost;
  onHide?: (creativeId: string) => void;
}

export function SponsoredPostCard({ post, onHide }: SponsoredPostCardProps) {
  const queryClient = useQueryClient();
  const [hidden, setHidden] = useState(false);
  const [whyDialogOpen, setWhyDialogOpen] = useState(false);
  const impressionFired = useRef(false);
  const cardRef = useRef<HTMLDivElement>(null);

  // Impression tracking via IntersectionObserver
  useEffect(() => {
    if (!post.impression_url || impressionFired.current) return;
    const el = cardRef.current;
    if (!el) return;

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting && !impressionFired.current) {
          impressionFired.current = true;
          // Fire impression beacon (best-effort)
          fetch(post.impression_url!, { method: "POST", credentials: "include" }).catch(() => {});
        }
      },
      { threshold: 0.5 },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [post.impression_url]);

  const hideMut = useMutation({
    mutationFn: () =>
      submitAdFeedback({
        creative_id: post.creative_id!,
        campaign_id: post.campaign_id,
        feedback_type: "hide",
      }),
    onSuccess: () => {
      setHidden(true);
      onHide?.(post.creative_id!);
      queryClient.invalidateQueries({ queryKey: ["feed"] });
      toast.success("Ad hidden");
    },
  });

  const handleCtaClick = useCallback(() => {
    // Fire click tracking beacon
    if (post.click_url) {
      fetch(post.click_url, { method: "POST", credentials: "include" }).catch(() => {});
    }
    // Navigate to CTA URL
    if (post.cta_url) {
      window.open(post.cta_url, "_blank", "noopener,noreferrer");
    }
  }, [post.click_url, post.cta_url]);

  if (hidden) return null;

  return (
    <>
      <Card ref={cardRef} data-testid="sponsored-post" className="overflow-hidden">
        <CardContent className="p-4 space-y-3">
          {/* Sponsored badge + sponsor label */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
              <Tag className="h-3.5 w-3.5" />
              <span className="font-medium">Sponsored</span>
              {post.sponsor_label && (
                <>
                  <span className="mx-0.5">&middot;</span>
                  <span>{post.sponsor_label}</span>
                </>
              )}
            </div>

            {/* Overflow menu */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="h-8 w-8" data-testid="sponsored-overflow">
                  <MoreHorizontal className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => hideMut.mutate()}>
                  Hide this ad
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setWhyDialogOpen(true)}>
                  Why this ad?
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => toast.info("Report submitted")}>
                  Report ad
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>

          {/* Image */}
          {post.image_urls && post.image_urls.length > 0 && (
            <div className="rounded-lg overflow-hidden">
              <img
                src={post.image_urls[0]}
                alt={post.headline || "Sponsored content"}
                className="w-full object-cover max-h-64"
              />
            </div>
          )}

          {/* Headline */}
          {post.headline && (
            <h3 className="text-lg font-semibold leading-tight">{post.headline}</h3>
          )}

          {/* Body */}
          {post.body && (
            <p className="text-sm text-muted-foreground">{post.body}</p>
          )}

          {/* CTA Button */}
          {post.cta_text && (
            <Button
              onClick={handleCtaClick}
              className="w-full"
              data-testid="sponsored-cta"
            >
              {post.cta_text}
              <ExternalLink className="ml-2 h-4 w-4" />
            </Button>
          )}

          {/* Reactions - same as regular posts but simplified */}
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Badge variant="secondary" className="text-xs">Ad</Badge>
          </div>
        </CardContent>
      </Card>

      {/* Why this ad dialog */}
      <WhyThisAdDialog
        creativeId={post.creative_id || ""}
        open={whyDialogOpen}
        onClose={() => setWhyDialogOpen(false)}
      />
    </>
  );
}
