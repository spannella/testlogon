// FE-161 (EPIC G): generic sponsored-slot card for list/discovery surfaces.
//
// Adapted from feed/SponsoredPostCard.tsx (same IntersectionObserver impression
// beacon + click-through idiom + "Sponsored"/sponsor-label badge + Why/Hide
// overflow), but driven by an AdServeResponse (serveAd) instead of a FeedPost
// and additionally reports structured events via trackAdEvent (POST
// /ui/ads/track) so market/catalog slots reconcile in ad analytics.

import { useState, useEffect, useRef, useCallback } from "react";
import type { Ref } from "react";
import { useMutation } from "@tanstack/react-query";
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
import { submitAdFeedback, trackAdEvent } from "@/api/endpoints/ads";
import { WhyThisAdDialog } from "@/pages/feed/WhyThisAdDialog";
import type { AdServeResponse } from "@/api/types";

interface SponsoredSlotCardProps {
  ad: AdServeResponse;
  /** Surface + slot for tracking (e.g. "token_discovery" / "sponsored_post"). */
  surface: string;
  slotType: string;
  /** Optional layout variant: "row" (table) vs "card" (grid). Default "card". */
  variant?: "card" | "row";
  /** Column span for the row variant (table cell). */
  colSpan?: number;
  onHide?: (creativeId: string) => void;
}

/** Fire a best-effort beacon to a server-provided tracking URL. */
function fireBeacon(url: string | null | undefined) {
  if (!url) return;
  fetch(url, { method: "POST", credentials: "include" }).catch(() => {});
}

export function SponsoredSlotCard({
  ad,
  surface,
  slotType,
  variant = "card",
  colSpan = 1,
  onHide,
}: SponsoredSlotCardProps) {
  const [hidden, setHidden] = useState(false);
  const [whyDialogOpen, setWhyDialogOpen] = useState(false);
  const impressionFired = useRef(false);
  const rootRef = useRef<HTMLDivElement>(null);

  const creativeId = ad.creative_id ?? "";
  const campaignId = ad.campaign_id ?? "";

  // Impression: fires once on first >=50% visibility. Beacon + structured track.
  useEffect(() => {
    if (impressionFired.current) return;
    const el = rootRef.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting && !impressionFired.current) {
          impressionFired.current = true;
          fireBeacon(ad.impression_url);
          if (creativeId) {
            trackAdEvent({
              event: "impression",
              creative_id: creativeId,
              campaign_id: campaignId,
              account_id: ad.account_id ?? "",
              surface,
              slot_type: slotType,
              content_id: creativeId,
              creator_id: ad.creator_id ?? "",
            }).catch(() => {});
          }
        }
      },
      { threshold: 0.5 },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [ad.impression_url, ad.account_id, ad.creator_id, campaignId, creativeId, surface, slotType]);

  const hideMut = useMutation({
    mutationFn: () =>
      submitAdFeedback({
        creative_id: creativeId,
        campaign_id: campaignId || undefined,
        feedback_type: "hide",
      }),
    onSuccess: () => {
      setHidden(true);
      onHide?.(creativeId);
      toast.success("Ad hidden");
    },
  });

  const handleCtaClick = useCallback(() => {
    fireBeacon(ad.click_url);
    if (creativeId) {
      trackAdEvent({
        event: "click",
        creative_id: creativeId,
        campaign_id: campaignId,
        account_id: ad.account_id ?? "",
        surface,
        slot_type: slotType,
        content_id: creativeId,
        creator_id: ad.creator_id ?? "",
      }).catch(() => {});
    }
    if (ad.cta_url) {
      window.open(ad.cta_url, "_blank", "noopener,noreferrer");
    }
  }, [ad.click_url, ad.cta_url, ad.account_id, ad.creator_id, campaignId, creativeId, surface, slotType]);

  if (hidden) return null;

  const label = (
    <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
      <Tag className="h-3.5 w-3.5" />
      <span className="font-medium">Sponsored</span>
      {ad.sponsor_label && (
        <>
          <span className="mx-0.5">&middot;</span>
          <span>{ad.sponsor_label}</span>
        </>
      )}
    </div>
  );

  const overflow = (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" className="h-7 w-7" data-testid="sponsored-slot-overflow">
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => hideMut.mutate()}>Hide this ad</DropdownMenuItem>
        <DropdownMenuItem onClick={() => setWhyDialogOpen(true)}>Why this ad?</DropdownMenuItem>
        <DropdownMenuItem onClick={() => toast.info("Report submitted")}>Report ad</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );

  const why = (
    <WhyThisAdDialog
      creativeId={creativeId}
      open={whyDialogOpen}
      onClose={() => setWhyDialogOpen(false)}
    />
  );

  // Row variant: a single full-width table row that matches the market table.
  if (variant === "row") {
    return (
      <tr data-testid="sponsored-slot" ref={rootRef as unknown as Ref<HTMLTableRowElement>}>
        <td colSpan={colSpan} className="p-0">
          <div
            className="flex cursor-pointer items-center gap-3 border-l-2 border-primary/40 bg-muted/40 px-3 py-2.5 hover:bg-muted/60"
            onClick={handleCtaClick}
          >
            {ad.image_url && (
              <img
                src={ad.image_url}
                alt={ad.alt_text || ad.headline || "Sponsored"}
                className="h-9 w-9 shrink-0 rounded object-cover"
              />
            )}
            <div className="min-w-0 flex-1">
              {label}
              <div className="truncate text-sm font-medium">
                {ad.headline || ad.title || "Sponsored"}
              </div>
              {ad.body_text && (
                <div className="truncate text-xs text-muted-foreground">{ad.body_text}</div>
              )}
            </div>
            {ad.cta_text && (
              <Badge variant="secondary" className="shrink-0 text-xs">
                {ad.cta_text}
                <ExternalLink className="ml-1 h-3 w-3" />
              </Badge>
            )}
            <div onClick={(e) => e.stopPropagation()}>{overflow}</div>
          </div>
          {why}
        </td>
      </tr>
    );
  }

  // Card variant: matches the catalog product grid card footprint.
  return (
    <>
      <Card
        ref={rootRef}
        data-testid="sponsored-slot"
        className="cursor-pointer overflow-hidden border-primary/30 transition-shadow hover:shadow-md"
        onClick={handleCtaClick}
      >
        <CardContent className="p-0">
          <div className="relative flex h-36 items-center justify-center rounded-t-xl bg-muted">
            {ad.image_url ? (
              <img
                src={ad.image_url}
                alt={ad.alt_text || ad.headline || "Sponsored"}
                className="h-full w-full rounded-t-xl object-cover"
              />
            ) : (
              <Tag className="h-8 w-8 text-muted-foreground/50" />
            )}
            <div className="absolute right-1 top-1" onClick={(e) => e.stopPropagation()}>
              {overflow}
            </div>
          </div>
          <div className="space-y-1 p-3">
            {label}
            <h4 className="line-clamp-2 text-sm font-medium leading-tight">
              {ad.headline || ad.title || "Sponsored"}
            </h4>
            {ad.body_text && (
              <p className="line-clamp-2 text-xs text-muted-foreground">{ad.body_text}</p>
            )}
            {ad.cta_text && (
              <Badge variant="secondary" className="mt-1 text-xs" data-testid="sponsored-slot-cta">
                {ad.cta_text}
                <ExternalLink className="ml-1 h-3 w-3" />
              </Badge>
            )}
          </div>
        </CardContent>
      </Card>
      {why}
    </>
  );
}
