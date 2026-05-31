import { useEffect, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Clock, Eye, PlayCircle, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  getRentalAccess,
  startRental,
  issueRentalPlayback,
  completeRentalPlayback,
} from "@/api/endpoints/vodRental";

interface VodRentalAccessPanelProps {
  videoId: string;
  viewOncePriceCents?: number | null;
  rentalPriceCents?: number | null;
  rentalDurationHours?: number;
  paymentMethodId?: string;
}

function fmtMoney(cents?: number | null): string {
  if (cents == null) return "—";
  return `$${(cents / 100).toFixed(2)}`;
}

function fmtRemaining(seconds: number): string {
  if (seconds <= 0) return "0m";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

/**
 * VOD-019 per-video rental / view-once access panel.
 *
 * Shows the current access state (active rental countdown, view-once badge,
 * expired / consumed CTA) and lets the viewer start a rental or play a
 * gated playback URL.
 */
export default function VodRentalAccessPanel({
  videoId,
  viewOncePriceCents,
  rentalPriceCents,
  rentalDurationHours = 48,
  paymentMethodId,
}: VodRentalAccessPanelProps) {
  const qc = useQueryClient();
  const [playbackUrl, setPlaybackUrl] = useState<string | null>(null);

  const accessQuery = useQuery({
    queryKey: ["vod-rental-access", videoId],
    queryFn: () => getRentalAccess(videoId),
  });

  // Live countdown for active rentals.
  const [remaining, setRemaining] = useState<number>(0);
  useEffect(() => {
    const secs = accessQuery.data?.remaining_seconds ?? 0;
    setRemaining(secs);
    if (secs <= 0) return;
    const id = window.setInterval(() => {
      setRemaining((r) => Math.max(0, r - 1));
    }, 1000);
    return () => window.clearInterval(id);
  }, [accessQuery.data?.remaining_seconds]);

  const startMut = useMutation({
    mutationFn: (tier: "rental" | "view_once") =>
      startRental(videoId, {
        tier,
        payment_method_id: paymentMethodId,
        rental_duration_hours: tier === "rental" ? rentalDurationHours : undefined,
      }),
    onSuccess: () => {
      toast.success("Access granted");
      qc.invalidateQueries({ queryKey: ["vod-rental-access", videoId] });
      qc.invalidateQueries({ queryKey: ["vod-rentals"] });
    },
    onError: (e: unknown) => {
      toast.error(e instanceof Error ? e.message : "Failed to start rental");
    },
  });

  const playMut = useMutation({
    mutationFn: () => issueRentalPlayback(videoId),
    onSuccess: (res) => {
      setPlaybackUrl(res.playback_url);
      qc.invalidateQueries({ queryKey: ["vod-rental-access", videoId] });
    },
    onError: (e: unknown) => {
      toast.error(e instanceof Error ? e.message : "Playback unavailable");
    },
  });

  const completeMut = useMutation({
    mutationFn: () => completeRentalPlayback(videoId),
    onSuccess: () => {
      setPlaybackUrl(null);
      qc.invalidateQueries({ queryKey: ["vod-rental-access", videoId] });
    },
  });

  const access = accessQuery.data;
  const active = !!access?.active;
  const reason = access?.reason ?? "not_rented";

  return (
    <Card data-testid="vod-rental-panel">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Lock className="h-4 w-4" /> Rental Access
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {accessQuery.isLoading && (
          <p className="text-sm text-muted-foreground">Checking access…</p>
        )}

        {active && access?.tier === "rental" && (
          <div className="flex items-center gap-2" data-testid="vod-rental-active">
            <Badge variant="secondary" className="gap-1">
              <Clock className="h-3 w-3" />
              {reason === "pending" ? "Press play to start" : `Expires in ${fmtRemaining(remaining)}`}
            </Badge>
          </div>
        )}

        {active && access?.tier === "view_once" && (
          <div className="flex items-center gap-2" data-testid="vod-rental-viewonce">
            <Badge variant="secondary" className="gap-1">
              <Eye className="h-3 w-3" />
              {access.views_remaining} view remaining
            </Badge>
          </div>
        )}

        {!active && reason === "expired" && (
          <p className="text-sm text-destructive" data-testid="vod-rental-expired">
            Your rental has expired.
          </p>
        )}
        {!active && reason === "consumed" && (
          <p className="text-sm text-destructive" data-testid="vod-rental-consumed">
            This view-once rental has already been used.
          </p>
        )}

        {active ? (
          <div className="space-y-2">
            <Button
              onClick={() => playMut.mutate()}
              disabled={playMut.isPending}
              data-testid="vod-rental-play"
              className="gap-2"
            >
              <PlayCircle className="h-4 w-4" /> Play
            </Button>
            {playbackUrl && (
              <div className="space-y-2">
                <video
                  src={playbackUrl}
                  controls
                  className="w-full rounded-md"
                  data-testid="vod-rental-player"
                  onEnded={() => completeMut.mutate()}
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => completeMut.mutate()}
                  data-testid="vod-rental-finish"
                >
                  I'm done watching
                </Button>
              </div>
            )}
          </div>
        ) : (
          <div className="flex flex-wrap gap-2">
            {viewOncePriceCents != null && viewOncePriceCents > 0 && (
              <Button
                variant="outline"
                onClick={() => startMut.mutate("view_once")}
                disabled={startMut.isPending}
                data-testid="vod-rental-buy-viewonce"
              >
                Watch once — {fmtMoney(viewOncePriceCents)}
              </Button>
            )}
            {rentalPriceCents != null && rentalPriceCents > 0 && (
              <Button
                onClick={() => startMut.mutate("rental")}
                disabled={startMut.isPending}
                data-testid="vod-rental-buy-rental"
              >
                Rent {rentalDurationHours}h — {fmtMoney(rentalPriceCents)}
              </Button>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
