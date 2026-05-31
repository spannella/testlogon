import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Video, Clock, Eye, CheckCircle2 } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { listRentals } from "@/api/endpoints/vodRental";
import type { VodRentalStatus } from "@/api/types";

function fmtRemaining(seconds: number): string {
  if (seconds <= 0) return "0m";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function StatusBadge({ r }: { r: VodRentalStatus }) {
  if (r.active && r.tier === "rental") {
    return (
      <Badge variant="secondary" className="gap-1">
        <Clock className="h-3 w-3" />
        {r.started ? `Expires in ${fmtRemaining(r.remaining_seconds)}` : "Ready to play"}
      </Badge>
    );
  }
  if (r.active && r.tier === "view_once") {
    return (
      <Badge variant="secondary" className="gap-1">
        <Eye className="h-3 w-3" />
        {r.views_remaining} view left
      </Badge>
    );
  }
  if (r.reason === "expired") {
    return <Badge variant="destructive">Expired</Badge>;
  }
  if (r.reason === "consumed") {
    return (
      <Badge variant="outline" className="gap-1">
        <CheckCircle2 className="h-3 w-3" /> Watched
      </Badge>
    );
  }
  return <Badge variant="outline">{r.reason}</Badge>;
}

/**
 * VOD-019 "My Rentals" page — lists the viewer's rental + view-once grants
 * with live status (active countdown, view-once badge, expired / consumed).
 */
export default function VodRentalsPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["vod-rentals"],
    queryFn: () => listRentals(100),
  });

  const items = data?.items ?? [];

  return (
    <div className="space-y-6" data-testid="vod-rentals-page">
      <div>
        <h1 className="text-2xl font-semibold flex items-center gap-2">
          <Video className="h-6 w-6" /> My Rentals
        </h1>
        <p className="text-sm text-muted-foreground">
          Time-limited rentals and view-once purchases.
        </p>
      </div>

      {isLoading && (
        <div className="space-y-3">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-16 w-full" />
          ))}
        </div>
      )}

      {!isLoading && items.length === 0 && (
        <EmptyState
          icon={<Video className="h-10 w-10" />}
          title="No rentals yet"
          description="Rent a video to watch it within a limited window or once."
        />
      )}

      {!isLoading && items.length > 0 && (
        <div className="space-y-3">
          {items.map((r) => (
            <Card key={r.rental_id || r.video_id} data-testid="vod-rental-item">
              <CardContent className="flex items-center justify-between gap-4 py-4">
                <div className="min-w-0">
                  <Link
                    to={`/videos/${r.video_id}`}
                    className="font-medium hover:underline truncate block"
                  >
                    {r.video_id}
                  </Link>
                  <p className="text-xs text-muted-foreground capitalize">
                    {r.tier.replace("_", " ")} · ${(r.amount_cents / 100).toFixed(2)}
                  </p>
                </div>
                <StatusBadge r={r} />
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
