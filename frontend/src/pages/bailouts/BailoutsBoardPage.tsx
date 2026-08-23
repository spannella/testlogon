import SurfaceIntro from "@/components/onboarding/SurfaceIntro";
import { useMemo, useState } from "react";
import { LifeBuoy, RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/shared/PageHeader";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useAuthStore } from "@/stores/authStore";
import { useBailoutBoard } from "@/hooks/useBailouts";
import type { BailoutAuction } from "@/api/endpoints/bailouts";
import { formatBps, formatCents, bufferBps } from "@/lib/bailout";
import { BailoutPendingBackend } from "@/pages/bailouts/BailoutShared";
import { BailoutAuctionPanel } from "@/pages/bailouts/BailoutAuctionPanel";

/**
 * BAILOUTS DISCOVERY BOARD (`/bailouts`) — the rescuer opportunity board,
 * sibling to the liquidations feed. Lists every open pre-emptive bailout auction
 * (symbol, capital needed, current implied share, buffer left, distance-to-liq)
 * so a rescuer can inject capital for a position-share before the position is
 * forced-liquidated. Degrades to an honest "pending backend" state on 404.
 */
export default function BailoutsBoardPage() {
  const userId = useAuthStore((s) => s.userId);
  const boardQ = useBailoutBoard();
  const [active, setActive] = useState<BailoutAuction | null>(null);

  const auctions = boardQ.data?.auctions ?? [];
  const open = useMemo(() => auctions.filter((a) => a.status === "open"), [auctions]);

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <SurfaceIntro surfaceId="bailouts" />

      <PageHeader
        title="Bailouts"
        description="Rescue distressed but still-solvent margin positions — inject capital for a position-share before a forced liquidation."
        actions={
          <Button variant="outline" size="sm" onClick={() => boardQ.refetch()} disabled={boardQ.isFetching}>
            <RefreshCw className={boardQ.isFetching ? "mr-2 h-4 w-4 animate-spin" : "mr-2 h-4 w-4"} />
            Refresh
          </Button>
        }
      />

      {boardQ.isLoading ? (
        <div className="space-y-3">
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-20 w-full" />
        </div>
      ) : boardQ.isError ? (
        <BailoutPendingBackend label="The bailout opportunity board" />
      ) : open.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-2 p-10 text-center">
            <LifeBuoy className="h-8 w-8 text-muted-foreground" />
            <p className="text-sm font-medium">No open bailout auctions</p>
            <p className="max-w-md text-sm text-muted-foreground">
              When a trader's position enters the distress band and they open a bailout, it appears
              here for you to rescue. Nothing is fabricated — this reflects the server feed.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {open.map((a) => (
            <BoardRow
              key={a.auction_id}
              a={a}
              isOwner={!!userId && a.owner_sub === userId}
              onOpen={() => setActive(a)}
            />
          ))}
        </div>
      )}

      <Dialog open={!!active} onOpenChange={(o) => !o && setActive(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <LifeBuoy className="h-4 w-4 text-primary" /> Bailout auction
            </DialogTitle>
          </DialogHeader>
          {active && (
            <BailoutAuctionPanel
              auction={active}
              isOwner={!!userId && active.owner_sub === userId}
              symbolId={active.symbol_id}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function BoardRow({
  a,
  isOwner,
  onOpen,
}: {
  a: BailoutAuction;
  isOwner: boolean;
  onOpen: () => void;
}) {
  const raised = (a.rescuers ?? []).reduce((s, r) => s + (r.capital_cents ?? 0), 0);
  const fundedPct = a.capital_needed_cents > 0
    ? Math.min(100, Math.round((raised / a.capital_needed_cents) * 100))
    : 0;
  // Distance-to-liq from marks (server buffer authoritative; recompute for display).
  const buffer = bufferBps(a.mark_price, a.liq_price);

  return (
    <Card>
      <CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0 space-y-1">
          <div className="flex items-center gap-2">
            <span className="font-semibold">Symbol #{a.symbol_id}</span>
            <Badge variant="outline" className="uppercase">{a.side}</Badge>
            {isOwner && <Badge variant="secondary">Your position</Badge>}
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs tabular-nums text-muted-foreground">
            <span>Needed <span className="font-medium text-foreground">{formatCents(a.capital_needed_cents)}</span></span>
            <span>Raised <span className="font-medium text-foreground">{formatCents(raised)} ({fundedPct}%)</span></span>
            <span>Max share <span className="font-medium text-foreground">{formatBps(a.max_share_bps)}</span></span>
            <span>Buffer to liq <span className="font-medium text-foreground">{formatBps(buffer)}</span></span>
            <span>Mark {formatCents(a.mark_price)} · Liq {formatCents(a.liq_price)}</span>
          </div>
        </div>
        <Button size="sm" onClick={onOpen} data-testid={`board-open-${a.auction_id}`}>
          <LifeBuoy className="mr-1.5 h-3.5 w-3.5" /> {isOwner ? "Manage" : "Bail out"}
        </Button>
      </CardContent>
    </Card>
  );
}
