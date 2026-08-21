import { useMemo, useState } from "react";
import { toast } from "sonner";
import { AlertTriangle, LifeBuoy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { BailoutAuction } from "@/api/endpoints/bailouts";
import { usePlaceRescueBid, useClearBailout } from "@/hooks/useBailouts";
import {
  formatBps,
  formatCents,
  bailoutClearing,
  indicativeShareBps,
  type RescueBid,
} from "@/lib/bailout";

/** Dollars string -> integer cents (rounded). */
function dollarsToCents(v: string): number {
  const n = Number(v);
  return Number.isFinite(n) ? Math.round(n * 100) : 0;
}

function shortSub(sub: string): string {
  return sub.length > 12 ? `${sub.slice(0, 6)}...${sub.slice(-4)}` : sub;
}

const STATUS_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  open: "default",
  cleared: "secondary",
  cancelled: "outline",
  liquidated: "destructive",
};

/**
 * The bailout-auction panel: capital-needed target, the rescuer bid book, a
 * rescue-bid form (capital -> position-share) behind a money-safety confirm, an
 * indicative clearing share preview, a live "if the mark hits {liq_price} first
 * this cancels -> liquidation" warning, and (owner) a Clear button. A variant of
 * the token AuctionSection adapted to the position-share rescue mechanic.
 */
export function BailoutAuctionPanel({
  auction,
  isOwner,
  symbolId,
}: {
  auction: BailoutAuction;
  isOwner: boolean;
  symbolId?: number;
}) {
  const bid = usePlaceRescueBid(auction.auction_id);
  const clear = useClearBailout(auction.auction_id, symbolId);

  const [capital, setCapital] = useState("");
  const [sharePct, setSharePct] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);

  const rescuers = auction.rescuers ?? [];
  const isOpen = auction.status === "open";

  const capitalCents = dollarsToCents(capital);
  const shareBpsWanted = Math.round(Number(sharePct) * 100);

  // Indicative pro-rata share the rescuer would receive (server clearing is
  // authoritative). Uses the auction's max_share_bps ceiling.
  const indicative = indicativeShareBps(
    capitalCents,
    auction.capital_needed_cents,
    auction.max_share_bps,
  );

  // Clearing preview from the visible sealed bids (owner-facing dilution hint).
  const preview = useMemo(() => {
    const cb: RescueBid[] = rescuers.map((r) => ({
      capital: r.capital_cents,
      share_bps: r.share_bps,
    }));
    return bailoutClearing(cb, auction.capital_needed_cents);
  }, [rescuers, auction.capital_needed_cents]);

  const raised = rescuers.reduce((s, r) => s + (r.capital_cents ?? 0), 0);
  const fundedPct = auction.capital_needed_cents > 0
    ? Math.min(100, Math.round((raised / auction.capital_needed_cents) * 100))
    : 0;

  const errors: string[] = [];
  if (!(capitalCents > 0)) errors.push("Capital must be greater than $0.");
  if (!(shareBpsWanted > 0)) errors.push("Requested share must be greater than 0%.");
  if (shareBpsWanted > auction.max_share_bps)
    errors.push(`Requested share exceeds the owner's ${formatBps(auction.max_share_bps)} ceiling.`);

  const doBid = async () => {
    try {
      await bid.mutateAsync({ capital_cents: capitalCents, share_bps: shareBpsWanted });
      setConfirmOpen(false);
      setCapital("");
      setSharePct("");
      toast.success("Rescue capital escrowed.");
    } catch {
      /* hook toasts on error */
    }
  };

  const doClear = async () => {
    try {
      await clear.mutateAsync();
      toast.success("Bailout auction cleared.");
    } catch {
      /* hook toasts on error */
    }
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="flex items-center gap-2 text-base">
            <LifeBuoy className="h-4 w-4 text-primary" /> Bailout auction
          </CardTitle>
          <Badge variant={STATUS_VARIANT[auction.status] ?? "outline"}>{auction.status}</Badge>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Metric label="Capital needed" value={formatCents(auction.capital_needed_cents)} />
            <Metric label="Raised" value={`${formatCents(raised)} (${fundedPct}%)`} />
            <Metric label="Max share (ceiling)" value={formatBps(auction.max_share_bps)} />
            <Metric
              label={auction.status === "cleared" ? "Clearing share" : "Implied share"}
              value={
                auction.clearing_share_bps != null
                  ? formatBps(auction.clearing_share_bps)
                  : preview.clearingShareBps > 0
                    ? `~${formatBps(preview.clearingShareBps)}`
                    : "—"
              }
            />
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
            <div className="h-full rounded-full bg-primary transition-all" style={{ width: `${fundedPct}%` }} />
          </div>
          {isOpen && (
            <p className="text-xs text-muted-foreground">
              Implied from visible bids: {preview.cleared ? "fully funded" : "under-funded"} — would
              raise {formatCents(preview.raised)} of {formatCents(auction.capital_needed_cents)} for
              {preview.clearingShareBps > 0 ? ` ${formatBps(preview.clearingShareBps)} of the position` : " —"}.
            </p>
          )}
          {/* Live cancel-on-liq warning. */}
          <div className="flex items-start gap-2 rounded-md border border-amber-300/50 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-500/30 dark:bg-amber-950/40 dark:text-amber-300">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>
              If the mark hits the {formatCents(auction.liq_price)} liquidation price first, this
              auction auto-cancels and the position is liquidated normally. Current mark{" "}
              {formatCents(auction.mark_price)}.
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Rescue-bid form (non-owner, while open) behind a money-safety confirm. */}
      {!isOwner && isOpen && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Bail out this position</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Inject rescue capital in exchange for a position-share — you co-own that slice of the
              position and its future unrealized PnL. Capital is escrowed until the auction clears or
              cancels.
            </p>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="rescue-capital">Capital ($)</Label>
                <Input id="rescue-capital" type="number" min={0} step={0.01} value={capital} onChange={(e) => setCapital(e.target.value)} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="rescue-share">Position-share wanted (%)</Label>
                <Input id="rescue-share" type="number" min={0} max={100} step={0.01} value={sharePct} onChange={(e) => setSharePct(e.target.value)} />
              </div>
            </div>
            <div className="rounded-lg border bg-muted/30 p-3 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Indicative pro-rata share</span>
                <span className="font-medium tabular-nums">
                  {indicative > 0 ? `~${formatBps(indicative)}` : "—"}
                </span>
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                Indicative only — the sealed auction clears at one uniform least-dilutive price.
              </p>
            </div>
            {errors.length > 0 && (
              <ul className="list-inside list-disc space-y-0.5 text-xs text-rose-600 dark:text-rose-400">
                {errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            )}
            <Button
              disabled={errors.length > 0 || bid.isPending}
              onClick={() => setConfirmOpen(true)}
              data-testid="rescue-bid"
            >
              Review &amp; bail out
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Bid book */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="text-base">Rescuer bids</CardTitle>
          {isOwner && isOpen && (
            <Button size="sm" onClick={doClear} disabled={clear.isPending} data-testid="clear-bailout">
              {clear.isPending ? "Clearing..." : "Clear auction"}
            </Button>
          )}
        </CardHeader>
        <CardContent>
          {rescuers.length === 0 ? (
            <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
              No rescue bids yet.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Rescuer</TableHead>
                  <TableHead className="text-right">Capital</TableHead>
                  <TableHead className="text-right">Share (bps)</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rescuers.map((r, i) => (
                  <TableRow key={`${r.sub}-${i}`}>
                    <TableCell className="font-mono text-xs">{shortSub(r.sub)}</TableCell>
                    <TableCell className="text-right tabular-nums">{formatCents(r.capital_cents)}</TableCell>
                    <TableCell className="text-right tabular-nums">{formatBps(r.share_bps)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Money-safety confirm (arm -> confirm) */}
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm rescue bid</DialogTitle>
            <DialogDescription>
              This escrows real capital for a position-share. Capital is held until the auction
              clears (you receive the share) or cancels (it is returned).
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 rounded-lg border bg-muted/30 p-3 text-sm">
            <Row label="Capital escrowed" value={formatCents(capitalCents)} />
            <Row label="Position-share wanted" value={formatBps(shareBpsWanted)} />
            <Row label="Indicative fill" value={indicative > 0 ? `~${formatBps(indicative)}` : "—"} />
            <Row label="Auto-cancels if mark hits" value={formatCents(auction.liq_price)} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)} disabled={bid.isPending}>
              Cancel
            </Button>
            <Button onClick={doBid} disabled={bid.isPending} data-testid="rescue-bid-confirm">
              {bid.isPending ? "Escrowing..." : "Escrow capital"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border p-2.5">
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-0.5 text-sm font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium tabular-nums">{value}</span>
    </div>
  );
}
