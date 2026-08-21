import { useState } from "react";
import { ShieldAlert, LifeBuoy, PlusCircle, Minus } from "lucide-react";
import { toast } from "sonner";
import { Link } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useDistress, usePositionBailout, useOpenBailout, useBailoutPrefs } from "@/hooks/useBailouts";
import type { DistressPosition } from "@/api/endpoints/bailouts";
import { healthZone, distressFraction, formatBps, formatCents, pctToBps } from "@/lib/bailout";
import { BailoutPendingBackend, HealthMeter } from "./BailoutShared";
import { BailoutAuctionPanel } from "./BailoutAuctionPanel";

/**
 * The margin-distress block for the Portfolio / position surface. For each of
 * the caller's margin positions it renders a 3-zone health meter + a live buffer
 * readout (distance-to-liq % vs the volatility-scaled danger line). When a
 * position is `eligible`, a distress banner offers the ordered escape options —
 * Add margin / Reduce position (links to the existing flows) then "Open bailout
 * auction" (which avoids the forced-liquidation penalty). Distress is
 * server-authoritative; the client never fabricates a signal.
 */
export function MarginDistressSection() {
  const distressQ = useDistress();
  const prefsQ = useBailoutPrefs();

  if (distressQ.isLoading) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm font-medium">
            <ShieldAlert className="h-4 w-4 text-muted-foreground" /> Margin distress
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-24 w-full" />
        </CardContent>
      </Card>
    );
  }

  const positions = distressQ.data?.positions ?? [];
  const autoEnabled = !!prefsQ.data?.auto_enabled;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <ShieldAlert className="h-4 w-4 text-muted-foreground" /> Margin distress
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {distressQ.isError ? (
          <BailoutPendingBackend label="Margin distress" />
        ) : positions.length === 0 ? (
          <p className="py-2 text-sm text-muted-foreground">
            No margin positions to monitor. Positions in the volatility-scaled distress band appear
            here with a bailout option before they are liquidated.
          </p>
        ) : (
          positions.map((p) => (
            <DistressRow key={p.symbol_id} p={p} autoEnabled={autoEnabled} />
          ))
        )}
      </CardContent>
    </Card>
  );
}

function DistressRow({ p, autoEnabled }: { p: DistressPosition; autoEnabled: boolean }) {
  const solvent = p.equity_cents > p.maintenance_cents;
  const zone = healthZone(p.buffer_bps, p.danger_bps, solvent);
  const frac = distressFraction(p.buffer_bps, p.danger_bps);

  // If a bailout already exists for this position, show its panel inline.
  const bailoutQ = usePositionBailout(p.symbol_id, !!p.auction_id);
  const auction = bailoutQ.data;

  return (
    <div className="space-y-3 rounded-lg border p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="font-medium">{p.symbol}</span>
          <span className="text-xs uppercase text-muted-foreground">{p.side}</span>
        </div>
        <div className="flex gap-4 text-xs tabular-nums text-muted-foreground">
          <span>Entry {formatCents(p.entry_price)}</span>
          <span>Mark {formatCents(p.mark_price)}</span>
          <span>Liq {formatCents(p.liq_price)}</span>
        </div>
      </div>

      <HealthMeter zone={zone} fraction={frac} bufferBps={p.buffer_bps} dangerBps={p.danger_bps} />

      <div className="flex flex-wrap gap-4 text-xs tabular-nums text-muted-foreground">
        <span>
          Equity <span className="font-medium text-foreground">{formatCents(p.equity_cents)}</span>
        </span>
        <span>
          Maintenance{" "}
          <span className="font-medium text-foreground">{formatCents(p.maintenance_cents)}</span>
        </span>
        <span>
          Volatility <span className="font-medium text-foreground">{formatBps(p.volatility_bps)}</span>
        </span>
      </div>

      {/* Distress banner with the ordered escape options (eligible only). */}
      {p.eligible && !auction && (
        <DistressBanner p={p} autoEnabled={autoEnabled} />
      )}

      {/* An already-open auction renders inline. */}
      {auction && <BailoutAuctionPanel auction={auction} isOwner symbolId={p.symbol_id} />}
    </div>
  );
}

function DistressBanner({ p, autoEnabled }: { p: DistressPosition; autoEnabled: boolean }) {
  return (
    <div className="space-y-3 rounded-md border border-amber-300/60 bg-amber-50 p-3 dark:border-amber-500/40 dark:bg-amber-950/40">
      <div className="flex items-start gap-2">
        <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-700 dark:text-amber-400" />
        <div className="text-sm text-amber-900 dark:text-amber-200">
          <p className="font-semibold">This position is in the distress band.</p>
          <p className="text-xs">
            It is still solvent (equity above maintenance), so you can act before a forced
            liquidation. Options, in order:
          </p>
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button asChild size="sm" variant="outline">
          <Link to={`/markets/${p.symbol_id}`}>
            <PlusCircle className="mr-1.5 h-3.5 w-3.5" /> Add margin
          </Link>
        </Button>
        <Button asChild size="sm" variant="outline">
          <Link to={`/markets/${p.symbol_id}`}>
            <Minus className="mr-1.5 h-3.5 w-3.5" /> Reduce position
          </Link>
        </Button>
        <OpenBailoutButton p={p} autoEnabled={autoEnabled} />
      </div>
      <p className="text-[11px] text-amber-800/80 dark:text-amber-300/80">
        A bailout auction raises rescue capital from other traders for a slice of this position —
        avoiding the forced-liquidation penalty.{" "}
        {autoEnabled
          ? "Auto-bailout is ON: an auction opens automatically on band-entry."
          : "Auto-bailout is off, so open one manually below."}
      </p>
    </div>
  );
}

function OpenBailoutButton({ p, autoEnabled }: { p: DistressPosition; autoEnabled: boolean }) {
  const open = useOpenBailout(p.symbol_id);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [maxSharePct, setMaxSharePct] = useState("20");

  const maxShareBps = pctToBps(Number(maxSharePct));
  const invalid = !(Number(maxSharePct) > 0) || Number(maxSharePct) > 100;

  const doOpen = async () => {
    try {
      await open.mutateAsync({ max_share_bps: maxShareBps });
      setDialogOpen(false);
      toast.success("Bailout auction opened.");
    } catch {
      /* hook toasts on error */
    }
  };

  return (
    <>
      <Button size="sm" onClick={() => setDialogOpen(true)} data-testid="open-bailout">
        <LifeBuoy className="mr-1.5 h-3.5 w-3.5" /> Open bailout auction
      </Button>
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Open a bailout auction</DialogTitle>
            <DialogDescription>
              Raise rescue capital for {p.symbol} in a sealed single-clearing-price auction. Rescuers
              inject capital for a position-share (co-owning a slice of the position and its future
              uPnL). It clears at the least-dilutive uniform price. If the mark hits{" "}
              {formatCents(p.liq_price)} first it auto-cancels into a normal liquidation.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5">
            <Label htmlFor="bailout-max-share">Max position-share to give up (%)</Label>
            <Input
              id="bailout-max-share"
              type="number"
              min={1}
              max={100}
              step={1}
              value={maxSharePct}
              onChange={(e) => setMaxSharePct(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Ceiling on total dilution ({formatBps(maxShareBps)}). The auction clears at or below
              this.
            </p>
            {autoEnabled && (
              <p className="text-xs text-muted-foreground">
                Auto-bailout is enabled — the server may have opened one automatically already.
              </p>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)} disabled={open.isPending}>
              Cancel
            </Button>
            <Button onClick={doOpen} disabled={invalid || open.isPending} data-testid="open-bailout-confirm">
              {open.isPending ? "Opening..." : "Open auction"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
