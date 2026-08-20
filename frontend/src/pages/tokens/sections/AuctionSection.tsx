import { useMemo, useState } from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import { toast } from "sonner";
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
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ApiError } from "@/api/client";
import type { Token, TokenAuction } from "@/api/endpoints/tokens";
import { useListToken, usePlaceAuctionBid, useClearAuction } from "@/hooks/useTokens";
import {
  formatBps,
  formatCents,
  pctToBps,
  bpsToQty,
  clearingSummary,
  type ClearingBid,
} from "@/lib/tokens";
import { PendingBackend } from "../PendingBackend";

/** Dollars string -> integer cents (rounded). */
function dollarsToCents(v: string): number {
  const n = Number(v);
  return Number.isFinite(n) ? Math.round(n * 100) : 0;
}

function shortSub(sub: string): string {
  return sub.length > 12 ? `${sub.slice(0, 6)}...${sub.slice(-4)}` : sub;
}

export function AuctionSection({
  tokenId,
  token,
  query,
  isIssuer,
}: {
  tokenId: string | undefined;
  token: Token | undefined;
  query: UseQueryResult<TokenAuction>;
  isIssuer: boolean;
}) {
  const auction = query.data;
  const noAuction = query.isError && query.error instanceof ApiError && query.error.status === 404;
  const hasOpenAuction = !!auction && auction.status === "open";

  if (query.isLoading) {
    return (
      <Card>
        <CardContent className="p-4">
          <Skeleton className="h-32 w-full" />
        </CardContent>
      </Card>
    );
  }

  // Non-404 errors still degrade to the pending-backend note.
  if (query.isError && !noAuction) {
    return (
      <Card>
        <CardContent className="p-4">
          <PendingBackend label="The auction" />
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {auction ? (
        <AuctionPanel tokenId={tokenId} token={token} auction={auction} isIssuer={isIssuer} />
      ) : isIssuer ? (
        <ListLauncher tokenId={tokenId} token={token} />
      ) : (
        <Card>
          <CardContent className="p-6 text-center text-sm text-muted-foreground">
            {hasOpenAuction
              ? "Loading auction..."
              : "This token has no open IPO auction. Only the issuer can open one."}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ── Issuer: open the IPO ─────────────────────────────────────────────

function ListLauncher({ tokenId, token }: { tokenId: string | undefined; token: Token | undefined }) {
  const list = useListToken(tokenId);
  const [offeredPct, setOfferedPct] = useState("20");
  const [reserve, setReserve] = useState("1.00");
  const [closeLocal, setCloseLocal] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);

  const offeredBps = pctToBps(Number(offeredPct));
  const reserveCents = dollarsToCents(reserve);
  const closeTs = closeLocal ? Math.floor(new Date(closeLocal).getTime() / 1000) : 0;
  const offeredQty = token ? bpsToQty(token.total_supply, offeredBps) : 0;

  const errors: string[] = [];
  if (!(Number(offeredPct) > 0) || Number(offeredPct) > 100) errors.push("Offered % must be 1-100.");
  if (!(reserveCents > 0)) errors.push("Reserve price must be greater than $0.");
  if (!closeTs || closeTs * 1000 <= Date.now()) errors.push("Close time must be in the future.");

  const doList = async () => {
    try {
      await list.mutateAsync({
        offered_pct_bps: offeredBps,
        reserve_price: reserveCents,
        close_ts: closeTs,
      });
      setConfirmOpen(false);
      toast.success("IPO auction opened.");
    } catch {
      /* hook toasts on error */
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">List (IPO) - single-clearing-price auction</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Offer a slice of supply via a sealed-bid auction. All winning bids fill at one clearing
          price. After clearing, the token trades on a continuous book.
        </p>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="space-y-1.5">
            <Label htmlFor="ipo-pct">Offered %</Label>
            <Input id="ipo-pct" type="number" min={1} max={100} step={1} value={offeredPct} onChange={(e) => setOfferedPct(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ipo-reserve">Reserve price ($)</Label>
            <Input id="ipo-reserve" type="number" min={0} step={0.01} value={reserve} onChange={(e) => setReserve(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ipo-close">Close time</Label>
            <Input id="ipo-close" type="datetime-local" value={closeLocal} onChange={(e) => setCloseLocal(e.target.value)} />
          </div>
        </div>
        <div className="rounded-lg border bg-muted/30 p-3 text-sm">
          <div className="flex justify-between">
            <span className="text-muted-foreground">Tokens offered</span>
            <span className="font-medium tabular-nums">
              {offeredQty.toLocaleString()} ({formatBps(offeredBps)})
            </span>
          </div>
        </div>
        {errors.length > 0 && (
          <ul className="list-inside list-disc space-y-0.5 text-xs text-rose-600 dark:text-rose-400">
            {errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        )}
        <Button disabled={errors.length > 0 || list.isPending} onClick={() => setConfirmOpen(true)} data-testid="open-ipo">
          Review &amp; open IPO
        </Button>
      </CardContent>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Open IPO auction</DialogTitle>
            <DialogDescription>
              This opens a sealed-bid auction offering {formatBps(offeredBps)} of supply.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 rounded-lg border bg-muted/30 p-3 text-sm">
            <Row label="Offered" value={`${offeredQty.toLocaleString()} (${formatBps(offeredBps)})`} />
            <Row label="Reserve price" value={formatCents(reserveCents)} />
            <Row label="Closes" value={closeTs ? new Date(closeTs * 1000).toLocaleString() : "-"} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)} disabled={list.isPending}>
              Cancel
            </Button>
            <Button onClick={doList} disabled={list.isPending} data-testid="open-ipo-confirm">
              {list.isPending ? "Opening..." : "Open IPO"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

// ── Open auction panel (bids + place-bid + clearing + clear) ─────────

function AuctionPanel({
  tokenId,
  token,
  auction,
  isIssuer,
}: {
  tokenId: string | undefined;
  token: Token | undefined;
  auction: TokenAuction;
  isIssuer: boolean;
}) {
  const bid = usePlaceAuctionBid(tokenId);
  const clear = useClearAuction(tokenId);
  const [qty, setQty] = useState("");
  const [limit, setLimit] = useState("");

  const bids = auction.bids ?? [];
  const offeredQty = token ? bpsToQty(token.total_supply, auction.offered_pct_bps) : 0;

  // Implied clearing preview from the visible sealed bids (issuer-facing hint).
  const preview = useMemo(() => {
    const cb: ClearingBid[] = bids.map((b) => ({ qty: b.qty, limit_price: b.limit_price }));
    return clearingSummary(cb, offeredQty, auction.reserve_price);
  }, [bids, offeredQty, auction.reserve_price]);

  const qtyN = Number(qty);
  const limitCents = dollarsToCents(limit);
  const canBid = qtyN > 0 && Number.isInteger(qtyN) && limitCents >= auction.reserve_price;

  const doBid = async () => {
    try {
      await bid.mutateAsync({ qty: qtyN, limit_price: limitCents });
      toast.success("Bid placed.");
      setQty("");
      setLimit("");
    } catch {
      /* hook toasts on error */
    }
  };

  const doClear = async () => {
    try {
      await clear.mutateAsync();
      toast.success("Auction cleared.");
    } catch {
      /* hook toasts on error */
    }
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="text-base">IPO auction</CardTitle>
          <Badge variant={auction.status === "open" ? "default" : "secondary"}>{auction.status}</Badge>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Metric label="Offered" value={`${offeredQty.toLocaleString()} (${formatBps(auction.offered_pct_bps)})`} />
            <Metric label="Reserve" value={formatCents(auction.reserve_price)} />
            <Metric
              label="Closes"
              value={auction.close_ts ? new Date(auction.close_ts * 1000).toLocaleString() : "-"}
            />
            <Metric
              label={auction.status === "cleared" ? "Clearing price" : "Implied clearing"}
              value={
                auction.clearing_price != null
                  ? formatCents(auction.clearing_price)
                  : preview.clearingPrice != null
                    ? `~${formatCents(preview.clearingPrice)}`
                    : "-"
              }
            />
          </div>
          {auction.status === "open" && (
            <p className="text-xs text-muted-foreground">
              Implied from visible bids: {preview.cleared ? "fully subscribed" : "under-subscribed"} -
              would fill {preview.filledQty.toLocaleString()} of {offeredQty.toLocaleString()} tokens
              {preview.clearingPrice != null ? ` at ${formatCents(preview.clearingPrice)}` : ""}.
            </p>
          )}
        </CardContent>
      </Card>

      {/* Place-bid (non-issuers, while open) */}
      {!isIssuer && auction.status === "open" && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Place a sealed bid</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="bid-qty">Quantity</Label>
                <Input id="bid-qty" type="number" min={1} step={1} value={qty} onChange={(e) => setQty(e.target.value)} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="bid-limit">Limit price ($)</Label>
                <Input id="bid-limit" type="number" min={0} step={0.01} value={limit} onChange={(e) => setLimit(e.target.value)} />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              Limit must be at or above the {formatCents(auction.reserve_price)} reserve. All winning
              bids fill at one clearing price.
            </p>
            <Button onClick={doBid} disabled={!canBid || bid.isPending} data-testid="place-bid">
              {bid.isPending ? "Placing..." : "Place bid"}
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Bids table */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="text-base">Bids</CardTitle>
          {isIssuer && auction.status === "open" && (
            <Button size="sm" onClick={doClear} disabled={clear.isPending} data-testid="clear-auction">
              {clear.isPending ? "Clearing..." : "Clear auction"}
            </Button>
          )}
        </CardHeader>
        <CardContent>
          {bids.length === 0 ? (
            <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
              No bids yet.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Bidder</TableHead>
                  <TableHead className="text-right">Quantity</TableHead>
                  <TableHead className="text-right">Limit price</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {bids.map((b, i) => (
                  <TableRow key={`${b.sub}-${i}`}>
                    <TableCell className="font-mono text-xs">{shortSub(b.sub)}</TableCell>
                    <TableCell className="text-right tabular-nums">{b.qty.toLocaleString()}</TableCell>
                    <TableCell className="text-right tabular-nums">{formatCents(b.limit_price)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
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
