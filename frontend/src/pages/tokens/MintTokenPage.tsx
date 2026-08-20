import { useMemo, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { ArrowLeft, Coins } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useMintToken } from "@/hooks/useTokens";
import { CREATION_FEE_CENTS, formatCents, formatBps, pctToBps, bpsToQty } from "@/lib/tokens";
import { tokenAckMessage } from "@/api/endpoints/tokens";

export default function MintTokenPage() {
  const navigate = useNavigate();
  const mint = useMintToken();

  const [name, setName] = useState("");
  const [ticker, setTicker] = useState("");
  const [supply, setSupply] = useState("1000000");
  const [revSharePct, setRevSharePct] = useState("2.5");
  const [confirmOpen, setConfirmOpen] = useState(false);

  const supplyN = Number(supply);
  const revShareBps = pctToBps(Number(revSharePct));

  const errors = useMemo(() => {
    const e: string[] = [];
    if (!name.trim()) e.push("Name is required.");
    if (!/^[A-Za-z0-9]{2,10}$/.test(ticker.trim())) e.push("Ticker must be 2-10 letters/numbers.");
    if (!(supplyN > 0) || !Number.isInteger(supplyN)) e.push("Total supply must be a positive whole number.");
    if (!(Number(revSharePct) > 0)) e.push("Revenue-share % must be greater than 0.");
    if (Number(revSharePct) > 100) e.push("Revenue-share % cannot exceed 100%.");
    return e;
  }, [name, ticker, supplyN, revSharePct]);

  const canSubmit = errors.length === 0 && !mint.isPending;

  const doMint = async () => {
    try {
      const token = await mint.mutateAsync({
        name: name.trim(),
        ticker: ticker.trim().toUpperCase(),
        total_supply: supplyN,
        revenue_share_bps: revShareBps,
      });
      setConfirmOpen(false);
      toast.success(`Minted ${token.ticker} - you hold 100% of supply.`);
      navigate(`/tokens/${encodeURIComponent(token.token_id)}`);
    } catch (err) {
      // useMintToken already surfaces a toast; keep the dialog open so the
      // user can retry. Surface any structured ack message too.
      const msg = tokenAckMessage((err as { body?: never })?.body as never);
      if (msg) toast.error(msg);
    }
  };

  return (
    <div className="mx-auto w-full max-w-2xl space-y-6 p-4 md:p-6">
      <div className="flex items-center gap-2">
        <Button asChild variant="ghost" size="icon">
          <Link to="/tokens" aria-label="Back to tokens">
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div className="flex items-center gap-2">
          <Coins className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-bold tracking-tight">Mint a creator token</h1>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Token details</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="tok-name">Name</Label>
            <Input
              id="tok-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Jane Doe Content Revenue"
              maxLength={64}
            />
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="tok-ticker">Ticker</Label>
              <Input
                id="tok-ticker"
                value={ticker}
                onChange={(e) => setTicker(e.target.value.toUpperCase())}
                placeholder="JANE"
                maxLength={10}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="tok-supply">Total supply</Label>
              <Input
                id="tok-supply"
                type="number"
                min={1}
                step={1}
                value={supply}
                onChange={(e) => setSupply(e.target.value)}
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="tok-revshare">Revenue-share %</Label>
            <Input
              id="tok-revshare"
              type="number"
              min={0}
              max={100}
              step={0.1}
              value={revSharePct}
              onChange={(e) => setRevSharePct(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Holders receive pro-rata distributions of{" "}
              <span className="font-medium text-foreground">{formatBps(revShareBps)}</span> (
              {revShareBps.toLocaleString()} bps) of your ongoing content revenue. You mint and
              hold 100% of {supplyN > 0 ? supplyN.toLocaleString() : "-"} tokens.
            </p>
          </div>

          {errors.length > 0 && (
            <ul className="list-inside list-disc space-y-0.5 text-xs text-rose-600 dark:text-rose-400">
              {errors.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          )}

          <Separator />

          <div className="flex items-center justify-between rounded-lg border bg-muted/30 p-3 text-sm">
            <span className="text-muted-foreground">One-time creation fee</span>
            <span className="font-semibold tabular-nums">{formatCents(CREATION_FEE_CENTS)}</span>
          </div>

          <Button
            className="w-full"
            disabled={!canSubmit}
            onClick={() => setConfirmOpen(true)}
            data-testid="mint-submit"
          >
            Review &amp; mint
          </Button>
        </CardContent>
      </Card>

      {/* Money-safety confirm - mirrors the trade-ticket deposit confirm. */}
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm token mint</DialogTitle>
            <DialogDescription>
              This charges a one-time {formatCents(CREATION_FEE_CENTS)} creation fee to your account.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 rounded-lg border bg-muted/30 p-3 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Ticker</span>
              <span className="font-medium tabular-nums">{ticker.toUpperCase() || "-"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Total supply</span>
              <span className="font-medium tabular-nums">{supplyN.toLocaleString()}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Revenue-share</span>
              <span className="font-medium tabular-nums">{formatBps(revShareBps)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">You retain</span>
              <span className="font-medium tabular-nums">
                100% ({bpsToQty(supplyN, 10_000).toLocaleString()})
              </span>
            </div>
            <Separator />
            <div className="flex justify-between">
              <span className="text-muted-foreground">Creation fee</span>
              <span className="font-semibold tabular-nums text-rose-600 dark:text-rose-400">
                -{formatCents(CREATION_FEE_CENTS)}
              </span>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)} disabled={mint.isPending}>
              Cancel
            </Button>
            <Button onClick={doMint} disabled={mint.isPending} data-testid="mint-confirm">
              {mint.isPending ? "Minting..." : `Pay ${formatCents(CREATION_FEE_CENTS)} & mint`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
