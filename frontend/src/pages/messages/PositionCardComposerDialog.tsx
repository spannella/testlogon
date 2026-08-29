import { useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useSymbols } from "@/hooks/useMarketData";
import { usePaperAccount, usePaperMarks } from "@/hooks/usePaperMarks";
import { usePaperMode } from "@/lib/paperMode";
import { paperPositionsToBlotter } from "@/lib/paperBlotter";
import { PositionCard } from "./PositionCard";
import {
  buildPositionCardPayload,
  DISCLOSURE_LABEL,
  type PositionCardPayload,
  type PositionDisclosure,
  type PositionSource,
} from "@/lib/tradingCards";

interface PositionCardComposerDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (payload: PositionCardPayload) => void;
  /** Owner display name for the preview attribution. */
  ownerName?: string;
}

const DISCLOSURES: PositionDisclosure[] = ["full", "pnl_pct", "roi"];

/**
 * FE-102 composer: pick one of the caller's open positions + a disclosure
 * level, then send a position_card. The caller's open positions are read from
 * the same PAPER account the Portfolio/PnL surfaces use (usePaperMarks); ROI is
 * uPnL / notional-at-entry. The disclosure selector routes through
 * buildPositionCardPayload so reduced levels never carry entry/mark/size.
 */
export function PositionCardComposerDialog({
  open,
  onClose,
  onSubmit,
  ownerName,
}: PositionCardComposerDialogProps) {
  const { enabled: paper } = usePaperMode();
  const acct = usePaperAccount(open || paper);
  const { marks, symName } = usePaperMarks(acct, open);
  const symbolsQ = useSymbols();

  const scalerFor = useMemo(() => {
    const map = new Map<number, number>();
    for (const s of symbolsQ.data?.symbols ?? []) map.set(s.symbol_id, s.price_scaler || 1);
    return (id: number) => map.get(id) || 1;
  }, [symbolsQ.data]);

  const sources = useMemo<PositionSource[]>(() => {
    const rows = paperPositionsToBlotter(acct, marks, symName);
    return rows.map((r) => {
      const notional = Math.abs(r.avgCost * r.netQty);
      const roi = notional !== 0 ? (r.unrealized / notional) * 100 : 0;
      return {
        symbol_id: r.symbolId,
        symbol: r.sym,
        side: r.side,
        roi_pct: roi,
        entry: r.avgCost,
        mark: r.markPx,
        size: Math.abs(r.netQty),
        price_scaler: scalerFor(r.symbolId),
      };
    });
  }, [acct, marks, symName, scalerFor]);

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [disclosure, setDisclosure] = useState<PositionDisclosure>("full");

  const selected = sources.find((s) => s.symbol_id === selectedId) ?? null;
  const previewPayload = selected ? buildPositionCardPayload(selected, disclosure) : null;

  function reset() {
    setSelectedId(null);
    setDisclosure("full");
  }
  function handleClose() {
    reset();
    onClose();
  }
  function handleSubmit() {
    if (!selected) return;
    onSubmit(buildPositionCardPayload(selected, disclosure));
    reset();
  }

  return (
    <Dialog open={open} onOpenChange={(o) => (!o ? handleClose() : undefined)}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Share position</DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label>Open position</Label>
            <div className="max-h-48 overflow-y-auto rounded-md border">
              {sources.length === 0 ? (
                <p className="p-3 text-sm text-muted-foreground" data-testid="position-composer-empty">
                  No open positions to share.
                </p>
              ) : (
                sources.map((s) => (
                  <button
                    key={s.symbol_id}
                    type="button"
                    onClick={() => setSelectedId(s.symbol_id)}
                    className={
                      "flex w-full items-center justify-between px-3 py-2 text-left text-sm hover:bg-accent " +
                      (selectedId === s.symbol_id ? "bg-accent" : "")
                    }
                    data-testid={`position-composer-option-${s.symbol_id}`}
                  >
                    <span className="font-medium">
                      {s.symbol} · {s.side}
                    </span>
                    <span
                      className={
                        "tabular-nums " +
                        (s.roi_pct >= 0 ? "text-emerald-600" : "text-rose-600")
                      }
                    >
                      {s.roi_pct >= 0 ? "+" : ""}
                      {s.roi_pct.toFixed(2)}%
                    </span>
                  </button>
                ))
              )}
            </div>
          </div>

          <div className="space-y-1.5">
            <Label>Disclosure</Label>
            <RadioGroup
              value={disclosure}
              onValueChange={(v) => setDisclosure(v as PositionDisclosure)}
            >
              {DISCLOSURES.map((d) => (
                <div key={d} className="flex items-center gap-2">
                  <RadioGroupItem value={d} id={`position-disclosure-${d}`} />
                  <Label htmlFor={`position-disclosure-${d}`} className="font-normal cursor-pointer">
                    {DISCLOSURE_LABEL[d]}
                  </Label>
                </div>
              ))}
            </RadioGroup>
          </div>

          {previewPayload && (
            <div className="flex justify-center pt-1">
              <PositionCard payload={previewPayload} ownerName={ownerName} />
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={handleClose}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={!selected} data-testid="position-composer-send">
            Share
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default PositionCardComposerDialog;
