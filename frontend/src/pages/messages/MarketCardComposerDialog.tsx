import { useMemo, useState } from "react";
import { Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useSymbols } from "@/hooks/useMarketData";
import { MarketCard } from "./MarketCard";
import type { MarketCardPayload } from "@/lib/tradingCards";
import { buildMarketCardPayload } from "@/lib/tradingCards";

interface MarketCardComposerDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (payload: MarketCardPayload) => void;
}

export function MarketCardComposerDialog({
  open,
  onClose,
  onSubmit,
}: MarketCardComposerDialogProps) {
  const symbolsQ = useSymbols();
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<{ symbol_id: number; symbol: string } | null>(null);

  const results = useMemo(() => {
    const all = symbolsQ.data?.symbols ?? [];
    const q = query.trim().toUpperCase();
    const filtered = q ? all.filter((s) => s.symbol.toUpperCase().includes(q)) : all;
    return filtered.slice(0, 40);
  }, [symbolsQ.data, query]);

  function reset() {
    setQuery("");
    setSelected(null);
  }
  function handleClose() {
    reset();
    onClose();
  }
  function handleSubmit() {
    if (!selected) return;
    onSubmit(buildMarketCardPayload(selected.symbol_id, selected.symbol));
    reset();
  }

  return (
    <Dialog open={open} onOpenChange={(o) => (!o ? handleClose() : undefined)}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Share market</DialogTitle>
        </DialogHeader>

        <div className="space-y-3">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              className="pl-8"
              placeholder="Search by ticker (e.g. BTC)"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              aria-label="Search symbols"
              data-testid="market-composer-search"
            />
          </div>

          <div className="max-h-56 overflow-y-auto rounded-md border">
            {symbolsQ.isLoading ? (
              <p className="p-3 text-sm text-muted-foreground">Loading symbols…</p>
            ) : results.length === 0 ? (
              <p className="p-3 text-sm text-muted-foreground">No matching symbols.</p>
            ) : (
              results.map((s) => (
                <button
                  key={s.symbol_id}
                  type="button"
                  onClick={() => setSelected({ symbol_id: s.symbol_id, symbol: s.symbol })}
                  className={
                    "flex w-full items-center justify-between px-3 py-2 text-left text-sm hover:bg-accent " +
                    (selected?.symbol_id === s.symbol_id ? "bg-accent" : "")
                  }
                  data-testid={`market-composer-option-${s.symbol_id}`}
                >
                  <span className="font-medium">{s.symbol}</span>
                  <span className="text-xs text-muted-foreground">#{s.symbol_id}</span>
                </button>
              ))
            )}
          </div>

          {selected && (
            <div className="flex justify-center pt-1">
              <MarketCard symbolId={selected.symbol_id} symbol={selected.symbol} />
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={handleClose}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={!selected} data-testid="market-composer-send">
            Share
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default MarketCardComposerDialog;
