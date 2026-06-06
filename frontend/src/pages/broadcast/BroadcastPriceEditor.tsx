import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Tag, X, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  setBroadcastPrice,
  clearBroadcastPrice,
  type ShelfItem,
} from "@/api/endpoints/broadcast-shelf";

interface BroadcastPriceEditorProps {
  sessionId: string;
  item: ShelfItem;
}

/**
 * Per-row inline editor (LCOM-004 §3.9 / GAP-0293) that lets the broadcaster
 * set or clear a broadcast-exclusive price on a single shelf item. Wraps the
 * `setBroadcastPrice` / `clearBroadcastPrice` API wrappers (GAP-0291) and
 * invalidates the shelf query on success so the row re-renders with the
 * effective price.
 */
export function BroadcastPriceEditor({ sessionId, item }: BroadcastPriceEditorProps) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [priceInput, setPriceInput] = useState("");
  const [expiryInput, setExpiryInput] = useState("");

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["broadcast-shelf", sessionId] });

  const setMut = useMutation({
    mutationFn: () => {
      const cents = Math.round(parseFloat(priceInput) * 100);
      const expiry = expiryInput ? parseInt(expiryInput, 10) * 60 : undefined;
      return setBroadcastPrice(sessionId, item.item_id, {
        broadcast_price_cents: cents,
        expires_in_seconds: expiry,
      });
    },
    onSuccess: (data) => {
      invalidate();
      toast.success(
        `Broadcast price set: $${(data.broadcast_price_cents / 100).toFixed(2)} (${data.discount_pct}% off)`,
      );
      setOpen(false);
      setPriceInput("");
      setExpiryInput("");
    },
    onError: (err) =>
      toast.error(err instanceof Error ? err.message : "Failed to set price"),
  });

  const clearMut = useMutation({
    mutationFn: () => clearBroadcastPrice(sessionId, item.item_id),
    onSuccess: () => {
      invalidate();
      toast.success("Broadcast price cleared");
    },
    onError: (err) =>
      toast.error(err instanceof Error ? err.message : "Failed to clear price"),
  });

  const catalogDollars = (item.price_cents / 100).toFixed(2);
  const maxDollars = ((item.price_cents - 1) / 100).toFixed(2);

  return (
    <div className="flex items-center gap-1">
      {item.is_broadcast_price && (
        <Badge
          variant="destructive"
          className="text-[10px] px-1 h-4"
          data-testid={`broadcast-price-active-badge-${item.item_id}`}
        >
          {item.discount_pct}% OFF
        </Badge>
      )}
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            aria-label={`Set broadcast price for ${item.name}`}
            data-testid={`set-broadcast-price-btn-${item.item_id}`}
          >
            <Tag className="h-3 w-3" />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-64 p-3" align="end">
          <div className="space-y-3">
            <p className="text-sm font-medium">Broadcast Price</p>
            <p className="text-xs text-muted-foreground">
              Catalog price: ${catalogDollars}. Must be less than ${maxDollars}.
            </p>
            <div className="space-y-1">
              <Label htmlFor={`bp-price-${item.item_id}`} className="text-xs">
                Price ($)
              </Label>
              <Input
                id={`bp-price-${item.item_id}`}
                type="number"
                min="0.01"
                max={maxDollars}
                step="0.01"
                placeholder={`e.g. ${(item.price_cents / 200).toFixed(2)}`}
                value={priceInput}
                onChange={(e) => setPriceInput(e.target.value)}
                data-testid={`broadcast-price-input-${item.item_id}`}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor={`bp-expiry-${item.item_id}`} className="text-xs">
                Expires in (minutes, optional)
              </Label>
              <Input
                id={`bp-expiry-${item.item_id}`}
                type="number"
                min="1"
                max="1440"
                placeholder="e.g. 10"
                value={expiryInput}
                onChange={(e) => setExpiryInput(e.target.value)}
                data-testid={`broadcast-price-expiry-input-${item.item_id}`}
              />
            </div>
            <div className="flex gap-2">
              <Button
                size="sm"
                className="flex-1"
                disabled={!priceInput || setMut.isPending}
                onClick={() => setMut.mutate()}
                data-testid={`broadcast-price-save-btn-${item.item_id}`}
              >
                {setMut.isPending ? (
                  <Loader2 className="h-3 w-3 animate-spin mr-1" />
                ) : null}
                Set Price
              </Button>
              {item.is_broadcast_price && (
                <Button
                  size="sm"
                  variant="outline"
                  disabled={clearMut.isPending}
                  onClick={() => clearMut.mutate()}
                  data-testid={`broadcast-price-clear-btn-${item.item_id}`}
                  aria-label={`Clear broadcast price for ${item.name}`}
                >
                  {clearMut.isPending ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <X className="h-3 w-3" />
                  )}
                </Button>
              )}
            </div>
          </div>
        </PopoverContent>
      </Popover>
    </div>
  );
}
