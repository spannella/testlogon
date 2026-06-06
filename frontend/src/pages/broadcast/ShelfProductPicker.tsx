import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { ShoppingBag, Loader2, Zap } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { getShelfProducts } from "@/api/endpoints/broadcast-shelf";
import type { ShelfItem } from "@/api/endpoints/broadcast-shelf";
import { sendChatProductLink } from "@/api/endpoints/broadcast-chat";

// GAP-0290 (LCOM-002) — broadcaster dialog to pick a shelf product and share
// it into the live chat via POST /broadcast/sessions/{id}/chat/product.

// Pricing fields (broadcast_price_cents / effective_price_cents / discount_pct)
// are being added to ShelfItem by GAP-0291. To avoid a merge conflict on that
// addition, read them locally as an optional augmentation instead of editing
// the shared ShelfItem type.
type ShelfItemWithPricing = ShelfItem & {
  effective_price_cents?: number | null;
  is_broadcast_price?: boolean | null;
  discount_pct?: number | null;
};

interface ShelfProductPickerProps {
  sessionId: string;
  open: boolean;
  onClose: () => void;
  onSent?: () => void;
}

export function ShelfProductPicker({
  sessionId,
  open,
  onClose,
  onSent,
}: ShelfProductPickerProps) {
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);

  const shelfQuery = useQuery({
    queryKey: ["broadcast", "shelf", sessionId],
    queryFn: () => getShelfProducts(sessionId),
    enabled: open,
    staleTime: 30_000,
  });

  const shareMut = useMutation({
    mutationFn: (itemId: string) => sendChatProductLink(sessionId, itemId),
    onSuccess: () => {
      setSelectedItemId(null);
      onSent?.();
      onClose();
    },
  });

  const products: ShelfItemWithPricing[] = shelfQuery.data?.items ?? [];

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-sm" data-testid="shelf-product-picker">
        <DialogHeader>
          <DialogTitle>Share a Product</DialogTitle>
          <DialogDescription>
            Choose a product from your shelf to share in the chat.
          </DialogDescription>
        </DialogHeader>

        {shelfQuery.isLoading ? (
          <div className="flex justify-center py-6">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          </div>
        ) : products.length === 0 ? (
          <p
            className="py-6 text-center text-sm text-muted-foreground"
            data-testid="shelf-empty"
          >
            Your shelf is empty. Add products from the session settings.
          </p>
        ) : (
          <ul
            className="space-y-2 max-h-72 overflow-y-auto pr-1"
            data-testid="shelf-product-list"
          >
            {products.map((p) => {
              const effectiveCents = p.effective_price_cents ?? p.price_cents;
              const effectivePrice = (effectiveCents / 100).toFixed(2);
              const regularPrice = (p.price_cents / 100).toFixed(2);
              const hasDiscount =
                !!p.is_broadcast_price &&
                p.discount_pct != null &&
                p.discount_pct > 0 &&
                effectiveCents < p.price_cents;

              return (
                <li key={p.item_id}>
                  <button
                    type="button"
                    className={`w-full flex items-center gap-3 rounded-md border px-3 py-2 text-left transition-colors ${
                      selectedItemId === p.item_id
                        ? "border-primary bg-primary/10"
                        : "border-border hover:bg-muted/50"
                    }`}
                    onClick={() => setSelectedItemId(p.item_id)}
                    data-testid={`shelf-product-${p.item_id}`}
                  >
                    {p.image_url && (
                      <img
                        src={p.image_url}
                        alt={p.name}
                        className="h-10 w-10 rounded object-cover shrink-0"
                      />
                    )}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{p.name}</p>
                      <div className="flex items-center gap-1 mt-0.5">
                        <span className="text-xs font-bold text-primary">
                          ${effectivePrice}
                        </span>
                        {hasDiscount && (
                          <>
                            <span className="text-[10px] line-through text-muted-foreground">
                              ${regularPrice}
                            </span>
                            <Badge
                              variant="destructive"
                              className="text-[9px] px-1 py-0 h-4"
                            >
                              <Zap className="h-2 w-2 mr-0.5" />
                              {p.discount_pct}% off
                            </Badge>
                          </>
                        )}
                      </div>
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button
            size="sm"
            disabled={!selectedItemId || shareMut.isPending}
            onClick={() => selectedItemId && shareMut.mutate(selectedItemId)}
            data-testid="shelf-share-btn"
          >
            {shareMut.isPending ? (
              <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
            ) : (
              <ShoppingBag className="mr-1 h-3.5 w-3.5" />
            )}
            Share in Chat
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
