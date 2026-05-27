import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Plus,
  Trash2,
  ArrowUp,
  ArrowDown,
  Package,
  Loader2,
  ShoppingBag,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  getShelfProducts,
  addShelfProduct,
  removeShelfProduct,
  reorderShelf,
  type ShelfItem,
} from "@/api/endpoints/broadcast-shelf";
import type { CatalogItem } from "@/api/types";
import { CatalogPickerDialog } from "./CatalogPickerDialog";

// ─── Helpers ──────────────────────────────────────────────────────

function formatPrice(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format(cents / 100);
}

const MAX_SHELF = 50;

// ─── Component ────────────────────────────────────────────────────

interface ProductShelfManagerProps {
  sessionId: string;
  sessionStatus: string;
  sessionCreatedBy: string;
}

export function ProductShelfManager({
  sessionId,
  sessionStatus,
  sessionCreatedBy: _sessionCreatedBy,
}: ProductShelfManagerProps) {
  void _sessionCreatedBy; // used for future ownership checks
  const queryClient = useQueryClient();
  const [pickerOpen, setPickerOpen] = useState(false);

  const canManage = ["draft", "ready", "live"].includes(sessionStatus);

  // ─── Data ─────────────────────────────────────────────────────

  const shelfQuery = useQuery({
    queryKey: ["broadcast-shelf", sessionId],
    queryFn: () => getShelfProducts(sessionId),
    staleTime: 10_000,
  });

  const items: ShelfItem[] = shelfQuery.data?.items ?? [];
  const existingIds = new Set(items.map((i) => i.item_id));

  // ─── Mutations ────────────────────────────────────────────────

  const addMut = useMutation({
    mutationFn: (vars: { categoryId: string; itemId: string; displayOrder: number }) =>
      addShelfProduct(sessionId, {
        item_id: vars.itemId,
        category_id: vars.categoryId,
        display_order: vars.displayOrder,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast-shelf", sessionId] });
      toast.success("Product added to shelf");
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to add product"),
  });

  const removeMut = useMutation({
    mutationFn: (itemId: string) => removeShelfProduct(sessionId, itemId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast-shelf", sessionId] });
      toast.success("Product removed from shelf");
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to remove product"),
  });

  const reorderMut = useMutation({
    mutationFn: (order: string[]) => reorderShelf(sessionId, order),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast-shelf", sessionId] });
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to reorder"),
  });

  // ─── Handlers ─────────────────────────────────────────────────

  const handlePickItem = (categoryId: string, item: CatalogItem) => {
    addMut.mutate({
      categoryId,
      itemId: item.item_id,
      displayOrder: items.length,
    });
    setPickerOpen(false);
  };

  const handleRemove = (itemId: string) => {
    removeMut.mutate(itemId);
  };

  const handleMoveUp = (index: number) => {
    if (index <= 0) return;
    const newOrder = items.map((i) => i.item_id);
    const tmp = newOrder[index - 1]!;
    newOrder[index - 1] = newOrder[index]!;
    newOrder[index] = tmp;
    reorderMut.mutate(newOrder);
  };

  const handleMoveDown = (index: number) => {
    if (index >= items.length - 1) return;
    const newOrder = items.map((i) => i.item_id);
    const tmp = newOrder[index]!;
    newOrder[index] = newOrder[index + 1]!;
    newOrder[index + 1] = tmp;
    reorderMut.mutate(newOrder);
  };

  // ─── Render ───────────────────────────────────────────────────

  return (
    <>
      <Card data-testid="product-shelf-manager">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShoppingBag className="h-4 w-4 text-muted-foreground" />
              <CardTitle className="text-sm font-medium">Product Shelf</CardTitle>
              <Badge variant="outline" className="text-xs" data-testid="shelf-manager-count">
                {items.length}/{MAX_SHELF}
              </Badge>
            </div>
            {canManage && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPickerOpen(true)}
                disabled={items.length >= MAX_SHELF || addMut.isPending}
                data-testid="add-product-btn"
              >
                {addMut.isPending ? (
                  <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                ) : (
                  <Plus className="h-3 w-3 mr-1" />
                )}
                Add Product
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {shelfQuery.isLoading ? (
            <div className="flex items-center justify-center py-6">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : items.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-6 text-center">
              <Package className="h-8 w-8 text-muted-foreground/50 mb-2" />
              <p className="text-sm text-muted-foreground">
                No products on the shelf yet
              </p>
              {canManage && (
                <p className="text-xs text-muted-foreground mt-1">
                  Add products from your catalog to display during the broadcast
                </p>
              )}
            </div>
          ) : (
            <div className="space-y-2" data-testid="shelf-manager-list">
              {items.map((item, idx) => (
                <div
                  key={item.item_id}
                  className="flex items-center gap-2 rounded-md border p-2"
                  data-testid={`shelf-manager-item-${item.item_id}`}
                >
                  {/* Thumbnail */}
                  <div className="w-10 h-10 rounded bg-muted flex items-center justify-center shrink-0 overflow-hidden">
                    {item.image_url ? (
                      <img
                        src={item.image_url}
                        alt={item.name}
                        className="w-full h-full object-cover"
                      />
                    ) : (
                      <Package className="h-4 w-4 text-muted-foreground" />
                    )}
                  </div>

                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">{item.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {formatPrice(item.price_cents, item.currency)}
                    </p>
                  </div>

                  {/* Controls */}
                  {canManage && (
                    <div className="flex items-center gap-1 shrink-0">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-6 w-6"
                        onClick={() => handleMoveUp(idx)}
                        disabled={idx === 0 || reorderMut.isPending}
                        aria-label={`Move ${item.name} up`}
                      >
                        <ArrowUp className="h-3 w-3" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-6 w-6"
                        onClick={() => handleMoveDown(idx)}
                        disabled={idx === items.length - 1 || reorderMut.isPending}
                        aria-label={`Move ${item.name} down`}
                      >
                        <ArrowDown className="h-3 w-3" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-6 w-6 text-destructive hover:text-destructive"
                        onClick={() => handleRemove(item.item_id)}
                        disabled={removeMut.isPending}
                        aria-label={`Remove ${item.name}`}
                        data-testid={`remove-shelf-item-${item.item_id}`}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <CatalogPickerDialog
        open={pickerOpen}
        onClose={() => setPickerOpen(false)}
        onSelect={handlePickItem}
        existingItemIds={existingIds}
      />
    </>
  );
}
