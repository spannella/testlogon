import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search, Package, Loader2, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { getCategories, getCategoryItems } from "@/api/endpoints/cart";
import type { CatalogCategory, CatalogItem } from "@/api/types";

// ─── Helpers ──────────────────────────────────────────────────────

function formatPrice(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format(cents / 100);
}

// ─── Component ────────────────────────────────────────────────────

interface CatalogPickerDialogProps {
  open: boolean;
  onClose: () => void;
  onSelect: (categoryId: string, item: CatalogItem) => void;
  /** Item IDs already on the shelf (shown as disabled) */
  existingItemIds?: Set<string>;
}

export function CatalogPickerDialog({
  open,
  onClose,
  onSelect,
  existingItemIds = new Set(),
}: CatalogPickerDialogProps) {
  const [selectedCategoryId, setSelectedCategoryId] = useState<string>("");
  const [searchText, setSearchText] = useState("");

  // Fetch categories
  const categoriesQuery = useQuery({
    queryKey: ["catalog", "categories"],
    queryFn: () => getCategories(200),
    enabled: open,
    staleTime: 60_000,
  });

  // Fetch items for selected category
  const itemsQuery = useQuery({
    queryKey: ["catalog", "items", selectedCategoryId],
    queryFn: () => getCategoryItems(selectedCategoryId, 200),
    enabled: open && !!selectedCategoryId,
    staleTime: 30_000,
  });

  const categories: CatalogCategory[] = categoriesQuery.data?.items ?? [];
  const allItems: CatalogItem[] = itemsQuery.data?.items ?? [];

  // Filter items by search text
  const filteredItems = searchText.trim()
    ? allItems.filter(
        (item) =>
          item.name.toLowerCase().includes(searchText.toLowerCase()) ||
          (item.description ?? "").toLowerCase().includes(searchText.toLowerCase())
      )
    : allItems;

  // Auto-select first category on load
  useEffect(() => {
    const first = categories[0];
    if (first && !selectedCategoryId) {
      setSelectedCategoryId(first.category_id);
    }
  }, [categories, selectedCategoryId]);

  // Reset state when dialog closes
  useEffect(() => {
    if (!open) {
      setSearchText("");
    }
  }, [open]);

  return (
    <Dialog open={open} onOpenChange={() => onClose()}>
      <DialogContent className="max-w-lg max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>Add Product to Shelf</DialogTitle>
          <DialogDescription>
            Select a product from your catalog to add to the broadcast shelf.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          {/* Category selector */}
          <Select value={selectedCategoryId} onValueChange={setSelectedCategoryId}>
            <SelectTrigger data-testid="catalog-category-select">
              <SelectValue placeholder="Select a category" />
            </SelectTrigger>
            <SelectContent>
              {categories.map((cat) => (
                <SelectItem key={cat.category_id} value={cat.category_id}>
                  {cat.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          {/* Search input */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search items..."
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              className="pl-10"
              data-testid="catalog-search-input"
            />
          </div>
        </div>

        {/* Items list */}
        <ScrollArea className="flex-1 min-h-0 mt-3">
          {categoriesQuery.isLoading || itemsQuery.isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : filteredItems.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Package className="h-8 w-8 text-muted-foreground/50 mb-2" />
              <p className="text-sm text-muted-foreground">
                {selectedCategoryId ? "No items found" : "Select a category"}
              </p>
            </div>
          ) : (
            <div className="space-y-2 pr-2">
              {filteredItems.map((item) => {
                const alreadyAdded = existingItemIds.has(item.item_id);
                return (
                  <Card
                    key={item.item_id}
                    className={`cursor-pointer transition-colors ${
                      alreadyAdded
                        ? "opacity-50 cursor-not-allowed"
                        : "hover:bg-accent"
                    }`}
                    data-testid={`catalog-picker-item-${item.item_id}`}
                  >
                    <CardContent className="p-3">
                      <div className="flex items-center gap-3">
                        {/* Thumbnail */}
                        <div className="w-12 h-12 rounded bg-muted flex items-center justify-center shrink-0 overflow-hidden">
                          {item.image_urls && item.image_urls.length > 0 ? (
                            <img
                              src={item.image_urls[0]}
                              alt={item.name}
                              className="w-full h-full object-cover"
                            />
                          ) : (
                            <Package className="h-5 w-5 text-muted-foreground" />
                          )}
                        </div>

                        {/* Info */}
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate">{item.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {formatPrice(item.price_cents, item.currency)}
                          </p>
                        </div>

                        {/* Action */}
                        {alreadyAdded ? (
                          <div className="flex items-center gap-1 text-xs text-muted-foreground">
                            <Check className="h-3 w-3" /> Added
                          </div>
                        ) : (
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-7 text-xs shrink-0"
                            onClick={() => onSelect(selectedCategoryId, item)}
                            data-testid={`pick-item-${item.item_id}`}
                          >
                            Add
                          </Button>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}
