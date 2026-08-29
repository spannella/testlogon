import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
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
import { searchCatalogItems } from "@/api/endpoints/cart";
import type { CatalogItem } from "@/api/types";
import { ProductCard } from "./ProductCard";
import { buildProductCardPayload, type ProductCardPayload } from "@/lib/ecomCards";

interface ProductCardComposerDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (payload: ProductCardPayload) => void;
}

/**
 * FE-150: "Share product" composer. Searches the shop catalog
 * (searchCatalogItems -> /ui/catalog/items/search) and lets the caller pick a
 * product to share. Emits a ProductCardPayload; the caller POSTs via
 * sendProductCardMessage which degrades-on-404 to a normal product_card message.
 */
export function ProductCardComposerDialog({
  open,
  onClose,
  onSubmit,
}: ProductCardComposerDialogProps) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<CatalogItem | null>(null);

  const searchQ = useQuery({
    queryKey: ["catalog", "search", "productCard", query],
    queryFn: () => searchCatalogItems(query),
    enabled: open && query.trim().length > 0,
    retry: false,
  });

  const results = useMemo(
    () => (searchQ.data?.items ?? []).slice(0, 40),
    [searchQ.data],
  );

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
    onSubmit(buildProductCardPayload(selected));
    reset();
  }

  return (
    <Dialog open={open} onOpenChange={(o) => (!o ? handleClose() : undefined)}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Share product</DialogTitle>
        </DialogHeader>

        <div className="space-y-3">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              className="pl-8"
              placeholder="Search the catalog"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              aria-label="Search products"
              data-testid="product-composer-search"
            />
          </div>

          <div className="max-h-56 overflow-y-auto rounded-md border">
            {query.trim().length === 0 ? (
              <p className="p-3 text-sm text-muted-foreground">
                Type to search for a product.
              </p>
            ) : searchQ.isLoading ? (
              <p className="p-3 text-sm text-muted-foreground">Searching…</p>
            ) : results.length === 0 ? (
              <p className="p-3 text-sm text-muted-foreground">No matching products.</p>
            ) : (
              results.map((item) => (
                <button
                  key={item.item_id}
                  type="button"
                  onClick={() => setSelected(item)}
                  className={
                    "flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-sm hover:bg-accent " +
                    (selected?.item_id === item.item_id ? "bg-accent" : "")
                  }
                  data-testid={`product-composer-option-${item.item_id}`}
                >
                  <span className="min-w-0 truncate font-medium">{item.name}</span>
                  <span className="shrink-0 text-xs text-muted-foreground tabular-nums">
                    {new Intl.NumberFormat("en-US", {
                      style: "currency",
                      currency: item.currency || "USD",
                    }).format(item.price_cents / 100)}
                  </span>
                </button>
              ))
            )}
          </div>

          {selected && (
            <div className="flex justify-center pt-1">
              <ProductCard payload={buildProductCardPayload(selected)} />
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={handleClose}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={!selected} data-testid="product-composer-send">
            Share
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default ProductCardComposerDialog;
