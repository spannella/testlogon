import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShoppingCart, Package, ChevronRight, ChevronLeft } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  getShelfProducts,
  type ShelfItem,
} from "@/api/endpoints/broadcast-shelf";
import { createCart, addCartItem, getCarts } from "@/api/endpoints/cart";

// ─── Helpers ──────────────────────────────────────────────────────

function formatPrice(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format(cents / 100);
}

// ─── ProductShelfCard ─────────────────────────────────────────────

function ProductShelfCard({ item }: { item: ShelfItem }) {
  const [adding, setAdding] = useState(false);
  const [added, setAdded] = useState(false);

  const handleAddToCart = async () => {
    setAdding(true);
    try {
      // Get or create a cart
      let cartId: string;
      const carts = await getCarts();
      const firstCart = carts[0];
      if (firstCart) {
        cartId = firstCart.cart_id;
      } else {
        const newCart = await createCart();
        cartId = newCart.cart_id;
      }

      await addCartItem(cartId, {
        sku: item.item_id,
        name: item.name,
        quantity: 1,
        unit_price_cents: item.price_cents,
        image_url: item.image_url ?? undefined,
        item_id: item.item_id,
        category_id: item.category_id,
      });
      setAdded(true);
      toast.success(`Added "${item.name}" to cart`);
      setTimeout(() => setAdded(false), 2000);
    } catch {
      toast.error("Failed to add to cart");
    } finally {
      setAdding(false);
    }
  };

  return (
    <Card className="overflow-hidden" data-testid={`shelf-card-${item.item_id}`}>
      <CardContent className="p-3">
        <div className="flex gap-3">
          {/* Thumbnail */}
          <div className="w-16 h-16 rounded bg-muted flex items-center justify-center shrink-0 overflow-hidden">
            {item.image_url ? (
              <img
                src={item.image_url}
                alt={item.name}
                className="w-full h-full object-cover"
              />
            ) : (
              <Package className="h-6 w-6 text-muted-foreground" />
            )}
          </div>

          {/* Info */}
          <div className="flex-1 min-w-0 space-y-1">
            <p className="text-sm font-medium truncate" title={item.name}>
              {item.name}
            </p>
            <p className="text-sm font-semibold text-primary" aria-label={`Price: ${formatPrice(item.price_cents, item.currency)}`}>
              {formatPrice(item.price_cents, item.currency)}
            </p>
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs w-full"
              disabled={adding}
              onClick={handleAddToCart}
              aria-label={`Add ${item.name} to cart`}
              data-testid={`add-to-cart-${item.item_id}`}
            >
              <ShoppingCart className="h-3 w-3 mr-1" />
              {adding ? "Adding..." : added ? "Added!" : "Add to Cart"}
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── ProductShelf ─────────────────────────────────────────────────

interface ProductShelfProps {
  sessionId: string;
  isVisible: boolean;
  onToggle: () => void;
}

export function ProductShelf({ sessionId, isVisible, onToggle }: ProductShelfProps) {
  const [shelfItems, setShelfItems] = useState<ShelfItem[]>([]);

  const shelfQuery = useQuery({
    queryKey: ["broadcast-shelf", sessionId],
    queryFn: () => getShelfProducts(sessionId),
    staleTime: 30_000,
  });

  // Sync query data to local state
  useEffect(() => {
    if (shelfQuery.data) {
      setShelfItems(shelfQuery.data.items);
    }
  }, [shelfQuery.data]);

  // Listen for SSE shelf events via custom window events
  useEffect(() => {
    const handleShelfAdd = (e: Event) => {
      const item = (e as CustomEvent<ShelfItem>).detail;
      setShelfItems((prev) =>
        [...prev.filter((i) => i.item_id !== item.item_id), item].sort(
          (a, b) => a.display_order - b.display_order
        )
      );
    };

    const handleShelfRemove = (e: Event) => {
      const { item_id } = (e as CustomEvent<{ item_id: string }>).detail;
      setShelfItems((prev) => prev.filter((i) => i.item_id !== item_id));
    };

    const handleShelfReorder = (e: Event) => {
      const { items } = (e as CustomEvent<{ items: ShelfItem[] }>).detail;
      setShelfItems(items);
    };

    window.addEventListener("shelf:add", handleShelfAdd);
    window.addEventListener("shelf:remove", handleShelfRemove);
    window.addEventListener("shelf:reorder", handleShelfReorder);

    return () => {
      window.removeEventListener("shelf:add", handleShelfAdd);
      window.removeEventListener("shelf:remove", handleShelfRemove);
      window.removeEventListener("shelf:reorder", handleShelfReorder);
    };
  }, []);

  if (!isVisible) {
    return (
      <Button
        variant="ghost"
        size="sm"
        className="text-gray-400 hover:text-white text-xs"
        onClick={onToggle}
        data-testid="shelf-toggle"
        aria-expanded={false}
        aria-controls="product-shelf-panel"
      >
        <ShoppingCart className="h-3 w-3 mr-1" />
        Products
        {shelfItems.length > 0 && (
          <Badge variant="secondary" className="ml-1 h-4 px-1 text-[10px]">
            {shelfItems.length}
          </Badge>
        )}
        <ChevronLeft className="h-3 w-3 ml-1" />
      </Button>
    );
  }

  return (
    <div
      id="product-shelf-panel"
      className="w-full lg:w-72 h-64 lg:h-auto lg:max-h-[calc(100vh-8rem)] shrink-0 flex flex-col bg-gray-900/50 rounded-lg border border-gray-800"
      role="complementary"
      aria-label="Product shelf"
      data-testid="product-shelf-panel"
    >
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-gray-800">
        <div className="flex items-center gap-2">
          <ShoppingCart className="h-4 w-4 text-gray-400" />
          <span className="text-sm font-medium text-white">Products</span>
          <Badge variant="secondary" className="h-5 px-1.5 text-xs" data-testid="shelf-count-badge">
            {shelfItems.length}
          </Badge>
        </div>
        <Button
          variant="ghost"
          size="icon"
          className="h-6 w-6 text-gray-400 hover:text-white"
          onClick={onToggle}
          data-testid="shelf-toggle"
          aria-expanded={true}
          aria-controls="product-shelf-panel"
        >
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>

      {/* Content */}
      <ScrollArea className="flex-1 px-2 py-2">
        {shelfItems.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <Package className="h-8 w-8 text-gray-600 mb-2" />
            <p className="text-xs text-gray-500">No products on shelf yet</p>
          </div>
        ) : (
          <div className="space-y-2" aria-live="polite">
            {shelfItems.map((item) => (
              <ProductShelfCard key={item.item_id} item={item} />
            ))}
          </div>
        )}
      </ScrollArea>
    </div>
  );
}
