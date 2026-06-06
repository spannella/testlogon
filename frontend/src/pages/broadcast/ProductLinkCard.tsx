import { ShoppingCart, Tag, Zap } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { ChatProductLink } from "@/api/endpoints/broadcast-chat";

// GAP-0289 (LCOM-002) — renders a kind="product_link" chat message as a
// rich product card with price, optional broadcast-discount badge, and a
// "Buy Now" action that opens the catalog item.

interface ProductLinkCardProps {
  sessionId: string;
  productLink: ChatProductLink;
}

export function ProductLinkCard({ sessionId, productLink }: ProductLinkCardProps) {
  // The HTTP response omits the pricing snapshot, so fall back to price_cents.
  const effectiveCents = productLink.effective_price_cents ?? productLink.price_cents;
  const displayPrice = (effectiveCents / 100).toFixed(2);
  const originalPrice = (productLink.price_cents / 100).toFixed(2);
  const hasDiscount =
    !!productLink.is_broadcast_price &&
    productLink.discount_pct != null &&
    productLink.discount_pct > 0 &&
    effectiveCents < productLink.price_cents;

  const handleBuy = () => {
    // Navigate to the catalog product page; checkout is handled there.
    window.open(
      `/shop?item=${encodeURIComponent(productLink.item_id)}&session=${encodeURIComponent(sessionId)}`,
      "_blank",
      "noopener,noreferrer",
    );
  };

  const currencySymbol = productLink.currency === "USD" ? "$" : `${productLink.currency} `;

  return (
    <Card
      className="my-1 mx-1 max-w-xs border border-primary/20 bg-primary/5"
      data-testid="product-link-card"
    >
      <CardContent className="p-2">
        <div className="flex gap-2">
          {productLink.image_url && (
            <img
              src={productLink.image_url}
              alt={productLink.name}
              className="h-14 w-14 rounded object-cover shrink-0"
              data-testid="product-link-image"
            />
          )}
          <div className="flex-1 min-w-0">
            <p
              className="text-xs font-semibold truncate"
              data-testid="product-link-name"
            >
              {productLink.name}
            </p>
            {productLink.description && (
              <p className="text-[10px] text-muted-foreground line-clamp-2">
                {productLink.description}
              </p>
            )}
            <div className="mt-1 flex items-center gap-1.5">
              <span
                className="text-xs font-bold text-primary"
                data-testid="product-link-price"
              >
                {currencySymbol}
                {displayPrice}
              </span>
              {hasDiscount && (
                <>
                  <span className="text-[10px] line-through text-muted-foreground">
                    {currencySymbol}
                    {originalPrice}
                  </span>
                  <Badge
                    variant="destructive"
                    className="text-[9px] px-1 py-0 h-4"
                    data-testid="product-link-discount"
                  >
                    <Zap className="h-2 w-2 mr-0.5" />
                    {productLink.discount_pct}% off
                  </Badge>
                </>
              )}
            </div>
          </div>
        </div>
        <Button
          size="sm"
          className="mt-2 w-full h-7 text-xs"
          onClick={handleBuy}
          data-testid="product-link-buy-btn"
        >
          <ShoppingCart className="mr-1 h-3 w-3" />
          Buy Now
        </Button>
        {productLink.is_broadcast_price && (
          <p className="mt-1 text-center text-[9px] text-amber-500 flex items-center justify-center gap-0.5">
            <Tag className="h-2.5 w-2.5" /> Live broadcast price
          </p>
        )}
      </CardContent>
    </Card>
  );
}
