import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Package, Bitcoin } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { getPaymentMethods } from "@/api/endpoints/billing";
import { formatPriceCents, type ProductCardPayload } from "@/lib/ecomCards";

export interface ProductCardProps {
  payload: ProductCardPayload;
  /**
   * Force the "pay with crypto" hint on/off. When omitted the card derives it
   * from the viewers payment methods (a crypto method on file shows the hint).
   */
  cryptoCheckout?: boolean;
}

/**
 * FE-150: an in-chat product card. Image + title + price + in-stock badge and a
 * Buy button that deep-links to the existing product detail route (BE-154) where
 * the caller can add-to-cart + check out. Pure presentation -- payload building
 * (incl. in_stock derivation) lives in lib/ecomCards.
 */
export function ProductCard({ payload, cryptoCheckout }: ProductCardProps) {
  const navigate = useNavigate();

  // The existing checkout pays via the viewers payment methods; surface the
  // "pay with crypto" hint when one of them is a crypto method (unless the
  // caller forces it). Reuses the billing read the checkout itself uses.
  const methodsQ = useQuery({
    queryKey: ["billing", "paymentMethods", "productCardHint"],
    queryFn: getPaymentMethods,
    enabled: cryptoCheckout === undefined,
    retry: false,
    staleTime: 60_000,
  });
  const hasCryptoMethod = (methodsQ.data ?? []).some((m) =>
    String(m.method_type ?? "").toLowerCase().includes("crypto"),
  );
  const showCryptoHint = cryptoCheckout ?? hasCryptoMethod;

  // Deep-link to the product detail page when we know the category; else fall
  // back to the shop catalog.
  const buyTo = payload.category_id
    ? `/shop/${encodeURIComponent(payload.category_id)}/${encodeURIComponent(payload.product_id)}`
    : "/shop";

  return (
    <Card className="w-72 max-w-full" data-testid="product-card">
      <CardContent className="pt-4">
        <div className="flex items-start gap-3">
          <div className="h-16 w-16 shrink-0 overflow-hidden rounded-md border bg-muted">
            {payload.image ? (
              // eslint-disable-next-line jsx-a11y/img-redundant-alt
              <img
                src={payload.image}
                alt={payload.title}
                className="h-full w-full object-cover"
                data-testid="product-card-image"
              />
            ) : (
              <div className="flex h-full w-full items-center justify-center text-muted-foreground">
                <Package className="h-6 w-6" />
              </div>
            )}
          </div>
          <div className="min-w-0 flex-1">
            <div
              className="line-clamp-2 text-sm font-semibold"
              data-testid="product-card-title"
            >
              {payload.title}
            </div>
            <div
              className="mt-1 text-lg font-bold tabular-nums"
              data-testid="product-card-price"
            >
              {formatPriceCents(payload.price_cents, payload.currency)}
            </div>
            <span
              className={cn(
                "mt-1 inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium",
                payload.in_stock
                  ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400"
                  : "bg-rose-500/15 text-rose-700 dark:text-rose-400",
              )}
              data-testid="product-card-stock"
            >
              {payload.in_stock ? "In stock" : "Out of stock"}
            </span>
          </div>
        </div>

        <Button
          size="sm"
          className="mt-3 w-full"
          disabled={!payload.in_stock}
          onClick={() => navigate(buyTo)}
          data-testid="product-card-buy"
        >
          Buy
        </Button>

        {showCryptoHint && (
          <p
            className="mt-2 flex items-center justify-center gap-1 text-[11px] text-muted-foreground"
            data-testid="product-card-crypto-hint"
          >
            <Bitcoin className="h-3 w-3" />
            Pay with crypto at checkout
          </p>
        )}
      </CardContent>
    </Card>
  );
}

export default ProductCard;
