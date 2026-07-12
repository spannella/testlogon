import { useMemo, useState } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { AvailabilityBadge } from "./AvailabilityBadge";
import {
  formatCents,
  type CatalogItem,
  type StorefrontVariant,
} from "@/api/endpoints/storeIntegration";

interface Props {
  item: CatalogItem;
}

/**
 * Storefront product card with a variant picker + live availability badge.
 * Reads the ECM-enriched CatalogItem (variants / availability).
 */
export function ProductCard({ item }: Props) {
  const variants = item.variants ?? [];
  const [selectedVariantId, setSelectedVariantId] = useState<string>(
    variants[0]?.variant_id ?? "",
  );

  const selectedVariant: StorefrontVariant | undefined = useMemo(
    () => variants.find((v) => v.variant_id === selectedVariantId),
    [variants, selectedVariantId],
  );

  const effectivePriceCents = selectedVariant?.price_cents ?? item.price_cents;
  // Variant availability overrides the parent item availability when present.
  const availability = selectedVariant?.availability ?? item.availability;
  const soldOut = availability ? availability.available <= 0 : item.stock_status === "out_of_stock";

  return (
    <Card data-testid="product-card" className="flex flex-col">
      <CardHeader>
        <CardTitle className="text-base">{item.name}</CardTitle>
        {item.description ? (
          <p className="text-sm text-muted-foreground line-clamp-2">{item.description}</p>
        ) : null}
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-3">
        {item.image_urls?.[0] ? (
          <img
            src={item.image_urls[0]}
            alt={item.name}
            className="h-32 w-full rounded-md object-cover"
            loading="lazy"
          />
        ) : (
          <div className="flex h-32 w-full items-center justify-center rounded-md bg-muted text-xs text-muted-foreground">
            No image
          </div>
        )}

        {variants.length > 0 ? (
          <div className="space-y-1">
            <Label className="text-xs">Variant</Label>
            <Select value={selectedVariantId} onValueChange={setSelectedVariantId}>
              <SelectTrigger data-testid="variant-picker">
                <SelectValue placeholder="Select a variant" />
              </SelectTrigger>
              <SelectContent>
                {variants.map((v) => (
                  <SelectItem key={v.variant_id} value={v.variant_id}>
                    {Object.entries(v.option_selections)
                      .map(([k, val]) => `${k}: ${String(val)}`)
                      .join(", ") || v.sku}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {selectedVariant ? (
              <p className="text-xs text-muted-foreground">SKU: {selectedVariant.sku}</p>
            ) : null}
          </div>
        ) : null}

        <div className="mt-auto flex items-end justify-between gap-2">
          <div>
            <p className="text-lg font-semibold" data-testid="product-price">
              {formatCents(effectivePriceCents, item.currency)}
            </p>
            <AvailabilityBadge
              availability={availability}
              stockStatus={item.stock_status}
              stockCount={item.stock_count}
            />
          </div>
          <Button size="sm" disabled={soldOut} data-testid="add-to-cart">
            {soldOut ? "Sold out" : "Add to cart"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
