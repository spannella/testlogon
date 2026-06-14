import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  formatCents,
  getCartItems,
  getCartTotal,
  listCarts,
} from "@/api/endpoints/storeIntegration";

export default function CartPricingPage() {
  const [cartId, setCartId] = useState<string>("");

  const cartsQuery = useQuery({
    queryKey: ["storefront", "carts"],
    queryFn: () => listCarts(),
    retry: false,
  });

  useEffect(() => {
    const first = cartsQuery.data?.[0]?.cart_id;
    if (!cartId && first) setCartId(first);
  }, [cartsQuery.data, cartId]);

  const itemsQuery = useQuery({
    queryKey: ["storefront", "cart-items", cartId],
    queryFn: () => getCartItems(cartId),
    enabled: !!cartId,
    retry: false,
  });

  const totalQuery = useQuery({
    queryKey: ["storefront", "cart-total", cartId],
    queryFn: () => getCartTotal(cartId),
    enabled: !!cartId,
    retry: false,
  });

  const carts = cartsQuery.data ?? [];
  const items = itemsQuery.data?.items ?? [];
  const total = totalQuery.data;
  const breakdown = total?.pricing_breakdown ?? null;
  const currency = total?.currency ?? "USD";

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cart Pricing"
        description="Review line items, applied pricing rules and your final total."
        actions={
          carts.length > 0 ? (
            <Select value={cartId} onValueChange={setCartId}>
              <SelectTrigger className="w-64" data-testid="cart-picker">
                <SelectValue placeholder="Select a cart" />
              </SelectTrigger>
              <SelectContent>
                {carts.map((c) => (
                  <SelectItem key={c.cart_id} value={c.cart_id}>
                    {c.cart_id} ({c.status})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : null
        }
      />

      {cartsQuery.isLoading ? (
        <Skeleton className="h-64 w-full" />
      ) : carts.length === 0 ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            You have no carts yet.
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {/* Line items */}
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="text-base">Items</CardTitle>
            </CardHeader>
            <CardContent>
              {itemsQuery.isLoading ? (
                <Skeleton className="h-32 w-full" />
              ) : items.length === 0 ? (
                <p className="py-6 text-center text-sm text-muted-foreground">
                  This cart is empty.
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Item</TableHead>
                      <TableHead className="text-right">Qty</TableHead>
                      <TableHead className="text-right">Unit</TableHead>
                      <TableHead className="text-right">Line total</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((it) => (
                      <TableRow key={it.sku} data-testid="cart-line">
                        <TableCell>
                          <div className="font-medium">{it.name}</div>
                          <div className="text-xs text-muted-foreground">{it.sku}</div>
                        </TableCell>
                        <TableCell className="text-right">{it.quantity}</TableCell>
                        <TableCell className="text-right">
                          {formatCents(it.unit_price_cents, currency)}
                        </TableCell>
                        <TableCell className="text-right">
                          {formatCents(it.line_total_cents, currency)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          {/* Pricing breakdown panel */}
          <Card data-testid="pricing-breakdown-panel">
            <CardHeader>
              <CardTitle className="text-base">Pricing breakdown</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {totalQuery.isLoading ? (
                <Skeleton className="h-32 w-full" />
              ) : (
                <>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">Subtotal</span>
                    <span data-testid="subtotal">
                      {formatCents(
                        breakdown?.subtotal_cents ?? total?.total_cents ?? 0,
                        currency,
                      )}
                    </span>
                  </div>

                  {breakdown && breakdown.applied_rules.length > 0 ? (
                    <>
                      <Separator />
                      <div className="space-y-2">
                        <p className="text-xs font-medium uppercase text-muted-foreground">
                          Applied rules
                        </p>
                        {breakdown.applied_rules.map((rule) => (
                          <div
                            key={rule.rule_id}
                            className="flex items-start justify-between gap-2 text-sm"
                            data-testid="applied-rule"
                          >
                            <div className="flex flex-col">
                              <span>{rule.rule_name || rule.rule_id}</span>
                              <Badge variant="outline" className="mt-0.5 w-fit text-[10px]">
                                {rule.discount_type}
                              </Badge>
                            </div>
                            <span className="text-emerald-600 dark:text-emerald-400">
                              −{formatCents(rule.discount_cents, currency)}
                            </span>
                          </div>
                        ))}
                      </div>
                    </>
                  ) : breakdown ? (
                    <p className="text-xs text-muted-foreground">
                      No pricing rules applied to this cart.
                    </p>
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      Pricing rules are not enabled — showing the plain total.
                    </p>
                  )}

                  {breakdown && breakdown.discount_cents > 0 ? (
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Total discount</span>
                      <span
                        className="text-emerald-600 dark:text-emerald-400"
                        data-testid="total-discount"
                      >
                        −{formatCents(breakdown.discount_cents, currency)}
                      </span>
                    </div>
                  ) : null}

                  <Separator />
                  <div className="flex items-center justify-between text-base font-semibold">
                    <span>Final total</span>
                    <span data-testid="final-total">
                      {formatCents(
                        breakdown?.final_total_cents ?? total?.total_cents ?? 0,
                        currency,
                      )}
                    </span>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
