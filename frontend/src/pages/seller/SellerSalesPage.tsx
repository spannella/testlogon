import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Store, PackageOpen, Truck, DollarSign, ShoppingBag, TrendingUp, AlertCircle } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ApiError } from "@/api/client";
import {
  listSellerSales,
  getSellerAnalytics,
  isOpenFulfilment,
  prettySellerStatus,
  type SellerSaleListOut,
  type SellerAnalytics,
} from "@/api/endpoints/sellerSales";
import { formatCents } from "@/api/endpoints/orderLifecycle";

function statusVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  const s = status.toLowerCase();
  if (s === "shipped" || s === "completed") return "default";
  if (s === "cancelled" || s === "returned") return "destructive";
  if (isOpenFulfilment(status)) return "secondary";
  return "outline";
}

export default function SellerSalesPage() {
  const salesQuery = useQuery<SellerSaleListOut, ApiError>({
    queryKey: ["seller-sales", "list"],
    queryFn: () => listSellerSales({ limit: 100 }),
    retry: false,
  });
  const analyticsQuery = useQuery<SellerAnalytics, ApiError>({
    queryKey: ["seller-sales", "analytics"],
    queryFn: () => getSellerAnalytics(),
    retry: false,
  });

  const sales = useMemo(() => salesQuery.data?.sales ?? [], [salesQuery.data]);
  const a = analyticsQuery.data;

  const disabled = salesQuery.error?.status === 503;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Seller Dashboard"
        description="Your received sales — fulfil orders and enter tracking."
        actions={
          <Button asChild variant="outline" size="sm">
            <Link to="/shop/admin/shipping">Shipping settings</Link>
          </Button>
        }
      />

      {/* Analytics summary */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-1.5">
              <DollarSign className="h-3.5 w-3.5" /> GMV (MTD)
            </CardDescription>
            <CardTitle className="text-xl" data-testid="seller-gmv">
              {analyticsQuery.isLoading ? (
                <Skeleton className="h-6 w-24" />
              ) : (
                formatCents(a?.gmv_cents ?? 0, a?.currency)
              )}
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-1.5">
              <ShoppingBag className="h-3.5 w-3.5" /> Units · Orders
            </CardDescription>
            <CardTitle className="text-xl">
              {analyticsQuery.isLoading ? (
                <Skeleton className="h-6 w-16" />
              ) : (
                `${a?.units ?? 0} · ${a?.order_count ?? 0}`
              )}
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-1.5">
              <TrendingUp className="h-3.5 w-3.5" /> Avg order value
            </CardDescription>
            <CardTitle className="text-xl">
              {analyticsQuery.isLoading ? (
                <Skeleton className="h-6 w-20" />
              ) : (
                formatCents(a?.aov_cents ?? 0, a?.currency)
              )}
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-1.5">
              <PackageOpen className="h-3.5 w-3.5" /> To fulfil
            </CardDescription>
            <CardTitle className="text-xl" data-testid="seller-open-fulfilment">
              {analyticsQuery.isLoading ? (
                <Skeleton className="h-6 w-10" />
              ) : (
                a?.open_fulfilment_count ?? 0
              )}
            </CardTitle>
          </CardHeader>
        </Card>
      </div>

      {/* Sales table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Store className="h-4 w-4" />
            Your sales
          </CardTitle>
          <CardDescription>Each row is a shipment you owe a buyer.</CardDescription>
        </CardHeader>
        <CardContent>
          {salesQuery.isLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : salesQuery.isError ? (
            <EmptyState
              icon={<AlertCircle className="h-7 w-7" />}
              title={disabled ? "Sales are not enabled here" : "Unable to load your sales"}
              description={
                disabled
                  ? "The order-lifecycle / seller fulfilment feature is off on this environment."
                  : salesQuery.error?.message || "Something went wrong loading your sales."
              }
              action={disabled ? undefined : { label: "Retry", onClick: () => void salesQuery.refetch() }}
            />
          ) : sales.length === 0 ? (
            <EmptyState
              icon={<ShoppingBag className="h-7 w-7" />}
              title="No sales yet"
              description="When a buyer purchases one of your items, the order will appear here for you to fulfil."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Buyer</TableHead>
                  <TableHead>Items</TableHead>
                  <TableHead className="text-right">Subtotal</TableHead>
                  <TableHead>Tracking</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sales.map((s) => {
                  const firstName = s.line_items[0]?.name || `${s.item_count} items`;
                  const extra = s.line_items.length > 1 ? ` +${s.line_items.length - 1}` : "";
                  return (
                    <TableRow key={s.ship_group_id} data-testid="seller-sale-row">
                      <TableCell className="font-medium">
                        {s.buyer_name || s.buyer_email || "Buyer"}
                      </TableCell>
                      <TableCell className="max-w-[240px] truncate" title={firstName}>
                        {firstName}
                        {extra}
                      </TableCell>
                      <TableCell className="text-right">
                        {formatCents(s.subtotal_cents, s.currency)}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {s.tracking_number
                          ? `${(s.carrier || "").toUpperCase()} ${s.tracking_number}`.trim()
                          : "—"}
                      </TableCell>
                      <TableCell>
                        <Badge variant={statusVariant(s.status)}>
                          {prettySellerStatus(s.status)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button asChild size="sm" variant={isOpenFulfilment(s.status) ? "default" : "outline"}>
                          <Link to={`/seller/sales/${encodeURIComponent(s.ship_group_id)}`}>
                            {isOpenFulfilment(s.status) ? (
                              <>
                                <Truck className="mr-1.5 h-3.5 w-3.5" />
                                Fulfil
                              </>
                            ) : (
                              "View"
                            )}
                          </Link>
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
