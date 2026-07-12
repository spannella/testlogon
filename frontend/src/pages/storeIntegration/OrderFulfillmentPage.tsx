import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { Package, Truck } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import {
  getOrderFulfillment,
  type ShipGroupFulfillment,
} from "@/api/endpoints/storeIntegration";

function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function statusVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  if (status === "delivered" || status === "shipped") return "default";
  if (status === "pending") return "outline";
  return "secondary";
}

function ShipGroupCard({ group }: { group: ShipGroupFulfillment }) {
  return (
    <Card data-testid="ship-group">
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Package className="h-4 w-4" />
          {group.ship_group_id}
        </CardTitle>
        <Badge variant={statusVariant(group.status)}>{group.status}</Badge>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <div className="grid grid-cols-2 gap-2">
          <div>
            <p className="text-xs text-muted-foreground">Carrier</p>
            <p>{group.carrier ?? "—"}</p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Tracking</p>
            <p className="flex items-center gap-1">
              {group.tracking_number ? (
                <>
                  <Truck className="h-3.5 w-3.5" />
                  <span data-testid="tracking-number">{group.tracking_number}</span>
                </>
              ) : (
                "—"
              )}
            </p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Shipped</p>
            <p>{fmtTs(group.shipped_at)}</p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Est. delivery</p>
            <p>{group.estimated_delivery ?? "—"}</p>
          </div>
        </div>
        {group.items.length > 0 ? (
          <div>
            <p className="text-xs text-muted-foreground">Items</p>
            <p>{group.items.join(", ")}</p>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

export default function OrderFulfillmentPage() {
  const params = useParams<{ orderId?: string }>();
  const [orderInput, setOrderInput] = useState(params.orderId ?? "");
  const [orderId, setOrderId] = useState(params.orderId ?? "");

  const query = useQuery({
    queryKey: ["storefront", "order-fulfillment", orderId],
    queryFn: () => getOrderFulfillment(orderId),
    enabled: !!orderId,
    retry: false,
  });

  const data = query.data;
  const notEnabled =
    query.error instanceof ApiError &&
    (query.error.status === 404 || query.error.status === 503);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Order Fulfillment"
        description="Track ship groups, carriers and tracking numbers for an order."
      />

      <Card>
        <CardContent className="flex flex-col gap-2 pt-6 sm:flex-row">
          <Input
            placeholder="Enter order ID"
            value={orderInput}
            onChange={(e) => setOrderInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") setOrderId(orderInput.trim());
            }}
            data-testid="order-id-input"
          />
          <Button onClick={() => setOrderId(orderInput.trim())} data-testid="track-order">
            Track order
          </Button>
        </CardContent>
      </Card>

      {!orderId ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            Enter an order ID above to view its fulfillment status.
          </CardContent>
        </Card>
      ) : query.isLoading ? (
        <Skeleton className="h-48 w-full" />
      ) : notEnabled ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            Fulfillment tracking is not enabled.
          </CardContent>
        </Card>
      ) : query.isError ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-destructive">
            {(query.error as ApiError)?.detail ?? "Could not load this order."}
          </CardContent>
        </Card>
      ) : data ? (
        <div className="space-y-4">
          <Card data-testid="order-summary">
            <CardHeader>
              <CardTitle className="text-base">Order {data.order_id}</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-6 text-sm">
              <div>
                <p className="text-xs text-muted-foreground">Lifecycle</p>
                <Badge variant="outline">{data.lifecycle_status ?? "unknown"}</Badge>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Fulfillment</p>
                <Badge variant={statusVariant(data.fulfillment_status ?? "")}>
                  {data.fulfillment_status ?? "unknown"}
                </Badge>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Tracking numbers</p>
                <p>{data.tracking_numbers.length > 0 ? data.tracking_numbers.join(", ") : "—"}</p>
              </div>
            </CardContent>
          </Card>

          {data.ship_groups.length > 0 ? (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {data.ship_groups.map((g) => (
                <ShipGroupCard key={g.ship_group_id} group={g} />
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="py-8 text-center text-sm text-muted-foreground">
                No ship groups for this order yet.
              </CardContent>
            </Card>
          )}
        </div>
      ) : null}
    </div>
  );
}
