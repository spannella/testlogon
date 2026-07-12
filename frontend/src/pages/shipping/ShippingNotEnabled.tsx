import { Truck } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

export function ShippingNotEnabled() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
        <Truck className="h-10 w-10 text-muted-foreground" />
        <div>
          <p className="text-base font-medium">Shipping is not enabled</p>
          <p className="text-sm text-muted-foreground">
            The shipping &amp; logistics module is currently disabled on this
            platform. Enable the <code>SHIPPING_ENABLED</code> feature flag to
            manage carriers, rates, and shipments.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
