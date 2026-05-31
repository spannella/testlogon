import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Package } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { listMyBundles, cancelBundleSubscription } from "@/api/endpoints/syndicates";
import type { BundleSubscriptionOut } from "@/api/types";

export default function MyBundlesPage() {
  const queryClient = useQueryClient();

  const { data: bundles = [] } = useQuery({
    queryKey: ["my-bundles"],
    queryFn: () => listMyBundles(),
  });

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center gap-3">
        <Package className="h-6 w-6" />
        <h1 className="text-2xl font-bold">My Bundles</h1>
      </div>
      <p className="text-muted-foreground">Manage your syndicate bundle subscriptions</p>

      {bundles.length === 0 ? (
        <Card>
          <CardContent className="py-8 text-center">
            <p className="text-muted-foreground">No active bundles</p>
            <Link to="/syndicates" className="text-sm text-primary hover:underline mt-2 inline-block">
              Browse syndicates to find bundles
            </Link>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {bundles.map((b: BundleSubscriptionOut) => (
            <BundleCard key={b.subscription_id} bundle={b} />
          ))}
        </div>
      )}
    </div>
  );
}

function BundleCard({ bundle }: { bundle: BundleSubscriptionOut }) {
  const [showCancel, setShowCancel] = useState(false);
  const queryClient = useQueryClient();

  const cancelMut = useMutation({
    mutationFn: () => cancelBundleSubscription(bundle.syndicate_id, bundle.subscription_id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["my-bundles"] });
      setShowCancel(false);
    },
  });

  const periodEnd = bundle.current_period_end
    ? new Date(bundle.current_period_end * 1000).toLocaleDateString()
    : "";
  const periodStart = bundle.current_period_start
    ? new Date(bundle.current_period_start * 1000).toLocaleDateString()
    : "";

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>
            <Link to={`/syndicates/${bundle.syndicate_id}`} className="hover:underline">
              {bundle.syndicate_name || bundle.syndicate_id}
            </Link>
          </CardTitle>
          <Badge variant={bundle.status === "active" ? "default" : "secondary"}>
            {bundle.status}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-2">
        <p className="text-lg font-medium">
          ${(bundle.price_cents / 100).toFixed(2)}/{bundle.interval}
        </p>
        {periodStart && periodEnd && (
          <p className="text-sm text-muted-foreground">
            Current period: {periodStart} - {periodEnd}
          </p>
        )}
        {bundle.included_creators && bundle.included_creators.length > 0 && (
          <div>
            <p className="text-sm font-medium mt-2">Included creators:</p>
            <div className="flex flex-wrap gap-2 mt-1">
              {bundle.included_creators.map((c) => (
                <Badge key={c.user_id} variant="outline">
                  {c.display_name || c.user_id}
                </Badge>
              ))}
            </div>
          </div>
        )}
      </CardContent>
      {bundle.status === "active" && (
        <CardFooter>
          <Button
            variant="outline"
            size="sm"
            className="text-destructive"
            onClick={() => setShowCancel(true)}
          >
            Cancel
          </Button>

          <Dialog open={showCancel} onOpenChange={setShowCancel}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Cancel Bundle Subscription</DialogTitle>
              </DialogHeader>
              <p className="text-sm text-muted-foreground">
                Your access will continue until the end of your current period
                {periodEnd ? ` (${periodEnd})` : ""}.
              </p>
              <DialogFooter>
                <Button variant="outline" onClick={() => setShowCancel(false)}>
                  Keep Subscription
                </Button>
                <Button
                  variant="destructive"
                  onClick={() => cancelMut.mutate()}
                  disabled={cancelMut.isPending}
                >
                  {cancelMut.isPending ? "Cancelling..." : "Confirm Cancel"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </CardFooter>
      )}
    </Card>
  );
}
