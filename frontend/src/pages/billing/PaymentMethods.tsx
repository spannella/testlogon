import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  CreditCard,
  Plus,
  Star,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { EmptyState } from "@/components/shared/EmptyState";
import {
  getPaymentMethods,
  createCardSetupIntent,
  setDefault,
  removePaymentMethod,
} from "@/api/endpoints/billing";
import type { PaymentMethod } from "@/api/types";

const BRAND_COLORS: Record<string, string> = {
  visa: "text-blue-600",
  mastercard: "text-orange-600",
  amex: "text-blue-800",
  discover: "text-orange-500",
};

function brandLabel(brand?: string): string {
  if (!brand) return "Card";
  return brand.charAt(0).toUpperCase() + brand.slice(1);
}

export function PaymentMethods() {
  const queryClient = useQueryClient();
  const [addOpen, setAddOpen] = useState(false);
  const [deleting, setDeleting] = useState<PaymentMethod | null>(null);
  const [setupLoading, setSetupLoading] = useState(false);

  const methodsQuery = useQuery({
    queryKey: ["billing", "payment-methods"],
    queryFn: getPaymentMethods,
  });

  const setupMutation = useMutation({
    mutationFn: () => createCardSetupIntent(),
    onSuccess: (data) => {
      // In production, you'd pass data.client_secret to Stripe.js confirmCardSetup
      toast.success(`Setup intent created: ${data.client_secret.slice(0, 15)}...`);
      setSetupLoading(false);
      setAddOpen(false);
      queryClient.invalidateQueries({ queryKey: ["billing", "payment-methods"] });
    },
    onError: () => {
      toast.error("Failed to create setup intent");
      setSetupLoading(false);
    },
  });

  const defaultMutation = useMutation({
    mutationFn: (id: string) => setDefault({ payment_method_id: id }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["billing", "payment-methods"] });
      toast.success("Default payment method updated");
    },
    onError: () => {
      toast.error("Failed to set default method");
    },
  });

  const removeMutation = useMutation({
    mutationFn: (id: string) => removePaymentMethod(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["billing", "payment-methods"] });
      setDeleting(null);
      toast.success("Payment method removed");
    },
    onError: () => {
      toast.error("Failed to remove payment method");
    },
  });

  const methods: PaymentMethod[] = Array.isArray(methodsQuery.data) ? methodsQuery.data : [];

  if (methodsQuery.isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-20 w-full rounded-xl" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {methods.length} payment method{methods.length !== 1 ? "s" : ""} saved
        </p>
        <Button variant="outline" size="sm" onClick={() => setAddOpen(true)}>
          <Plus className="mr-1 h-3.5 w-3.5" />
          Add Card
        </Button>
      </div>

      {methods.length === 0 ? (
        <EmptyState
          icon={<CreditCard className="h-8 w-8" />}
          title="No payment methods"
          description="Add a payment method to get started"
          className="py-16"
        />
      ) : (
        <div className="space-y-3">
          {methods.map((method) => (
            <Card key={method.payment_method_id}>
              <CardContent className="flex items-center gap-4 p-4">
                <div className={`shrink-0 ${BRAND_COLORS[method.brand ?? ""] ?? "text-muted-foreground"}`}>
                  <CreditCard className="h-8 w-8" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold">
                      {brandLabel(method.brand)}
                    </span>
                    <span className="text-sm text-muted-foreground">
                      •••• {method.last4 ?? "????"}
                    </span>
                    {method.is_default && (
                      <Badge variant="secondary" className="text-[10px]">
                        Default
                      </Badge>
                    )}
                  </div>
                  <div className="mt-0.5 flex items-center gap-3 text-xs text-muted-foreground">
                    {method.exp_month != null && method.exp_year != null && (
                      <span>
                        Expires {String(method.exp_month).padStart(2, "0")}/{method.exp_year}
                      </span>
                    )}
                    {method.label && <span>{method.label}</span>}
                    {method.method_type && (
                      <span className="capitalize">{method.method_type}</span>
                    )}
                  </div>
                </div>
                <div className="flex shrink-0 gap-1">
                  {!method.is_default && (
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      title="Set as default"
                      onClick={() => defaultMutation.mutate(method.payment_method_id)}
                      disabled={defaultMutation.isPending}
                    >
                      <Star className="h-3.5 w-3.5" />
                    </Button>
                  )}
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 text-destructive"
                    title="Remove"
                    onClick={() => setDeleting(method)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Add card dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Payment Method</DialogTitle>
            <DialogDescription>
              Enter your card details to add a new payment method.
            </DialogDescription>
          </DialogHeader>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              setSetupLoading(true);
              setupMutation.mutate();
            }}
            className="space-y-4 py-2"
          >
            <div className="space-y-1.5">
              <Label htmlFor="card-number">Card Number</Label>
              <Input id="card-number" placeholder="4242 4242 4242 4242" />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="card-expiry">Expiry</Label>
                <Input id="card-expiry" placeholder="MM / YY" />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="card-cvc">CVC</Label>
                <Input id="card-cvc" placeholder="123" />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              In production, this form would use Stripe Elements for PCI-compliant card collection.
            </p>
            <DialogFooter>
              <Button type="submit" disabled={setupLoading}>
                {setupLoading ? "Processing..." : "Add Card"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation */}
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(open) => { if (!open) setDeleting(null); }}
        title="Remove Payment Method"
        description={`Remove ${brandLabel(deleting?.brand)} ending in ${deleting?.last4 ?? "????"}?`}
        confirmLabel="Remove"
        variant="danger"
        onConfirm={() => {
          if (deleting) removeMutation.mutate(deleting.payment_method_id);
        }}
        loading={removeMutation.isPending}
      />
    </div>
  );
}
