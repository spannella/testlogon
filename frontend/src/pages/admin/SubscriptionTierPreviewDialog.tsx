import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Check } from "lucide-react";
import type { SubscriptionTierPreviewItem } from "@/api/types";

export interface SubscriptionTierPreviewDialogProps {
  open: boolean;
  tiers: SubscriptionTierPreviewItem[];
  onClose: () => void;
}

function formatCurrency(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function SubscriptionTierPreviewDialog({
  open,
  tiers,
  onClose,
}: SubscriptionTierPreviewDialogProps) {
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle>Subscriber Preview</DialogTitle>
        </DialogHeader>
        {tiers.length === 0 ? (
          <p className="text-sm text-muted-foreground">No active tiers to preview.</p>
        ) : (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {tiers.map((tier) => (
              <Card key={tier.tier_id} data-testid="tier-preview-card">
                <CardHeader>
                  <CardTitle className="text-base">{tier.name}</CardTitle>
                  <p className="text-sm text-muted-foreground">
                    {formatCurrency(tier.price_cents)} / {tier.billing_cycle}
                  </p>
                  <Badge variant="secondary" className="w-fit">
                    {tier.access_level}
                  </Badge>
                </CardHeader>
                <CardContent>
                  {tier.description && (
                    <p className="mb-2 text-sm">{tier.description}</p>
                  )}
                  <ul className="space-y-1">
                    {tier.benefits.map((b, idx) => (
                      <li key={`${b}-${idx}`} className="flex items-center gap-2 text-sm">
                        <Check className="h-4 w-4 text-green-500" />
                        {b}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
