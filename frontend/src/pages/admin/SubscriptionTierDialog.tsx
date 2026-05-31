import { useEffect, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogFooter,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Plus, X } from "lucide-react";
import type {
  SubscriptionTierAccessLevel,
  SubscriptionTierBillingCycle,
  SubscriptionTierCreate,
  SubscriptionTierOut,
} from "@/api/types";

export interface SubscriptionTierDialogProps {
  open: boolean;
  tier: SubscriptionTierOut | null; // null = create mode
  onSave: (data: SubscriptionTierCreate) => void;
  onCancel: () => void;
  saving?: boolean;
}

const MAX_BENEFITS = 20;

export default function SubscriptionTierDialog({
  open,
  tier,
  onSave,
  onCancel,
  saving,
}: SubscriptionTierDialogProps) {
  const [name, setName] = useState("");
  const [priceDollars, setPriceDollars] = useState("9.99");
  const [billingCycle, setBillingCycle] = useState<SubscriptionTierBillingCycle>("monthly");
  const [description, setDescription] = useState("");
  const [accessLevel, setAccessLevel] = useState<SubscriptionTierAccessLevel>("basic");
  const [benefits, setBenefits] = useState<string[]>([]);
  const [benefitDraft, setBenefitDraft] = useState("");

  useEffect(() => {
    if (open) {
      setName(tier?.name ?? "");
      setPriceDollars(tier ? (tier.price_cents / 100).toFixed(2) : "9.99");
      setBillingCycle((tier?.billing_cycle as SubscriptionTierBillingCycle) ?? "monthly");
      setDescription(tier?.description ?? "");
      setAccessLevel((tier?.access_level as SubscriptionTierAccessLevel) ?? "basic");
      setBenefits(tier?.benefits ? [...tier.benefits] : []);
      setBenefitDraft("");
    }
  }, [open, tier]);

  const addBenefit = () => {
    const v = benefitDraft.trim();
    if (!v || benefits.length >= MAX_BENEFITS) return;
    setBenefits((prev) => [...prev, v]);
    setBenefitDraft("");
  };

  const removeBenefit = (idx: number) => {
    setBenefits((prev) => prev.filter((_, i) => i !== idx));
  };

  const handleSave = () => {
    const priceCents = Math.round(parseFloat(priceDollars || "0") * 100);
    onSave({
      name: name.trim(),
      price_cents: priceCents,
      billing_cycle: billingCycle,
      description: description.trim(),
      benefits,
      access_level: accessLevel,
    });
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onCancel()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{tier ? "Edit Tier" : "Create Tier"}</DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1">
            <Label htmlFor="tier-name">Name</Label>
            <Input
              id="tier-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Gold Tier"
              maxLength={100}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <Label htmlFor="tier-price">Price (USD)</Label>
              <Input
                id="tier-price"
                type="number"
                step="0.01"
                min="1"
                max="1000"
                value={priceDollars}
                onChange={(e) => setPriceDollars(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label>Billing Cycle</Label>
              <Select
                value={billingCycle}
                onValueChange={(v) => setBillingCycle(v as SubscriptionTierBillingCycle)}
              >
                <SelectTrigger aria-label="Billing cycle">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="monthly">Monthly</SelectItem>
                  <SelectItem value="quarterly">Quarterly</SelectItem>
                  <SelectItem value="yearly">Yearly</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-1">
            <Label htmlFor="tier-description">Description</Label>
            <Textarea
              id="tier-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Access to exclusive posts and early releases"
              maxLength={500}
            />
          </div>

          <div className="space-y-1">
            <Label>Access Level</Label>
            <Select
              value={accessLevel}
              onValueChange={(v) => setAccessLevel(v as SubscriptionTierAccessLevel)}
            >
              <SelectTrigger aria-label="Access level">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="basic">Basic</SelectItem>
                <SelectItem value="premium">Premium</SelectItem>
                <SelectItem value="vip">VIP</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>Benefits ({benefits.length}/{MAX_BENEFITS})</Label>
            <div className="flex gap-2">
              <Input
                value={benefitDraft}
                onChange={(e) => setBenefitDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    addBenefit();
                  }
                }}
                placeholder="Add a benefit"
                maxLength={200}
              />
              <Button
                type="button"
                variant="outline"
                onClick={addBenefit}
                disabled={!benefitDraft.trim() || benefits.length >= MAX_BENEFITS}
              >
                <Plus className="h-4 w-4" />
              </Button>
            </div>
            <ul className="space-y-1">
              {benefits.map((b, idx) => (
                <li
                  key={`${b}-${idx}`}
                  className="flex items-center justify-between rounded border px-2 py-1 text-sm"
                >
                  <span>{b}</span>
                  <button
                    type="button"
                    aria-label={`Remove benefit ${b}`}
                    onClick={() => removeBenefit(idx)}
                    className="text-muted-foreground hover:text-red-600"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onCancel} disabled={saving}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={saving || !name.trim()}>
            {saving ? "Saving…" : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
