import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Tag, Plus, BarChart3 } from "lucide-react";
import { toast } from "sonner";

import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";

import {
  listPromoCodes,
  createPromoCode,
  deletePromoCode,
  getPromoCodeStats,
} from "@/api/endpoints/promoCodes";
import type { PromoCodeOut, PromoCodeStatsOut } from "@/api/types";

function discountLabel(code: PromoCodeOut): string {
  if (code.discount_type === "percentage") return `${code.discount_value}% off`;
  if (code.discount_type === "fixed_amount")
    return `$${(code.discount_value / 100).toFixed(2)} off`;
  if (code.discount_type === "free_trial")
    return `${code.free_trial_days}-day trial`;
  return code.discount_type;
}

function isExpired(code: PromoCodeOut): boolean {
  return code.expires_at > 0 && code.expires_at < Date.now() / 1000;
}

function formatDate(ts: number): string {
  if (!ts) return "Never";
  return new Date(ts * 1000).toLocaleDateString();
}

export default function PromoCodesPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [statsCode, setStatsCode] = useState<PromoCodeOut | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["promo-codes", "list"],
    queryFn: () => listPromoCodes(),
    staleTime: 30_000,
  });

  const deleteMut = useMutation({
    mutationFn: (codeId: string) => deletePromoCode(codeId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["promo-codes", "list"] });
      toast.success("Promo code deactivated");
    },
  });

  const codes = data?.items ?? [];

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-4 md:p-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Tag className="h-6 w-6" />
          <h1 className="text-2xl font-bold">Promo Codes</h1>
        </div>
        <Button onClick={() => setShowCreate(true)} data-testid="create-promo-btn">
          <Plus className="mr-2 h-4 w-4" />
          Create Code
        </Button>
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-8 text-center text-muted-foreground">Loading...</div>
          ) : codes.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground">
              No promo codes yet. Create your first one!
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm" data-testid="promo-codes-table">
                <thead>
                  <tr className="border-b bg-muted/50">
                    <th className="px-4 py-3 text-left font-medium">Code</th>
                    <th className="px-4 py-3 text-left font-medium">Type</th>
                    <th className="px-4 py-3 text-left font-medium">Usage</th>
                    <th className="px-4 py-3 text-left font-medium">Status</th>
                    <th className="px-4 py-3 text-left font-medium">Expires</th>
                    <th className="px-4 py-3 text-left font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {codes.map((c) => (
                    <tr key={c.code_id} className="border-b" data-testid={`promo-row-${c.code}`}>
                      <td className="px-4 py-3">
                        <Badge variant="secondary">{c.code}</Badge>
                      </td>
                      <td className="px-4 py-3">{discountLabel(c)}</td>
                      <td className="px-4 py-3">
                        {c.current_uses}/{c.max_uses || "∞"}
                      </td>
                      <td className="px-4 py-3">
                        {!c.active ? (
                          <Badge variant="destructive">Inactive</Badge>
                        ) : isExpired(c) ? (
                          <Badge variant="outline">Expired</Badge>
                        ) : (
                          <Badge variant="default">Active</Badge>
                        )}
                      </td>
                      <td className="px-4 py-3">{formatDate(c.expires_at)}</td>
                      <td className="px-4 py-3 space-x-1">
                        {c.active && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => deleteMut.mutate(c.code_id)}
                            data-testid={`deactivate-${c.code}`}
                          >
                            Deactivate
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setStatsCode(c)}
                          data-testid={`stats-${c.code}`}
                        >
                          <BarChart3 className="mr-1 h-3 w-3" />
                          Stats
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <CreatePromoDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={() => {
          setShowCreate(false);
          qc.invalidateQueries({ queryKey: ["promo-codes", "list"] });
        }}
      />

      {statsCode && (
        <StatsDialog
          code={statsCode}
          open={!!statsCode}
          onClose={() => setStatsCode(null)}
        />
      )}
    </div>
  );
}

// ─── Create Dialog ───────────────────────────────────────────────

function CreatePromoDialog({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [code, setCode] = useState("");
  const [discountType, setDiscountType] = useState<"percentage" | "fixed_amount" | "free_trial">("percentage");
  const [discountValue, setDiscountValue] = useState(10);
  const [freeDays, setFreeDays] = useState(7);
  const [applySub, setApplySub] = useState(true);
  const [applyVod, setApplyVod] = useState(false);
  const [applyShop, setApplyShop] = useState(false);
  const [maxUses, setMaxUses] = useState(0);
  const [maxPerUser, setMaxPerUser] = useState(1);
  const [minPurchase, setMinPurchase] = useState(0);

  const createMut = useMutation({
    mutationFn: () => {
      const applies_to: string[] = [];
      if (applySub) applies_to.push("subscription");
      if (applyVod) applies_to.push("vod");
      if (applyShop) applies_to.push("shop");
      return createPromoCode({
        code: code.toUpperCase(),
        discount_type: discountType,
        discount_value: discountType === "free_trial" ? 0 : discountValue,
        free_trial_days: discountType === "free_trial" ? freeDays : 0,
        applies_to: applies_to.length > 0 ? applies_to : ["subscription"],
        max_uses: maxUses,
        max_uses_per_user: maxPerUser,
        min_purchase_cents: minPurchase,
      });
    },
    onSuccess: () => {
      toast.success("Promo code created");
      onCreated();
      setCode("");
    },
    onError: (err: any) => {
      const detail = err?.response?.data?.detail || "Failed to create code";
      toast.error(detail);
    },
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-md" data-testid="create-promo-dialog">
        <DialogHeader>
          <DialogTitle>Create Promo Code</DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div>
            <Label>Code</Label>
            <Input
              value={code}
              onChange={(e) => setCode(e.target.value.toUpperCase())}
              placeholder="SUMMER25"
              data-testid="promo-code-input"
            />
          </div>

          <div>
            <Label>Discount Type</Label>
            <Select value={discountType} onValueChange={(v: any) => setDiscountType(v)}>
              <SelectTrigger data-testid="discount-type-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="percentage">Percentage off</SelectItem>
                <SelectItem value="fixed_amount">Fixed amount off</SelectItem>
                <SelectItem value="free_trial">Free trial</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {discountType !== "free_trial" && (
            <div>
              <Label>{discountType === "percentage" ? "Percent off" : "Amount off (cents)"}</Label>
              <Input
                type="number"
                value={discountValue}
                onChange={(e) => setDiscountValue(Number(e.target.value))}
                data-testid="discount-value-input"
              />
            </div>
          )}

          {discountType === "free_trial" && (
            <div>
              <Label>Free trial days</Label>
              <Input
                type="number"
                value={freeDays}
                onChange={(e) => setFreeDays(Number(e.target.value))}
                data-testid="free-trial-days-input"
              />
            </div>
          )}

          <div>
            <Label>Applies to</Label>
            <div className="mt-1 flex gap-4">
              <label className="flex items-center gap-1.5 text-sm">
                <Checkbox checked={applySub} onCheckedChange={(v) => setApplySub(!!v)} />
                Subscriptions
              </label>
              <label className="flex items-center gap-1.5 text-sm">
                <Checkbox checked={applyVod} onCheckedChange={(v) => setApplyVod(!!v)} />
                VOD
              </label>
              <label className="flex items-center gap-1.5 text-sm">
                <Checkbox checked={applyShop} onCheckedChange={(v) => setApplyShop(!!v)} />
                Shop
              </label>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label>Max uses (0=unlimited)</Label>
              <Input
                type="number"
                value={maxUses}
                onChange={(e) => setMaxUses(Number(e.target.value))}
                data-testid="max-uses-input"
              />
            </div>
            <div>
              <Label>Max per user</Label>
              <Input
                type="number"
                value={maxPerUser}
                onChange={(e) => setMaxPerUser(Number(e.target.value))}
                data-testid="max-per-user-input"
              />
            </div>
          </div>

          <div>
            <Label>Min purchase (cents, 0=none)</Label>
            <Input
              type="number"
              value={minPurchase}
              onChange={(e) => setMinPurchase(Number(e.target.value))}
              data-testid="min-purchase-input"
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            onClick={() => createMut.mutate()}
            disabled={createMut.isPending || !code.trim()}
            data-testid="submit-promo-btn"
          >
            {createMut.isPending ? "Creating..." : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Stats Dialog ────────────────────────────────────────────────

function StatsDialog({
  code,
  open,
  onClose,
}: {
  code: PromoCodeOut;
  open: boolean;
  onClose: () => void;
}) {
  const { data, isLoading } = useQuery({
    queryKey: ["promo-codes", code.code_id, "stats"],
    queryFn: () => getPromoCodeStats(code.code_id),
    enabled: open,
    staleTime: 60_000,
  });

  const stats = (data as PromoCodeStatsOut | undefined)?.stats;

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent data-testid="promo-stats-dialog">
        <DialogHeader>
          <DialogTitle>Stats: {code.code}</DialogTitle>
        </DialogHeader>

        {isLoading ? (
          <div className="py-4 text-center text-muted-foreground">Loading...</div>
        ) : stats ? (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <Card>
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold">{stats.total_redemptions}</div>
                  <div className="text-xs text-muted-foreground">Total redemptions</div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold">
                    ${(stats.total_discount_cents / 100).toFixed(2)}
                  </div>
                  <div className="text-xs text-muted-foreground">Total discount given</div>
                </CardContent>
              </Card>
            </div>

            {stats.redemptions.length > 0 && (
              <div className="max-h-48 overflow-y-auto rounded border">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b bg-muted/50">
                      <th className="px-2 py-1.5 text-left">User</th>
                      <th className="px-2 py-1.5 text-left">Discount</th>
                      <th className="px-2 py-1.5 text-left">Type</th>
                      <th className="px-2 py-1.5 text-left">Date</th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.redemptions.map((r, i) => (
                      <tr key={i} className="border-b">
                        <td className="px-2 py-1.5 font-mono text-xs">{r.user_id.slice(0, 12)}...</td>
                        <td className="px-2 py-1.5">${(r.discount_applied_cents / 100).toFixed(2)}</td>
                        <td className="px-2 py-1.5">{r.checkout_type}</td>
                        <td className="px-2 py-1.5">{formatDate(r.redeemed_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        ) : (
          <div className="py-4 text-center text-muted-foreground">No stats available</div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
