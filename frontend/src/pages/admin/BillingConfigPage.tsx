import { useEffect, useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError } from "@/api/client";
import {
  getBillingConfig,
  updateBillingConfig,
  previewBillingConfig,
  getBillingConfigAudit,
} from "@/api/endpoints/billingConfig";
import type {
  BillingConfigOut,
  BillingConfigUpdate,
  BillingConfigPreview,
} from "@/api/types";

const FEE_FIELDS: Array<{ field: keyof BillingConfigOut; label: string }> = [
  { field: "fee_tips_bps", label: "Tips" },
  { field: "fee_unlocks_bps", label: "Unlocks" },
  { field: "fee_subscriptions_bps", label: "Subscriptions" },
  { field: "fee_catalog_bps", label: "Catalog" },
  { field: "fee_ad_revenue_bps", label: "Ad Revenue" },
];

const bpsToPct = (bps: number) => `${(bps / 100).toFixed(1)}%`;
const centsToDollars = (cents: number) => `$${(cents / 100).toFixed(2)}`;

export default function BillingConfigPage() {
  const qc = useQueryClient();
  const [form, setForm] = useState<BillingConfigUpdate>({});
  const [previewOpen, setPreviewOpen] = useState(false);
  const [preview, setPreview] = useState<BillingConfigPreview | null>(null);

  const { data: config } = useQuery({
    queryKey: ["billing-config"],
    queryFn: getBillingConfig,
  });

  const { data: audit } = useQuery({
    queryKey: ["billing-config", "audit"],
    queryFn: () => getBillingConfigAudit({ limit: 25 }),
  });

  // Seed the editable form from the loaded config.
  useEffect(() => {
    if (config) {
      setForm({
        fee_tips_bps: config.fee_tips_bps,
        fee_unlocks_bps: config.fee_unlocks_bps,
        fee_subscriptions_bps: config.fee_subscriptions_bps,
        fee_catalog_bps: config.fee_catalog_bps,
        fee_ad_revenue_bps: config.fee_ad_revenue_bps,
        min_payout_cents: config.min_payout_cents,
        payout_fee_cents: config.payout_fee_cents,
        payout_schedule: config.payout_schedule,
        auto_payout_enabled: config.auto_payout_enabled,
        min_deposit_cents: config.min_deposit_cents,
        max_deposit_cents: config.max_deposit_cents,
        deposit_fee_bps: config.deposit_fee_bps,
        tax_enabled: config.tax_enabled,
        default_tax_rate_bps: config.default_tax_rate_bps,
      });
    }
  }, [config]);

  const setField = (field: keyof BillingConfigUpdate, value: number | string | boolean) =>
    setForm((prev) => ({ ...prev, [field]: value }));

  const saveMut = useMutation({
    mutationFn: (data: BillingConfigUpdate) => updateBillingConfig(data),
    onSuccess: () => {
      toast.success("Billing configuration saved");
      qc.invalidateQueries({ queryKey: ["billing-config"] });
      setPreviewOpen(false);
    },
    onError: (e) => {
      const msg = e instanceof ApiError ? e.message : "Failed to save configuration";
      toast.error(msg);
    },
  });

  const previewMut = useMutation({
    mutationFn: (data: BillingConfigUpdate) => previewBillingConfig(data),
    onSuccess: (data) => {
      setPreview(data);
      setPreviewOpen(true);
    },
    onError: () => toast.error("Failed to generate preview"),
  });

  const numberField = (field: keyof BillingConfigUpdate): number =>
    typeof form[field] === "number" ? (form[field] as number) : 0;

  const lastUpdated = useMemo(() => {
    if (!config?.updated_at) return null;
    return new Date(config.updated_at * 1000).toLocaleString();
  }, [config]);

  return (
    <div className="space-y-6 p-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Billing Configuration</h1>
          <p className="text-sm text-muted-foreground">
            Root only — changes are live immediately
          </p>
        </div>
        {config?.updated_by && (
          <div className="text-right text-xs text-muted-foreground">
            <div>Last updated by {config.updated_by}</div>
            {lastUpdated && <div>{lastUpdated}</div>}
          </div>
        )}
      </div>

      {/* Platform Fees */}
      <Card>
        <CardHeader>
          <CardTitle>Platform Fees</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {FEE_FIELDS.map(({ field, label }) => (
              <div key={field} className="space-y-1">
                <Label htmlFor={field}>{label}</Label>
                <Input
                  id={field}
                  type="number"
                  min={0}
                  max={5000}
                  step={100}
                  value={numberField(field as keyof BillingConfigUpdate)}
                  onChange={(e) =>
                    setField(field as keyof BillingConfigUpdate, Number(e.target.value))
                  }
                />
                <p className="text-xs text-muted-foreground">
                  {bpsToPct(numberField(field as keyof BillingConfigUpdate))}
                </p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Payout Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Payout Settings</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div className="space-y-1">
            <Label htmlFor="min_payout_cents">Minimum Payout (cents)</Label>
            <Input
              id="min_payout_cents"
              type="number"
              min={0}
              value={numberField("min_payout_cents")}
              onChange={(e) => setField("min_payout_cents", Number(e.target.value))}
            />
            <p className="text-xs text-muted-foreground">
              {centsToDollars(numberField("min_payout_cents"))}
            </p>
          </div>
          <div className="space-y-1">
            <Label htmlFor="payout_fee_cents">Payout Fee (cents)</Label>
            <Input
              id="payout_fee_cents"
              type="number"
              min={0}
              value={numberField("payout_fee_cents")}
              onChange={(e) => setField("payout_fee_cents", Number(e.target.value))}
            />
          </div>
          <div className="space-y-1">
            <Label>Schedule</Label>
            <Select
              value={typeof form.payout_schedule === "string" ? form.payout_schedule : "weekly"}
              onValueChange={(v) => setField("payout_schedule", v)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="daily">Daily</SelectItem>
                <SelectItem value="weekly">Weekly</SelectItem>
                <SelectItem value="monthly">Monthly</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-center gap-2">
            <Switch
              id="auto_payout_enabled"
              checked={!!form.auto_payout_enabled}
              onCheckedChange={(v) => setField("auto_payout_enabled", v)}
            />
            <Label htmlFor="auto_payout_enabled">Auto-payout Enabled</Label>
          </div>
        </CardContent>
      </Card>

      {/* Deposit Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Deposit Settings</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <div className="space-y-1">
            <Label htmlFor="min_deposit_cents">Min Deposit (cents)</Label>
            <Input
              id="min_deposit_cents"
              type="number"
              min={0}
              value={numberField("min_deposit_cents")}
              onChange={(e) => setField("min_deposit_cents", Number(e.target.value))}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="max_deposit_cents">Max Deposit (cents)</Label>
            <Input
              id="max_deposit_cents"
              type="number"
              min={0}
              value={numberField("max_deposit_cents")}
              onChange={(e) => setField("max_deposit_cents", Number(e.target.value))}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="deposit_fee_bps">Deposit Fee (bps)</Label>
            <Input
              id="deposit_fee_bps"
              type="number"
              min={0}
              max={5000}
              value={numberField("deposit_fee_bps")}
              onChange={(e) => setField("deposit_fee_bps", Number(e.target.value))}
            />
          </div>
        </CardContent>
      </Card>

      {/* Tax Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Tax Settings</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div className="flex items-center gap-2">
            <Switch
              id="tax_enabled"
              checked={!!form.tax_enabled}
              onCheckedChange={(v) => setField("tax_enabled", v)}
            />
            <Label htmlFor="tax_enabled">Tax Collection Enabled</Label>
          </div>
          <div className="space-y-1">
            <Label htmlFor="default_tax_rate_bps">Default Tax Rate (bps)</Label>
            <Input
              id="default_tax_rate_bps"
              type="number"
              min={0}
              max={10000}
              disabled={!form.tax_enabled}
              value={numberField("default_tax_rate_bps")}
              onChange={(e) => setField("default_tax_rate_bps", Number(e.target.value))}
            />
          </div>
        </CardContent>
      </Card>

      <div className="flex gap-2">
        <Button variant="outline" onClick={() => previewMut.mutate(form)}>
          Preview Impact
        </Button>
        <Button onClick={() => saveMut.mutate(form)} disabled={saveMut.isPending}>
          Save Changes
        </Button>
      </div>

      {/* Change History */}
      <Card>
        <CardHeader>
          <CardTitle>Change History</CardTitle>
        </CardHeader>
        <CardContent>
          {audit && audit.entries.length > 0 ? (
            <ul className="space-y-3">
              {audit.entries.map((entry, i) => (
                <li key={i} className="border-b pb-2 text-sm">
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary">{entry.admin_sub}</Badge>
                    <span className="text-xs text-muted-foreground">
                      {new Date(entry.created_at * 1000).toLocaleString()}
                    </span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-2">
                    {entry.changes.map((c, j) => (
                      <span key={j} className="rounded bg-muted px-2 py-0.5 text-xs">
                        <span className="font-medium">{c.field}</span>{" "}
                        <span className="line-through opacity-60">{String(c.old_value)}</span>
                        {" → "}
                        <span className="font-semibold">{String(c.new_value)}</span>
                      </span>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted-foreground">No changes recorded yet.</p>
          )}
        </CardContent>
      </Card>

      {/* Impact Preview Dialog */}
      <Dialog open={previewOpen} onOpenChange={setPreviewOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Impact Preview</DialogTitle>
          </DialogHeader>
          {preview && (
            <div className="space-y-4">
              <div>
                <p className="text-sm font-medium">Affected Transaction Types</p>
                <div className="mt-1 flex flex-wrap gap-2">
                  {preview.affected_tx_types.length > 0 ? (
                    preview.affected_tx_types.map((t) => (
                      <Badge key={t} variant="outline">
                        {t}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-xs text-muted-foreground">None</span>
                  )}
                </div>
              </div>
              <div className="text-sm">
                Projected daily delta:{" "}
                <span className="font-semibold">
                  {centsToDollars(preview.projected_daily_delta_cents)}/day
                </span>
              </div>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div className="rounded border p-2">
                  <p className="font-medium">Before</p>
                  <p>Amount: {centsToDollars(preview.sample_before.amount_cents)}</p>
                  <p>Fee: {centsToDollars(preview.sample_before.fee_cents)}</p>
                  <p>Net: {centsToDollars(preview.sample_before.net_cents)}</p>
                </div>
                <div className="rounded border p-2">
                  <p className="font-medium">After</p>
                  <p>Amount: {centsToDollars(preview.sample_after.amount_cents)}</p>
                  <p>Fee: {centsToDollars(preview.sample_after.fee_cents)}</p>
                  <p>Net: {centsToDollars(preview.sample_after.net_cents)}</p>
                </div>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setPreviewOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => saveMut.mutate(form)} disabled={saveMut.isPending}>
              Confirm &amp; Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
