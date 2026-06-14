import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Percent, Pencil, Plus, RefreshCw } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
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
  listCrmTaxRates,
  createCrmTaxRate,
  updateCrmTaxRate,
  formatBps,
  type CrmTaxRate,
} from "@/api/endpoints/crmInvoices";
import { CrmFeatureDisabled } from "./CrmFeatureDisabled";

interface FormState {
  name: string;
  rate_pct: string; // user-entered percent; converted to bps
  jurisdiction: string;
  description: string;
  is_active: boolean;
}

const EMPTY: FormState = {
  name: "",
  rate_pct: "0",
  jurisdiction: "",
  description: "",
  is_active: true,
};

function pctToBps(pct: string): number {
  return Math.round(Number(pct || "0") * 100);
}

export function TaxRateAdminPanel() {
  const qc = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<CrmTaxRate | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY);

  const query = useQuery({
    queryKey: ["crm-tax-rates"],
    queryFn: () => listCrmTaxRates({ active_only: false, limit: 100 }),
    retry: (count, err) =>
      !(err instanceof ApiError && (err.status === 404 || err.status === 503)) && count < 2,
  });

  const saveMut = useMutation({
    mutationFn: async () => {
      const rate_bps = pctToBps(form.rate_pct);
      if (editing) {
        return updateCrmTaxRate(editing.tax_rate_id, {
          name: form.name.trim(),
          rate_bps,
          jurisdiction: form.jurisdiction.trim(),
          description: form.description.trim(),
          is_active: form.is_active,
        });
      }
      return createCrmTaxRate({
        name: form.name.trim(),
        rate_bps,
        jurisdiction: form.jurisdiction.trim(),
        description: form.description.trim(),
      });
    },
    onSuccess: () => {
      toast.success(editing ? "Tax rate updated" : "Tax rate created");
      qc.invalidateQueries({ queryKey: ["crm-tax-rates"] });
      setDialogOpen(false);
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to save tax rate"),
  });

  const openCreate = () => {
    setEditing(null);
    setForm(EMPTY);
    setDialogOpen(true);
  };

  const openEdit = (t: CrmTaxRate) => {
    setEditing(t);
    setForm({
      name: t.name,
      rate_pct: String(t.rate_bps / 100),
      jurisdiction: t.jurisdiction,
      description: t.description,
      is_active: t.is_active,
    });
    setDialogOpen(true);
  };

  if (query.error instanceof ApiError && (query.error.status === 404 || query.error.status === 503)) {
    return (
      <CrmFeatureDisabled
        title="Tax-rate management not enabled"
        message="Ask an administrator to enable CRM_TAX_RATES_ENABLED."
      />
    );
  }

  const rates: CrmTaxRate[] = query.data?.tax_rates ?? [];
  const canSubmit =
    form.name.trim() && form.jurisdiction.trim() && Number(form.rate_pct) >= 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2 text-base">
          <Percent className="h-4 w-4" />
          Tax Rates
        </CardTitle>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => query.refetch()}>
            <RefreshCw className="mr-1 h-4 w-4" />
            Refresh
          </Button>
          <Button size="sm" onClick={openCreate}>
            <Plus className="mr-1 h-4 w-4" />
            New Tax Rate
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {query.isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : rates.length === 0 ? (
          <div className="py-10 text-center text-sm text-muted-foreground">
            No tax rates defined yet.
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Jurisdiction</TableHead>
                <TableHead className="text-right">Rate</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Edit</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rates.map((t) => (
                <TableRow key={t.tax_rate_id}>
                  <TableCell className="font-medium">{t.name}</TableCell>
                  <TableCell>{t.jurisdiction}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatBps(t.rate_bps)}</TableCell>
                  <TableCell className="max-w-xs truncate text-muted-foreground">
                    {t.description || "—"}
                  </TableCell>
                  <TableCell>
                    <Badge variant={t.is_active ? "default" : "secondary"}>
                      {t.is_active ? "active" : "inactive"}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" onClick={() => openEdit(t)}>
                      <Pencil className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editing ? `Edit ${editing.name}` : "New Tax Rate"}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="tax-name">Name</Label>
              <Input
                id="tax-name"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="CA Sales Tax"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label htmlFor="tax-jur">Jurisdiction</Label>
                <Input
                  id="tax-jur"
                  value={form.jurisdiction}
                  onChange={(e) => setForm((f) => ({ ...f, jurisdiction: e.target.value }))}
                  placeholder="US-CA"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="tax-rate">Rate (%)</Label>
                <Input
                  id="tax-rate"
                  type="number"
                  step="0.01"
                  min={0}
                  max={100}
                  value={form.rate_pct}
                  onChange={(e) => setForm((f) => ({ ...f, rate_pct: e.target.value }))}
                />
              </div>
            </div>
            <div className="space-y-1">
              <Label htmlFor="tax-desc">Description</Label>
              <Input
                id="tax-desc"
                value={form.description}
                onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
              />
            </div>
            {editing && (
              <div className="flex items-center gap-2">
                <Switch
                  id="tax-active"
                  checked={form.is_active}
                  onCheckedChange={(v) => setForm((f) => ({ ...f, is_active: v }))}
                />
                <Label htmlFor="tax-active">Active</Label>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              Cancel
            </Button>
            <Button disabled={!canSubmit || saveMut.isPending} onClick={() => saveMut.mutate()}>
              {saveMut.isPending ? "Saving…" : "Save"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
