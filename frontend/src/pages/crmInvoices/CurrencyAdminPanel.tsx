import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Coins, Pencil, Plus, RefreshCw } from "lucide-react";

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
  listCrmCurrencies,
  createCrmCurrency,
  updateCrmCurrency,
  type CrmCurrency,
} from "@/api/endpoints/crmInvoices";
import { CrmFeatureDisabled } from "./CrmFeatureDisabled";

interface FormState {
  iso_code: string;
  name: string;
  symbol: string;
  rate_to_usd: string;
  decimal_places: string;
  is_active: boolean;
}

const EMPTY: FormState = {
  iso_code: "",
  name: "",
  symbol: "",
  rate_to_usd: "1",
  decimal_places: "2",
  is_active: true,
};

export function CurrencyAdminPanel() {
  const qc = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<CrmCurrency | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY);

  const query = useQuery({
    queryKey: ["crm-currencies"],
    queryFn: () => listCrmCurrencies(false),
    retry: (count, err) =>
      !(err instanceof ApiError && (err.status === 404 || err.status === 503)) && count < 2,
  });

  const saveMut = useMutation({
    mutationFn: async () => {
      const rate = Number(form.rate_to_usd);
      const dp = Number(form.decimal_places);
      if (editing) {
        return updateCrmCurrency(editing.iso_code, {
          name: form.name.trim(),
          symbol: form.symbol.trim(),
          rate_to_usd: rate,
          decimal_places: dp,
          is_active: form.is_active,
        });
      }
      return createCrmCurrency({
        iso_code: form.iso_code.trim().toUpperCase(),
        name: form.name.trim(),
        symbol: form.symbol.trim(),
        rate_to_usd: rate,
        decimal_places: dp,
        is_active: form.is_active,
      });
    },
    onSuccess: () => {
      toast.success(editing ? "Currency updated" : "Currency created");
      qc.invalidateQueries({ queryKey: ["crm-currencies"] });
      setDialogOpen(false);
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 409) {
        toast.error("A currency with that ISO code already exists.");
      } else {
        toast.error(e instanceof ApiError ? e.detail : "Failed to save currency");
      }
    },
  });

  const openCreate = () => {
    setEditing(null);
    setForm(EMPTY);
    setDialogOpen(true);
  };

  const openEdit = (c: CrmCurrency) => {
    setEditing(c);
    setForm({
      iso_code: c.iso_code,
      name: c.name,
      symbol: c.symbol,
      rate_to_usd: String(c.rate_to_usd),
      decimal_places: String(c.decimal_places),
      is_active: c.is_active,
    });
    setDialogOpen(true);
  };

  if (query.error instanceof ApiError && (query.error.status === 404 || query.error.status === 503)) {
    return (
      <CrmFeatureDisabled
        title="Currency management not enabled"
        message="Ask an administrator to enable CRM_CURRENCIES_ENABLED."
      />
    );
  }

  const currencies: CrmCurrency[] = query.data?.currencies ?? [];
  const canSubmit =
    (editing || form.iso_code.trim().length === 3) &&
    form.name.trim() &&
    form.symbol.trim() &&
    Number(form.rate_to_usd) > 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2 text-base">
          <Coins className="h-4 w-4" />
          Currencies
        </CardTitle>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => query.refetch()}>
            <RefreshCw className="mr-1 h-4 w-4" />
            Refresh
          </Button>
          <Button size="sm" onClick={openCreate}>
            <Plus className="mr-1 h-4 w-4" />
            New Currency
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
        ) : currencies.length === 0 ? (
          <div className="py-10 text-center text-sm text-muted-foreground">
            No currencies defined yet.
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ISO</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Symbol</TableHead>
                <TableHead className="text-right">Rate → USD</TableHead>
                <TableHead className="text-right">Decimals</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Edit</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {currencies.map((c) => (
                <TableRow key={c.iso_code}>
                  <TableCell className="font-medium">
                    {c.iso_code}
                    {c.is_default && (
                      <Badge variant="outline" className="ml-2 text-[10px]">
                        default
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell>{c.name}</TableCell>
                  <TableCell>{c.symbol}</TableCell>
                  <TableCell className="text-right tabular-nums">{c.rate_to_usd}</TableCell>
                  <TableCell className="text-right tabular-nums">{c.decimal_places}</TableCell>
                  <TableCell>
                    <Badge variant={c.is_active ? "default" : "secondary"}>
                      {c.is_active ? "active" : "inactive"}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" onClick={() => openEdit(c)}>
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
            <DialogTitle>{editing ? `Edit ${editing.iso_code}` : "New Currency"}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="iso">ISO Code (3 letters)</Label>
              <Input
                id="iso"
                maxLength={3}
                disabled={!!editing}
                value={form.iso_code}
                onChange={(e) => setForm((f) => ({ ...f, iso_code: e.target.value.toUpperCase() }))}
                placeholder="EUR"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="cur-name">Name</Label>
              <Input
                id="cur-name"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="Euro"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label htmlFor="cur-symbol">Symbol</Label>
                <Input
                  id="cur-symbol"
                  value={form.symbol}
                  onChange={(e) => setForm((f) => ({ ...f, symbol: e.target.value }))}
                  placeholder="€"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="cur-dp">Decimal Places</Label>
                <Input
                  id="cur-dp"
                  type="number"
                  min={0}
                  max={4}
                  value={form.decimal_places}
                  onChange={(e) => setForm((f) => ({ ...f, decimal_places: e.target.value }))}
                />
              </div>
            </div>
            <div className="space-y-1">
              <Label htmlFor="cur-rate">Rate to USD</Label>
              <Input
                id="cur-rate"
                type="number"
                step="0.0001"
                min={0}
                value={form.rate_to_usd}
                onChange={(e) => setForm((f) => ({ ...f, rate_to_usd: e.target.value }))}
              />
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id="cur-active"
                checked={form.is_active}
                onCheckedChange={(v) => setForm((f) => ({ ...f, is_active: v }))}
              />
              <Label htmlFor="cur-active">Active</Label>
            </div>
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
