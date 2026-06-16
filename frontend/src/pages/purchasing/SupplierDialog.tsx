import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
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

import {
  createSupplier,
  updateSupplier,
  type Supplier,
} from "@/api/endpoints/purchasing";

export function SupplierDialog({
  open,
  onOpenChange,
  onSaved,
  existing,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onSaved: (s: Supplier) => void;
  existing?: Supplier;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [currency, setCurrency] = useState("USD");
  const [terms, setTerms] = useState("30");

  useEffect(() => {
    if (open) {
      setName(existing?.name ?? "");
      setEmail(existing?.email ?? "");
      setPhone(existing?.phone ?? "");
      setCurrency(existing?.default_currency ?? "USD");
      setTerms(String(existing?.payment_terms_days ?? 30));
    }
  }, [open, existing]);

  const saveMut = useMutation({
    mutationFn: () => {
      const body = {
        name: name.trim(),
        email: email.trim() || null,
        phone: phone.trim() || null,
        default_currency: currency.trim() || "USD",
        payment_terms_days: Math.max(0, Number(terms) || 0),
      };
      return existing
        ? updateSupplier(existing.supplier_id, body)
        : createSupplier(body);
    },
    onSuccess: (s) => {
      toast.success(existing ? "Supplier updated" : "Supplier created");
      void qc.invalidateQueries({ queryKey: ["purchasing", "suppliers"] });
      if (existing) void qc.invalidateQueries({ queryKey: ["purchasing", "supplier", existing.supplier_id] });
      onSaved(s);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to save supplier"),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{existing ? "Edit Supplier" : "New Supplier"}</DialogTitle>
          <DialogDescription>
            {existing ? "Update supplier details." : "Add a new supplier to your catalog."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="space-y-1">
            <Label>Name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Supplies" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label>Email</Label>
              <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="ops@acme.com" />
            </div>
            <div className="space-y-1">
              <Label>Phone</Label>
              <Input value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="+1…" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label>Default currency</Label>
              <Input
                value={currency}
                maxLength={3}
                onChange={(e) => setCurrency(e.target.value.toUpperCase())}
              />
            </div>
            <div className="space-y-1">
              <Label>Payment terms (days)</Label>
              <Input
                type="number"
                min={0}
                max={365}
                value={terms}
                onChange={(e) => setTerms(e.target.value)}
              />
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={!name.trim() || saveMut.isPending} onClick={() => saveMut.mutate()}>
            {saveMut.isPending ? "Saving…" : existing ? "Save changes" : "Create supplier"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
