import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Settings2 } from "lucide-react";

import { ApiError } from "@/api/client";
import {
  addMethod,
  createCarrier,
  disableCarrier,
  listCarriers,
  listMethods,
  updateCarrier,
  updateMethod,
  type CarrierCode,
  type CarrierOut,
  type MethodCode,
} from "@/api/endpoints/shipping";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ShippingNotEnabled } from "./ShippingNotEnabled";
import { CARRIER_CODES, METHOD_CODES, fmtCents } from "./shippingHelpers";

function CarrierMethods({ carrier }: { carrier: CarrierOut }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [methodCode, setMethodCode] = useState<MethodCode>("ground");
  const [methodLabel, setMethodLabel] = useState("");
  const [rateDollars, setRateDollars] = useState("");
  const [minDays, setMinDays] = useState("");
  const [maxDays, setMaxDays] = useState("");

  const methodsQuery = useQuery({
    queryKey: ["shipping", "methods", carrier.carrier_id],
    queryFn: () => listMethods(carrier.carrier_id, false),
  });

  const addMut = useMutation({
    mutationFn: () =>
      addMethod(carrier.carrier_id, {
        method_code: methodCode,
        method_label: methodLabel.trim(),
        base_rate_cents: Math.round(parseFloat(rateDollars || "0") * 100),
        transit_days_min: minDays ? Number(minDays) : undefined,
        transit_days_max: maxDays ? Number(maxDays) : undefined,
      }),
    onSuccess: () => {
      toast.success("Method added");
      setOpen(false);
      setMethodLabel("");
      setRateDollars("");
      setMinDays("");
      setMaxDays("");
      void qc.invalidateQueries({ queryKey: ["shipping", "methods", carrier.carrier_id] });
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to add method"),
  });

  const toggleMethodMut = useMutation({
    mutationFn: (vars: { code: string; enabled: boolean }) =>
      updateMethod(carrier.carrier_id, vars.code, { enabled: vars.enabled }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["shipping", "methods", carrier.carrier_id] });
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to update method"),
  });

  const methods = methodsQuery.data ?? [];

  return (
    <div className="space-y-2 pl-2">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-muted-foreground">
          Shipping methods
        </span>
        <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
          <Plus className="mr-1 h-3.5 w-3.5" /> Add method
        </Button>
      </div>
      {methodsQuery.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading methods…</p>
      ) : methods.length === 0 ? (
        <p className="text-sm text-muted-foreground">No methods configured.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Method</TableHead>
              <TableHead>Base rate</TableHead>
              <TableHead>Transit</TableHead>
              <TableHead className="text-right">Enabled</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {methods.map((m) => (
              <TableRow key={m.method_code}>
                <TableCell>
                  <div className="font-medium">{m.method_label}</div>
                  <div className="text-xs text-muted-foreground">{m.method_code}</div>
                </TableCell>
                <TableCell>{fmtCents(m.base_rate_cents, m.currency)}</TableCell>
                <TableCell>
                  {m.transit_days_min != null && m.transit_days_max != null
                    ? `${m.transit_days_min}–${m.transit_days_max} days`
                    : "—"}
                </TableCell>
                <TableCell className="text-right">
                  <Switch
                    checked={m.enabled}
                    onCheckedChange={(v) =>
                      toggleMethodMut.mutate({ code: m.method_code, enabled: v })
                    }
                  />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add shipping method</DialogTitle>
            <DialogDescription>
              Add a method to {carrier.display_name}.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 py-2">
            <div className="grid gap-1.5">
              <Label>Method code</Label>
              <Select value={methodCode} onValueChange={(v) => setMethodCode(v as MethodCode)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {METHOD_CODES.map((c) => (
                    <SelectItem key={c} value={c}>
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label>Label</Label>
              <Input
                value={methodLabel}
                placeholder="e.g. Ground Shipping"
                onChange={(e) => setMethodLabel(e.target.value)}
              />
            </div>
            <div className="grid gap-1.5">
              <Label>Base rate ($)</Label>
              <Input
                type="number"
                min="0"
                step="0.01"
                value={rateDollars}
                placeholder="9.99"
                onChange={(e) => setRateDollars(e.target.value)}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-1.5">
                <Label>Transit days (min)</Label>
                <Input
                  type="number"
                  min="0"
                  value={minDays}
                  onChange={(e) => setMinDays(e.target.value)}
                />
              </div>
              <div className="grid gap-1.5">
                <Label>Transit days (max)</Label>
                <Input
                  type="number"
                  min="0"
                  value={maxDays}
                  onChange={(e) => setMaxDays(e.target.value)}
                />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!methodLabel.trim() || addMut.isPending}
              onClick={() => addMut.mutate()}
            >
              {addMut.isPending ? "Adding…" : "Add method"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export function CarriersPanel() {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [newCode, setNewCode] = useState<CarrierCode>("ups");
  const [newName, setNewName] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const carriersQuery = useQuery({
    queryKey: ["shipping", "carriers", "all"],
    queryFn: () => listCarriers(false),
    retry: false,
  });

  const createMut = useMutation({
    mutationFn: () =>
      createCarrier({ carrier_code: newCode, display_name: newName.trim() }),
    onSuccess: () => {
      toast.success("Carrier created");
      setCreateOpen(false);
      setNewName("");
      void qc.invalidateQueries({ queryKey: ["shipping", "carriers"] });
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to create carrier"),
  });

  const toggleMut = useMutation({
    mutationFn: (vars: { id: string; enabled: boolean }) =>
      vars.enabled
        ? updateCarrier(vars.id, { enabled: true })
        : disableCarrier(vars.id).then(() => undefined),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["shipping", "carriers"] });
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to update carrier"),
  });

  if (carriersQuery.isError && (carriersQuery.error as ApiError)?.status === 503) {
    return <ShippingNotEnabled />;
  }

  const carriers = carriersQuery.data ?? [];

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>Carriers</CardTitle>
          <CardDescription>
            Manage shipping carriers and their methods.
          </CardDescription>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-1 h-4 w-4" /> New carrier
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        {carriersQuery.isLoading ? (
          <p className="text-sm text-muted-foreground">Loading carriers…</p>
        ) : carriers.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No carriers configured yet. Create one to get started.
          </p>
        ) : (
          carriers.map((c) => (
            <div key={c.carrier_id} className="rounded-lg border p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div>
                    <div className="font-medium">{c.display_name}</div>
                    <div className="text-xs text-muted-foreground">
                      {c.carrier_code}
                    </div>
                  </div>
                  {c.online_tracking && (
                    <Badge variant="secondary">Online tracking</Badge>
                  )}
                  <Badge variant={c.enabled ? "default" : "outline"}>
                    {c.enabled ? "Enabled" : "Disabled"}
                  </Badge>
                </div>
                <div className="flex items-center gap-3">
                  <Switch
                    checked={c.enabled}
                    onCheckedChange={(v) =>
                      toggleMut.mutate({ id: c.carrier_id, enabled: v })
                    }
                  />
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() =>
                      setExpanded(expanded === c.carrier_id ? null : c.carrier_id)
                    }
                  >
                    <Settings2 className="mr-1 h-4 w-4" />
                    {expanded === c.carrier_id ? "Hide methods" : "Methods"}
                  </Button>
                </div>
              </div>
              {expanded === c.carrier_id && (
                <div className="mt-4 border-t pt-4">
                  <CarrierMethods carrier={c} />
                </div>
              )}
            </div>
          ))
        )}
      </CardContent>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New carrier</DialogTitle>
            <DialogDescription>Register a shipping carrier.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 py-2">
            <div className="grid gap-1.5">
              <Label>Carrier code</Label>
              <Select value={newCode} onValueChange={(v) => setNewCode(v as CarrierCode)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CARRIER_CODES.map((c) => (
                    <SelectItem key={c} value={c}>
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label>Display name</Label>
              <Input
                value={newName}
                placeholder="e.g. UPS"
                onChange={(e) => setNewName(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!newName.trim() || createMut.isPending}
              onClick={() => createMut.mutate()}
            >
              {createMut.isPending ? "Creating…" : "Create carrier"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
