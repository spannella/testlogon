/**
 * OBP PAY-001 — Counterparties / Beneficiaries Manager
 *
 * Feature-flagged: gracefully shows "not enabled" state on 404.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { UserCheck, Plus, Trash2, Pencil, RefreshCw, AlertCircle } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
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
  listCounterparties,
  createCounterparty,
  updateCounterparty,
  deleteCounterparty,
  type Counterparty,
  type CounterpartyScheme,
  type CounterpartyCreateIn,
} from "@/api/endpoints/bankPayments";

function fmt(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString();
}

function RoutingBadge({ routing }: { routing: Counterparty["routing"] }) {
  const last4 = routing.iban_last4 ?? routing.account_number_last4;
  return (
    <span className="text-xs text-muted-foreground">
      {routing.scheme}
      {last4 && ` ···${last4}`}
      {routing.sort_code && ` / ${routing.sort_code}`}
      {routing.bank_name && ` @ ${routing.bank_name}`}
      {" "}
      <span className="uppercase">{routing.currency}</span>
    </span>
  );
}

function FeatureDisabled() {
  return (
    <div className="flex flex-col items-center gap-3 py-16 text-center text-muted-foreground">
      <AlertCircle className="h-10 w-10" />
      <p className="text-sm font-medium">Counterparties / Beneficiaries not enabled</p>
      <p className="text-xs max-w-sm">
        This feature requires the Open Banking Project and Payments flags to be active.
        Contact your administrator to enable PAY-001.
      </p>
    </div>
  );
}

const SCHEMES: CounterpartyScheme[] = [
  "IBAN",
  "ACCOUNT_SORT_CODE",
  "ACCOUNT_NUMBER",
  "BANK",
];

interface CreateFormState {
  name: string;
  description: string;
  scheme: CounterpartyScheme;
  iban: string;
  account_number: string;
  sort_code: string;
  bank_code: string;
  bank_name: string;
  account_holder: string;
  currency: string;
}

const BLANK_FORM: CreateFormState = {
  name: "",
  description: "",
  scheme: "IBAN",
  iban: "",
  account_number: "",
  sort_code: "",
  bank_code: "",
  bank_name: "",
  account_holder: "",
  currency: "usd",
};

export default function CounterpartiesPage() {
  const qc = useQueryClient();
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState<CreateFormState>(BLANK_FORM);
  const [editId, setEditId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");

  const listQuery = useQuery({
    queryKey: ["counterparties", cursor],
    queryFn: () => listCounterparties({ limit: 50, cursor }),
    retry: (failCount, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return failCount < 2;
    },
  });

  const isDisabled =
    listQuery.isError &&
    listQuery.error instanceof ApiError &&
    (listQuery.error.status === 404 || listQuery.error.status === 503);

  const createMut = useMutation({
    mutationFn: () => {
      const payload: CounterpartyCreateIn = {
        name: form.name.trim(),
        description: form.description.trim() || undefined,
        routing: {
          scheme: form.scheme,
          iban: form.iban.trim() || undefined,
          account_number: form.account_number.trim() || undefined,
          sort_code: form.sort_code.trim() || undefined,
          bank_code: form.bank_code.trim() || undefined,
          bank_name: form.bank_name.trim() || undefined,
          account_holder: form.account_holder.trim() || undefined,
          currency: form.currency.trim() || "usd",
        },
      };
      return createCounterparty(payload);
    },
    onSuccess: () => {
      toast.success("Counterparty created");
      setShowCreate(false);
      setForm(BLANK_FORM);
      void qc.invalidateQueries({ queryKey: ["counterparties"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to create counterparty"),
  });

  const updateMut = useMutation({
    mutationFn: (id: string) =>
      updateCounterparty(id, {
        name: editName.trim() || undefined,
        description: editDescription.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success("Counterparty updated");
      setEditId(null);
      void qc.invalidateQueries({ queryKey: ["counterparties"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to update counterparty"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteCounterparty(id),
    onSuccess: () => {
      toast.success("Counterparty deleted");
      void qc.invalidateQueries({ queryKey: ["counterparties"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to delete counterparty"),
  });

  const items = listQuery.data?.counterparties ?? [];
  const nextCursor = listQuery.data?.cursor ?? null;

  const setField = (k: keyof CreateFormState) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader
        title="Counterparties"
        description="Manage beneficiaries and payment counterparties."
        actions={
          !isDisabled && (
            <Button onClick={() => setShowCreate(true)} size="sm">
              <Plus className="h-4 w-4 mr-1" /> Add counterparty
            </Button>
          )
        }
      />

      {isDisabled && <FeatureDisabled />}

      {!isDisabled && (
        <>
          {listQuery.isLoading && (
            <div className="space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-16 w-full rounded-lg" />
              ))}
            </div>
          )}

          {!listQuery.isLoading && items.length === 0 && !listQuery.isError && (
            <div className="flex flex-col items-center gap-2 py-16 text-center text-muted-foreground">
              <UserCheck className="h-10 w-10" />
              <p className="text-sm">No counterparties yet. Add one to get started.</p>
            </div>
          )}

          {items.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Beneficiaries ({items.length})</CardTitle>
                <CardDescription>Your saved payment recipients.</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {items.map((cp) => (
                    <div
                      key={cp.counterparty_id}
                      className="flex items-start justify-between gap-3 rounded-lg border p-3"
                      data-testid={`counterparty-${cp.counterparty_id}`}
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-medium text-sm">{cp.name}</span>
                          {cp.is_beneficiary && (
                            <Badge variant="secondary" className="text-xs">Beneficiary</Badge>
                          )}
                        </div>
                        <RoutingBadge routing={cp.routing} />
                        {cp.description && (
                          <p className="text-xs text-muted-foreground mt-1">{cp.description}</p>
                        )}
                        <p className="text-xs text-muted-foreground mt-1">
                          Added {fmt(cp.created_at)}
                        </p>
                      </div>
                      <div className="flex gap-1 shrink-0">
                        <Button
                          size="icon"
                          variant="ghost"
                          aria-label="Edit counterparty"
                          onClick={() => {
                            setEditId(cp.counterparty_id);
                            setEditName(cp.name);
                            setEditDescription(cp.description ?? "");
                          }}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          aria-label="Delete counterparty"
                          onClick={() => deleteMut.mutate(cp.counterparty_id)}
                          disabled={deleteMut.isPending}
                        >
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="flex gap-2 mt-4">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => qc.invalidateQueries({ queryKey: ["counterparties"] })}
                    disabled={listQuery.isFetching}
                  >
                    <RefreshCw className="h-3.5 w-3.5 mr-1" /> Refresh
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCursor(nextCursor ?? undefined)}
                    disabled={!nextCursor}
                  >
                    Next page
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Create dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Add counterparty</DialogTitle>
            <DialogDescription>Save a beneficiary for payments.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3 pt-2">
            <div className="space-y-1">
              <Label>Name</Label>
              <Input
                placeholder="John Doe / Acme Ltd"
                value={form.name}
                onChange={setField("name")}
                data-testid="cp-name"
              />
            </div>
            <div className="space-y-1">
              <Label>Routing scheme</Label>
              <Select
                value={form.scheme}
                onValueChange={(v) => setForm((f) => ({ ...f, scheme: v as CounterpartyScheme }))}
              >
                <SelectTrigger data-testid="cp-scheme">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SCHEMES.map((s) => (
                    <SelectItem key={s} value={s}>{s}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {(form.scheme === "IBAN") && (
              <div className="space-y-1">
                <Label>IBAN</Label>
                <Input placeholder="GB29NWBK60161331926819" value={form.iban} onChange={setField("iban")} />
              </div>
            )}
            {(form.scheme === "ACCOUNT_SORT_CODE" || form.scheme === "ACCOUNT_NUMBER") && (
              <>
                <div className="space-y-1">
                  <Label>Account number</Label>
                  <Input placeholder="12345678" value={form.account_number} onChange={setField("account_number")} />
                </div>
                {form.scheme === "ACCOUNT_SORT_CODE" && (
                  <div className="space-y-1">
                    <Label>Sort code</Label>
                    <Input placeholder="60-16-13" value={form.sort_code} onChange={setField("sort_code")} />
                  </div>
                )}
              </>
            )}
            {form.scheme === "BANK" && (
              <>
                <div className="space-y-1">
                  <Label>Bank code</Label>
                  <Input placeholder="SWIFT / BIC" value={form.bank_code} onChange={setField("bank_code")} />
                </div>
                <div className="space-y-1">
                  <Label>Bank name</Label>
                  <Input placeholder="Bank of Example" value={form.bank_name} onChange={setField("bank_name")} />
                </div>
              </>
            )}

            <div className="space-y-1">
              <Label>Account holder name (optional)</Label>
              <Input placeholder="Jane Smith" value={form.account_holder} onChange={setField("account_holder")} />
            </div>
            <div className="space-y-1">
              <Label>Currency</Label>
              <Input placeholder="usd" value={form.currency} onChange={setField("currency")} />
            </div>
            <div className="space-y-1">
              <Label>Description (optional)</Label>
              <Textarea
                rows={2}
                placeholder="Monthly supplier payment"
                value={form.description}
                onChange={setField("description")}
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button
                onClick={() => createMut.mutate()}
                disabled={createMut.isPending || !form.name.trim()}
                data-testid="cp-create-btn"
              >
                {createMut.isPending ? "Saving…" : "Save counterparty"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Edit dialog */}
      <Dialog open={!!editId} onOpenChange={(o) => !o && setEditId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit counterparty</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 pt-2">
            <div className="space-y-1">
              <Label>Name</Label>
              <Input value={editName} onChange={(e) => setEditName(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label>Description</Label>
              <Input value={editDescription} onChange={(e) => setEditDescription(e.target.value)} />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={() => setEditId(null)}>Cancel</Button>
              <Button
                onClick={() => editId && updateMut.mutate(editId)}
                disabled={updateMut.isPending}
              >
                {updateMut.isPending ? "Saving…" : "Save changes"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
