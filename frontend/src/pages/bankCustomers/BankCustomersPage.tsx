/**
 * CUS-001 + CUS-002: Bank Customers list and detail (admin).
 *
 * Features:
 *  - List customers (paginated, filterable by branch)
 *  - Create new customer
 *  - Customer detail (edit, attributes, user links, message thread)
 *
 * Gated by OPEN_BANK_PROJECT_ENABLED + customer_entity_enabled.
 * 404/503 = feature not enabled; rendered gracefully.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Users, Plus, ChevronRight, RefreshCw, Link2, MessageSquare, Tag, X } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { ApiError } from "@/api/client";
import {
  listCustomers,
  getCustomer,
  createCustomer,
  patchCustomer,
  listCustomerLinks,
  linkCustomerUser,
  listCustomerMessages,
  postCustomerMessage,
  listCustomerAttributes,
  setCustomerAttribute,
  deleteCustomerAttribute,
  type CustomerOut,
  type CustomerAttributeSetIn,
} from "@/api/endpoints/bankCustomers";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function kycBadgeVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  if (status === "verified") return "default";
  if (status === "pending") return "secondary";
  if (status === "failed") return "destructive";
  return "outline";
}

// ─── Feature-disabled banner ──────────────────────────────────────────────────

function FeatureDisabled({ message }: { message: string }) {
  return (
    <EmptyState
      icon={<Users className="h-8 w-8" />}
      title="Bank Customers not available"
      description={message}
    />
  );
}

// ─── Attributes panel ─────────────────────────────────────────────────────────

function AttributesPanel({ customerId }: { customerId: string }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [type, setType] = useState<"STRING" | "INTEGER" | "DOUBLE" | "DATE_WITH_DAY">("STRING");

  const attrsQ = useQuery({
    queryKey: ["bank-customers", customerId, "attributes"],
    queryFn: () => listCustomerAttributes(customerId),
    retry: false,
  });

  const setAttrMut = useMutation({
    mutationFn: (body: CustomerAttributeSetIn) => setCustomerAttribute(customerId, body),
    onSuccess: () => {
      toast.success("Attribute saved");
      setName("");
      setValue("");
      void qc.invalidateQueries({ queryKey: ["bank-customers", customerId, "attributes"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to save attribute"),
  });

  const delAttrMut = useMutation({
    mutationFn: (attribute_id: string) => deleteCustomerAttribute(customerId, attribute_id),
    onSuccess: () => {
      toast.success("Attribute removed");
      void qc.invalidateQueries({ queryKey: ["bank-customers", customerId, "attributes"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed to remove attribute"),
  });

  return (
    <div className="space-y-3">
      <h4 className="text-sm font-semibold flex items-center gap-2">
        <Tag className="h-4 w-4" /> Attributes
      </h4>

      {attrsQ.isLoading && <Skeleton className="h-8 w-full" />}

      {attrsQ.data && attrsQ.data.length === 0 && (
        <p className="text-sm text-muted-foreground">No attributes.</p>
      )}

      {attrsQ.data && attrsQ.data.map((attr) => (
        <div key={attr.attribute_id} className="flex items-center justify-between rounded border px-3 py-2 text-sm">
          <span>
            <span className="font-medium">{attr.name}</span>
            <span className="text-muted-foreground mx-2">({attr.type})</span>
            <span>{attr.value}</span>
          </span>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 text-muted-foreground"
            onClick={() => delAttrMut.mutate(attr.attribute_id)}
          >
            <X className="h-3 w-3" />
          </Button>
        </div>
      ))}

      <div className="flex gap-2 flex-wrap items-end">
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Name</Label>
          <Input className="h-8 w-32 text-xs" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. tier" />
        </div>
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Type</Label>
          <select
            className="h-8 rounded-md border bg-background px-2 text-xs"
            value={type}
            onChange={(e) => setType(e.target.value as typeof type)}
          >
            <option>STRING</option>
            <option>INTEGER</option>
            <option>DOUBLE</option>
            <option>DATE_WITH_DAY</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Value</Label>
          <Input className="h-8 w-32 text-xs" value={value} onChange={(e) => setValue(e.target.value)} placeholder="value" />
        </div>
        <Button
          size="sm"
          className="h-8"
          disabled={!name.trim() || !value.trim() || setAttrMut.isPending}
          onClick={() => setAttrMut.mutate({ name: name.trim(), type, value: value.trim() })}
        >
          Set
        </Button>
      </div>
    </div>
  );
}

// ─── Links panel ──────────────────────────────────────────────────────────────

function LinksPanel({ customerId }: { customerId: string }) {
  const qc = useQueryClient();
  const [userSub, setUserSub] = useState("");

  const linksQ = useQuery({
    queryKey: ["bank-customers", customerId, "links"],
    queryFn: () => listCustomerLinks(customerId),
    retry: false,
  });

  const linkMut = useMutation({
    mutationFn: (sub: string) => linkCustomerUser(customerId, { user_sub: sub }),
    onSuccess: () => {
      toast.success("User linked");
      setUserSub("");
      void qc.invalidateQueries({ queryKey: ["bank-customers", customerId, "links"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Link failed"),
  });

  return (
    <div className="space-y-3">
      <h4 className="text-sm font-semibold flex items-center gap-2">
        <Link2 className="h-4 w-4" /> Linked Users
      </h4>

      {linksQ.isLoading && <Skeleton className="h-8 w-full" />}

      {linksQ.data && linksQ.data.length === 0 && (
        <p className="text-sm text-muted-foreground">No linked users.</p>
      )}

      {linksQ.data && linksQ.data.map((lnk) => (
        <div key={lnk.user_sub} className="rounded border px-3 py-2 text-sm">
          <p className="font-mono text-xs text-muted-foreground">{lnk.user_sub}</p>
          <p className="text-xs text-muted-foreground">Linked {fmt(lnk.linked_at)} by {lnk.linked_by}</p>
        </div>
      ))}

      <div className="flex gap-2 items-end">
        <div className="flex flex-col gap-1 flex-1">
          <Label className="text-xs">User sub to link</Label>
          <Input
            className="h-8 text-xs"
            value={userSub}
            onChange={(e) => setUserSub(e.target.value)}
            placeholder="user sub / email"
          />
        </div>
        <Button
          size="sm"
          className="h-8"
          disabled={!userSub.trim() || linkMut.isPending}
          onClick={() => linkMut.mutate(userSub.trim())}
        >
          Link
        </Button>
      </div>
    </div>
  );
}

// ─── Message thread panel ─────────────────────────────────────────────────────

function MessagesPanel({ customerId }: { customerId: string }) {
  const qc = useQueryClient();
  const [body, setBody] = useState("");

  const msgsQ = useQuery({
    queryKey: ["bank-customers", customerId, "messages"],
    queryFn: () => listCustomerMessages(customerId, { limit: 50, newest_first: false }),
    retry: false,
  });

  const sendMut = useMutation({
    mutationFn: (text: string) => postCustomerMessage(customerId, text),
    onSuccess: () => {
      toast.success("Message sent");
      setBody("");
      void qc.invalidateQueries({ queryKey: ["bank-customers", customerId, "messages"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Send failed"),
  });

  return (
    <div className="space-y-3">
      <h4 className="text-sm font-semibold flex items-center gap-2">
        <MessageSquare className="h-4 w-4" /> Message Thread
      </h4>

      {msgsQ.isLoading && <Skeleton className="h-16 w-full" />}

      <div className="max-h-48 overflow-y-auto space-y-2">
        {msgsQ.data?.messages.map((m) => (
          <div
            key={m.message_id}
            className={`rounded-lg px-3 py-2 text-sm max-w-[80%] ${
              m.author_role === "STAFF"
                ? "ml-auto bg-primary text-primary-foreground"
                : "bg-muted"
            }`}
          >
            <p>{m.body}</p>
            <p className="text-xs opacity-70 mt-1">{m.author_role} · {fmt(m.created_at)}</p>
          </div>
        ))}
        {msgsQ.data?.messages.length === 0 && (
          <p className="text-sm text-muted-foreground">No messages yet.</p>
        )}
      </div>

      <div className="flex gap-2 items-end">
        <Textarea
          className="min-h-[60px] text-sm resize-none"
          placeholder="Type a message..."
          value={body}
          onChange={(e) => setBody(e.target.value)}
        />
        <Button
          size="sm"
          disabled={!body.trim() || sendMut.isPending}
          onClick={() => sendMut.mutate(body.trim())}
        >
          Send
        </Button>
      </div>
    </div>
  );
}

// ─── Customer detail dialog ───────────────────────────────────────────────────

function CustomerDetailDialog({
  customerId,
  open,
  onClose,
}: {
  customerId: string;
  open: boolean;
  onClose: () => void;
}) {
  const qc = useQueryClient();

  const detailQ = useQuery({
    queryKey: ["bank-customers", "detail", customerId],
    queryFn: () => getCustomer(customerId),
    enabled: open && !!customerId,
    retry: false,
  });

  const c = detailQ.data;

  const [editMode, setEditMode] = useState(false);
  const [legalName, setLegalName] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [dob, setDob] = useState("");
  const [kycStatus, setKycStatus] = useState("");

  function startEdit(cust: CustomerOut) {
    setLegalName(cust.legal_name);
    setEmail(cust.email ?? "");
    setPhone(cust.mobile_phone ?? "");
    setDob(cust.date_of_birth ?? "");
    setKycStatus(cust.kyc_status);
    setEditMode(true);
  }

  const patchMut = useMutation({
    mutationFn: () =>
      patchCustomer(customerId, {
        legal_name: legalName.trim() || undefined,
        email: email.trim() || null,
        mobile_phone: phone.trim() || null,
        date_of_birth: dob.trim() || null,
        kyc_status: kycStatus || undefined,
        expected_version: c!.version,
      }),
    onSuccess: () => {
      toast.success("Customer updated");
      setEditMode(false);
      void qc.invalidateQueries({ queryKey: ["bank-customers"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Update failed"),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Customer Detail</DialogTitle>
        </DialogHeader>

        {detailQ.isLoading && (
          <div className="space-y-2">
            {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-6 w-full" />)}
          </div>
        )}

        {c && !editMode && (
          <div className="space-y-2 text-sm">
            <div className="grid grid-cols-2 gap-2">
              <div><span className="text-muted-foreground">ID:</span> <span className="font-mono text-xs">{c.customer_id}</span></div>
              <div><span className="text-muted-foreground">Number:</span> {c.customer_number}</div>
              <div><span className="text-muted-foreground">Name:</span> <strong>{c.legal_name}</strong></div>
              <div><span className="text-muted-foreground">KYC:</span> <Badge variant={kycBadgeVariant(c.kyc_status)}>{c.kyc_status}</Badge></div>
              <div><span className="text-muted-foreground">Email:</span> {c.email ?? "—"}</div>
              <div><span className="text-muted-foreground">Phone:</span> {c.mobile_phone ?? "—"}</div>
              <div><span className="text-muted-foreground">DOB:</span> {c.date_of_birth ?? "—"}</div>
              <div><span className="text-muted-foreground">Branch:</span> {c.branch_id ?? "—"}</div>
              <div><span className="text-muted-foreground">Created:</span> {fmt(c.created_at)}</div>
              <div><span className="text-muted-foreground">Updated:</span> {fmt(c.updated_at)}</div>
            </div>
            <Button size="sm" variant="outline" onClick={() => startEdit(c)}>Edit</Button>
          </div>
        )}

        {c && editMode && (
          <div className="space-y-3 text-sm">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>Legal Name</Label>
                <Input value={legalName} onChange={(e) => setLegalName(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label>Email</Label>
                <Input value={email} onChange={(e) => setEmail(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label>Phone</Label>
                <Input value={phone} onChange={(e) => setPhone(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label>Date of Birth</Label>
                <Input value={dob} onChange={(e) => setDob(e.target.value)} placeholder="YYYY-MM-DD" />
              </div>
              <div className="space-y-1">
                <Label>KYC Status</Label>
                <select
                  className="w-full h-9 rounded-md border bg-background px-3 text-sm"
                  value={kycStatus}
                  onChange={(e) => setKycStatus(e.target.value)}
                >
                  <option value="none">none</option>
                  <option value="pending">pending</option>
                  <option value="verified">verified</option>
                  <option value="failed">failed</option>
                </select>
              </div>
            </div>
            <div className="flex gap-2">
              <Button size="sm" disabled={patchMut.isPending} onClick={() => patchMut.mutate()}>Save</Button>
              <Button size="sm" variant="outline" onClick={() => setEditMode(false)}>Cancel</Button>
            </div>
          </div>
        )}

        {c && (
          <>
            <Separator className="my-2" />
            <AttributesPanel customerId={customerId} />
            <Separator className="my-2" />
            <LinksPanel customerId={customerId} />
            <Separator className="my-2" />
            <MessagesPanel customerId={customerId} />
          </>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Create customer dialog ───────────────────────────────────────────────────

function CreateCustomerDialog({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: (id: string) => void;
}) {
  const [legalName, setLegalName] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [dob, setDob] = useState("");
  const [branchId, setBranchId] = useState("");

  const createMut = useMutation({
    mutationFn: () =>
      createCustomer({
        legal_name: legalName.trim(),
        email: email.trim() || null,
        mobile_phone: phone.trim() || null,
        date_of_birth: dob.trim() || null,
        branch_id: branchId.trim() || null,
      }),
    onSuccess: (c) => {
      toast.success(`Customer ${c.customer_number} created`);
      setLegalName("");
      setEmail("");
      setPhone("");
      setDob("");
      setBranchId("");
      onCreated(c.customer_id);
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Create failed"),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>New Customer</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1">
            <Label>Legal Name <span className="text-destructive">*</span></Label>
            <Input value={legalName} onChange={(e) => setLegalName(e.target.value)} placeholder="Full legal name" />
          </div>
          <div className="space-y-1">
            <Label>Email</Label>
            <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="customer@example.com" />
          </div>
          <div className="space-y-1">
            <Label>Mobile Phone</Label>
            <Input value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="+1..." />
          </div>
          <div className="space-y-1">
            <Label>Date of Birth</Label>
            <Input value={dob} onChange={(e) => setDob(e.target.value)} placeholder="YYYY-MM-DD" />
          </div>
          <div className="space-y-1">
            <Label>Branch ID</Label>
            <Input value={branchId} onChange={(e) => setBranchId(e.target.value)} placeholder="optional" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            disabled={!legalName.trim() || createMut.isPending}
            onClick={() => createMut.mutate()}
          >
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function BankCustomersPage() {
  const qc = useQueryClient();
  const [branchFilter, setBranchFilter] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [showCreate, setShowCreate] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const listQ = useQuery({
    queryKey: ["bank-customers", "list", branchFilter, cursor],
    queryFn: () =>
      listCustomers({
        branch_id: branchFilter.trim() || undefined,
        cursor,
        limit: 25,
      }),
    retry: false,
  });

  // Detect feature-disabled errors from the query
  if (listQ.error instanceof ApiError && (listQ.error.status === 404 || listQ.error.status === 503)) {
    return (
      <div className="flex flex-col gap-6">
        <PageHeader title="Bank Customers" description="OBP CUS-001..CUS-005" />
        <FeatureDisabled message="The bank customers feature is not enabled on this platform." />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Bank Customers"
        description="Manage OBP customer records, user links, and message threads."
        actions={
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4 mr-1" /> New Customer
          </Button>
        }
      />

      {/* Filters */}
      <div className="flex gap-3 items-end flex-wrap">
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Branch ID</Label>
          <Input
            className="h-8 w-48 text-sm"
            placeholder="Filter by branch…"
            value={branchFilter}
            onChange={(e) => { setBranchFilter(e.target.value); setCursor(undefined); }}
          />
        </div>
        <Button
          variant="outline"
          size="sm"
          className="h-8"
          onClick={() => void qc.invalidateQueries({ queryKey: ["bank-customers", "list"] })}
        >
          <RefreshCw className="h-3 w-3 mr-1" /> Refresh
        </Button>
      </div>

      {/* Table */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Customers</CardTitle>
          <CardDescription>
            {listQ.data ? `${listQ.data.customers.length} loaded` : "Loading…"}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {listQ.isLoading && (
            <div className="p-4 space-y-2">
              {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
            </div>
          )}

          {listQ.data?.customers.length === 0 && (
            <EmptyState
              icon={<Users className="h-8 w-8" />}
              title="No customers found"
              description="Create the first customer record using the button above."
            />
          )}

          {listQ.data && listQ.data.customers.length > 0 && (
            <div className="divide-y">
              {listQ.data.customers.map((c) => (
                <button
                  key={c.customer_id}
                  className="w-full flex items-center justify-between px-4 py-3 hover:bg-muted/50 transition-colors text-left"
                  onClick={() => setSelectedId(c.customer_id)}
                >
                  <div className="space-y-0.5">
                    <p className="font-medium text-sm">{c.legal_name}</p>
                    <p className="text-xs text-muted-foreground">
                      #{c.customer_number} · {c.email ?? "no email"} · {c.mobile_phone ?? "no phone"}
                    </p>
                  </div>
                  <div className="flex items-center gap-3">
                    <Badge variant={kycBadgeVariant(c.kyc_status)}>{c.kyc_status}</Badge>
                    <ChevronRight className="h-4 w-4 text-muted-foreground" />
                  </div>
                </button>
              ))}
            </div>
          )}

          {/* Pagination */}
          {listQ.data?.cursor && (
            <div className="p-3 border-t flex justify-center">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setCursor(listQ.data!.cursor!)}
              >
                Load more
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Dialogs */}
      <CreateCustomerDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={(id) => {
          setShowCreate(false);
          setSelectedId(id);
          void qc.invalidateQueries({ queryKey: ["bank-customers", "list"] });
        }}
      />

      {selectedId && (
        <CustomerDetailDialog
          customerId={selectedId}
          open={!!selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  );
}
