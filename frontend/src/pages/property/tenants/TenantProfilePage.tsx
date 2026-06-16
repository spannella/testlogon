/**
 * TenantProfilePage — Tenant detail view (TEN-004)
 * Route: /property/tenants/:tenantId
 *
 * Five-tab layout: Identity | Employment | Income | Emergency Contacts | Lease History
 */

import { useRef, useState } from "react";
import { useNavigate, useParams, Link } from "react-router-dom";
import {
  useQuery,
  useMutation,
  useQueryClient,
  useInfiniteQuery,
} from "@tanstack/react-query";
import { toast } from "sonner";
import {
  AlertCircle,
  CheckCircle2,
  Trash2,
  Upload,
  PlusCircle,
  XCircle,
} from "lucide-react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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
  getPropertyTenant,
  updatePropertyTenant,
  getTenantProfile,
  updateTenantProfile,
  setIncomeVerification,
  listIncomeDocs,
  uploadIncomeDoc,
  deleteIncomeDoc,
  listTenantLeases,
  type PropertyTenantOut,
  type TenantProfileOut,
  type EmergencyContactOut,
  type IncomeDocOut,
  type TenantLeaseSummaryOut,
} from "@/api/endpoints/propertyTenants";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function isFeatureDisabled(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404 && /not enabled/i.test(err.detail ?? "");
}

function fmtDate(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

function fmtCents(cents: number | null | undefined, currency = "usd"): string {
  if (cents == null) return "—";
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
  }).format(cents / 100);
}

function fmtBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function tenantStatusBadge(status: string) {
  const map: Record<string, "default" | "secondary" | "outline"> = {
    active: "default",
    past: "secondary",
    prospect: "outline",
  };
  const label = status.charAt(0).toUpperCase() + status.slice(1);
  return <Badge variant={map[status] ?? "outline"}>{label}</Badge>;
}

function leaseStatusBadge(status: string) {
  const map: Record<string, "default" | "secondary" | "outline"> = {
    active: "default",
    upcoming: "outline",
    draft: "outline",
    ended: "secondary",
  };
  const label = status.charAt(0).toUpperCase() + status.slice(1);
  return <Badge variant={map[status] ?? "outline"}>{label}</Badge>;
}

function verificationBadge(status?: string) {
  if (!status || status === "unverified") return <Badge variant="outline">Unverified</Badge>;
  if (status === "pending") return <Badge variant="outline" className="text-yellow-600">Pending</Badge>;
  if (status === "verified") return <Badge variant="default">Verified</Badge>;
  if (status === "rejected") return <Badge variant="destructive">Rejected</Badge>;
  return <Badge variant="outline">{status}</Badge>;
}

// ─── Edit-identity form ────────────────────────────────────────────────────────

const identitySchema = z.object({
  display_name: z.string().min(1, "Name is required"),
  email: z.string().email("Invalid email").optional().or(z.literal("")),
  phone: z.string().optional().or(z.literal("")),
  status: z.enum(["prospect", "active", "past"]).optional(),
});
type IdentityForm = z.infer<typeof identitySchema>;

// ─── Employment form ──────────────────────────────────────────────────────────

const employmentSchema = z.object({
  employer_name: z.string().min(1, "Employer name is required"),
  job_title: z.string().optional().or(z.literal("")),
  employment_type: z
    .enum(["full_time", "part_time", "self_employed", "contract", "unemployed", "retired", "student"])
    .optional(),
  start_date: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, "Use YYYY-MM-DD")
    .optional()
    .or(z.literal("")),
  employer_phone: z.string().optional().or(z.literal("")),
});
type EmploymentForm = z.infer<typeof employmentSchema>;

// ─── Emergency contact form ───────────────────────────────────────────────────

const ecSchema = z.object({
  name: z.string().min(1, "Name is required"),
  relationship: z.string().optional().or(z.literal("")),
  phone: z.string().optional().or(z.literal("")),
  email: z.string().email("Invalid email").optional().or(z.literal("")),
});
type EcForm = z.infer<typeof ecSchema>;

// ─── Sub-sections ─────────────────────────────────────────────────────────────

function IdentityTab({ tenant }: { tenant: PropertyTenantOut }) {
  const queryClient = useQueryClient();
  const [showEdit, setShowEdit] = useState(false);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<IdentityForm>({
    resolver: zodResolver(identitySchema),
    defaultValues: {
      display_name: tenant.display_name,
      email: tenant.email ?? "",
      phone: tenant.phone ?? "",
      status: tenant.status,
    },
  });

  const updateMut = useMutation({
    mutationFn: (vals: IdentityForm) =>
      updatePropertyTenant(tenant.tenant_id, {
        display_name: vals.display_name || null,
        email: vals.email || null,
        phone: vals.phone || null,
        status: vals.status ?? null,
      }),
    onSuccess: () => {
      toast.success("Tenant updated");
      setShowEdit(false);
      void queryClient.invalidateQueries({ queryKey: ["propertyTenants", "detail", tenant.tenant_id] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Update failed"),
  });

  const onSubmit = handleSubmit((vals) => updateMut.mutate(vals));

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            reset({
              display_name: tenant.display_name,
              email: tenant.email ?? "",
              phone: tenant.phone ?? "",
              status: tenant.status,
            });
            setShowEdit(true);
          }}
        >
          Edit
        </Button>
      </div>

      <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
        <div>
          <dt className="text-muted-foreground">Name</dt>
          <dd className="font-medium">{tenant.display_name}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Email</dt>
          <dd>{tenant.email ?? "—"}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Phone</dt>
          <dd>{tenant.phone ?? "—"}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Status</dt>
          <dd>{tenantStatusBadge(tenant.status)}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Active Unit</dt>
          <dd>{tenant.active_unit_id ?? "—"}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Party ID</dt>
          <dd>
            <code className="text-xs bg-muted px-1 py-0.5 rounded">{tenant.party_id || "—"}</code>
          </dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Created</dt>
          <dd>{fmtDate(tenant.created_at)}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Last Updated</dt>
          <dd>{fmtDate(tenant.updated_at)}</dd>
        </div>
      </dl>

      <Dialog open={showEdit} onOpenChange={setShowEdit}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Tenant</DialogTitle>
          </DialogHeader>
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="space-y-1">
              <Label htmlFor="edit_name">Full name *</Label>
              <Input id="edit_name" {...register("display_name")} />
              {errors.display_name && (
                <p className="text-xs text-destructive">{errors.display_name.message}</p>
              )}
            </div>
            <div className="space-y-1">
              <Label htmlFor="edit_email">Email</Label>
              <Input id="edit_email" type="email" {...register("email")} />
              {errors.email && (
                <p className="text-xs text-destructive">{errors.email.message}</p>
              )}
            </div>
            <div className="space-y-1">
              <Label htmlFor="edit_phone">Phone</Label>
              <Input id="edit_phone" type="tel" {...register("phone")} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="edit_status">Status</Label>
              <select
                id="edit_status"
                {...register("status")}
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm"
              >
                <option value="prospect">Prospect</option>
                <option value="active">Active</option>
                <option value="past">Past</option>
              </select>
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowEdit(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={isSubmitting || updateMut.isPending}>
                {updateMut.isPending ? "Saving…" : "Save"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function EmploymentTab({
  tenantId,
  profile,
}: {
  tenantId: string;
  profile: TenantProfileOut | undefined;
}) {
  const queryClient = useQueryClient();
  const [showEdit, setShowEdit] = useState(false);
  const emp = profile?.employment ?? {};

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<EmploymentForm>({
    resolver: zodResolver(employmentSchema),
    defaultValues: {
      employer_name: emp.employer_name ?? "",
      job_title: emp.job_title ?? "",
      employment_type: (emp.employment_type as EmploymentForm["employment_type"]) ?? undefined,
      start_date: emp.start_date ?? "",
      employer_phone: emp.employer_phone ?? "",
    },
  });

  const updateMut = useMutation({
    mutationFn: (vals: EmploymentForm) =>
      updateTenantProfile(tenantId, {
        employment: {
          employer_name: vals.employer_name,
          job_title: vals.job_title || undefined,
          employment_type: vals.employment_type || undefined,
          start_date: vals.start_date || undefined,
          employer_phone: vals.employer_phone || undefined,
        },
      }),
    onSuccess: () => {
      toast.success("Employment updated");
      setShowEdit(false);
      void queryClient.invalidateQueries({ queryKey: ["propertyTenants", "profile", tenantId] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Update failed"),
  });

  const onSubmit = handleSubmit((vals) => updateMut.mutate(vals));

  const EMP_TYPES: Record<string, string> = {
    full_time: "Full-time",
    part_time: "Part-time",
    self_employed: "Self-employed",
    contract: "Contract",
    unemployed: "Unemployed",
    retired: "Retired",
    student: "Student",
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            reset({
              employer_name: emp.employer_name ?? "",
              job_title: emp.job_title ?? "",
              employment_type: (emp.employment_type as EmploymentForm["employment_type"]) ?? undefined,
              start_date: emp.start_date ?? "",
              employer_phone: emp.employer_phone ?? "",
            });
            setShowEdit(true);
          }}
        >
          Edit
        </Button>
      </div>

      {!emp.employer_name ? (
        <p className="text-sm text-muted-foreground">No employment information on file.</p>
      ) : (
        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
          <div>
            <dt className="text-muted-foreground">Employer</dt>
            <dd className="font-medium">{emp.employer_name}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Job Title</dt>
            <dd>{emp.job_title ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Employment Type</dt>
            <dd>{emp.employment_type ? EMP_TYPES[emp.employment_type] ?? emp.employment_type : "—"}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Start Date</dt>
            <dd>{emp.start_date ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Employer Phone</dt>
            <dd>{emp.employer_phone ?? "—"}</dd>
          </div>
        </dl>
      )}

      <Dialog open={showEdit} onOpenChange={setShowEdit}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Employment</DialogTitle>
          </DialogHeader>
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="space-y-1">
              <Label htmlFor="emp_employer">Employer name *</Label>
              <Input id="emp_employer" {...register("employer_name")} />
              {errors.employer_name && (
                <p className="text-xs text-destructive">{errors.employer_name.message}</p>
              )}
            </div>
            <div className="space-y-1">
              <Label htmlFor="emp_title">Job title</Label>
              <Input id="emp_title" {...register("job_title")} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="emp_type">Employment type</Label>
              <select
                id="emp_type"
                {...register("employment_type")}
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm"
              >
                <option value="">— Select —</option>
                {Object.entries(EMP_TYPES).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="emp_start">Start date (YYYY-MM-DD)</Label>
              <Input id="emp_start" placeholder="2023-01-15" {...register("start_date")} />
              {errors.start_date && (
                <p className="text-xs text-destructive">{errors.start_date.message}</p>
              )}
            </div>
            <div className="space-y-1">
              <Label htmlFor="emp_phone">Employer phone</Label>
              <Input id="emp_phone" type="tel" {...register("employer_phone")} />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowEdit(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={isSubmitting || updateMut.isPending}>
                {updateMut.isPending ? "Saving…" : "Save"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function IncomeTab({
  tenantId,
  profile,
}: {
  tenantId: string;
  profile: TenantProfileOut | undefined;
}) {
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [docKind, setDocKind] = useState("other");
  const income = profile?.income ?? {};

  const verifyMut = useMutation({
    mutationFn: (status: string) => setIncomeVerification(tenantId, status),
    onSuccess: () => {
      toast.success("Verification status updated");
      void queryClient.invalidateQueries({ queryKey: ["propertyTenants", "profile", tenantId] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to update verification"),
  });

  // Income docs
  const docsQ = useQuery({
    queryKey: ["propertyTenants", "incomeDocs", tenantId],
    queryFn: () => listIncomeDocs(tenantId),
    retry: false,
  });

  const uploadMut = useMutation({
    mutationFn: (file: File) => uploadIncomeDoc(tenantId, file, docKind),
    onSuccess: () => {
      toast.success("Document uploaded");
      void queryClient.invalidateQueries({ queryKey: ["propertyTenants", "incomeDocs", tenantId] });
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof Error ? err.message : "Upload failed — check your documents list before retrying",
      ),
  });

  const deleteMut = useMutation({
    mutationFn: (docId: string) => deleteIncomeDoc(tenantId, docId),
    onSuccess: () => {
      toast.success("Document deleted");
      void queryClient.invalidateQueries({ queryKey: ["propertyTenants", "incomeDocs", tenantId] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Delete failed"),
  });

  const DOC_KINDS = [
    { value: "pay_stub", label: "Pay Stub" },
    { value: "tax_return", label: "Tax Return" },
    { value: "bank_statement", label: "Bank Statement" },
    { value: "offer_letter", label: "Offer Letter" },
    { value: "other", label: "Other" },
  ];

  return (
    <div className="space-y-6">
      {/* Income summary */}
      <div className="space-y-3">
        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
          <div>
            <dt className="text-muted-foreground">Annual Income</dt>
            <dd className="font-medium">
              {fmtCents(income.annual_income_cents, income.income_currency || "usd")}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Pay Frequency</dt>
            <dd>{income.pay_frequency ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Verification</dt>
            <dd>{verificationBadge(income.verification_status)}</dd>
          </div>
          {income.verification_status === "verified" && (
            <div>
              <dt className="text-muted-foreground">Verified on</dt>
              <dd>{fmtDate(income.verified_at)}</dd>
            </div>
          )}
        </dl>

        <div className="flex flex-wrap gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => verifyMut.mutate("verified")}
            disabled={verifyMut.isPending}
          >
            <CheckCircle2 className="h-3.5 w-3.5 mr-1" />
            Mark Verified
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => verifyMut.mutate("pending")}
            disabled={verifyMut.isPending}
          >
            Mark Pending
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => verifyMut.mutate("rejected")}
            disabled={verifyMut.isPending}
          >
            <XCircle className="h-3.5 w-3.5 mr-1" />
            Mark Rejected
          </Button>
        </div>
      </div>

      {/* Income docs */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center justify-between">
            Income Documents
            <div className="flex items-center gap-2">
              <Select value={docKind} onValueChange={setDocKind}>
                <SelectTrigger className="h-8 w-36 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {DOC_KINDS.map((dk) => (
                    <SelectItem key={dk.value} value={dk.value}>
                      {dk.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                size="sm"
                variant="outline"
                disabled={uploadMut.isPending}
                onClick={() => fileInputRef.current?.click()}
              >
                <Upload className="h-3.5 w-3.5 mr-1" />
                {uploadMut.isPending ? "Uploading…" : "Upload"}
              </Button>
              <input
                ref={fileInputRef}
                type="file"
                accept="*/*"
                className="hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) uploadMut.mutate(file);
                  e.target.value = "";
                }}
              />
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {docsQ.isLoading ? (
            <Skeleton className="h-10 w-full" />
          ) : (docsQ.data?.docs.length ?? 0) === 0 ? (
            <p className="text-sm text-muted-foreground">No documents uploaded yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>File</TableHead>
                  <TableHead>Kind</TableHead>
                  <TableHead>Size</TableHead>
                  <TableHead>Uploaded</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(docsQ.data?.docs ?? []).map((doc: IncomeDocOut) => (
                  <TableRow key={doc.doc_id}>
                    <TableCell className="font-medium">{doc.file_name}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">
                        {doc.doc_kind}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{fmtBytes(doc.size_bytes)}</TableCell>
                    <TableCell className="text-muted-foreground">{fmtDate(doc.uploaded_at)}</TableCell>
                    <TableCell>
                      <Button
                        size="icon"
                        variant="ghost"
                        disabled={deleteMut.isPending}
                        onClick={() => {
                          if (confirm(`Delete "${doc.file_name}"?`)) deleteMut.mutate(doc.doc_id);
                        }}
                      >
                        <Trash2 className="h-3.5 w-3.5 text-destructive" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function EmergencyContactsTab({ tenantId, profile }: { tenantId: string; profile: TenantProfileOut | undefined }) {
  const queryClient = useQueryClient();
  const serverContacts: EmergencyContactOut[] = profile?.emergency_contacts ?? [];
  const [localContacts, setLocalContacts] = useState<EmergencyContactOut[]>(serverContacts);
  const [showAdd, setShowAdd] = useState(false);
  const isDirty = JSON.stringify(localContacts) !== JSON.stringify(serverContacts);

  const {
    register,
    handleSubmit,
    reset: resetEc,
    formState: { errors: ecErrors },
  } = useForm<EcForm>({ resolver: zodResolver(ecSchema) });

  const saveMut = useMutation({
    mutationFn: (contacts: EmergencyContactOut[]) =>
      updateTenantProfile(tenantId, {
        emergency_contacts: contacts.map((c) => ({
          ec_id: c.ec_id,
          name: c.name,
          relationship: c.relationship ?? undefined,
          phone: c.phone ?? undefined,
          email: c.email ?? undefined,
        })),
      }),
    onSuccess: () => {
      toast.success("Emergency contacts saved");
      void queryClient.invalidateQueries({ queryKey: ["propertyTenants", "profile", tenantId] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Save failed"),
  });

  const onAddSubmit = handleSubmit((vals) => {
    const newContact: EmergencyContactOut = {
      ec_id: crypto.randomUUID(),
      name: vals.name,
      relationship: vals.relationship || null,
      phone: vals.phone || null,
      email: vals.email || null,
    };
    setLocalContacts((prev) => [...prev, newContact]);
    setShowAdd(false);
    resetEc();
  });

  const removeContact = (ecId: string) => {
    setLocalContacts((prev) => prev.filter((c) => c.ec_id !== ecId));
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">{localContacts.length} / 5 contacts</p>
        <div className="flex gap-2">
          {isDirty && (
            <Button
              size="sm"
              onClick={() => saveMut.mutate(localContacts)}
              disabled={saveMut.isPending}
            >
              {saveMut.isPending ? "Saving…" : "Save contacts"}
            </Button>
          )}
          <Button
            size="sm"
            variant="outline"
            disabled={localContacts.length >= 5}
            onClick={() => setShowAdd(true)}
            title={localContacts.length >= 5 ? "Maximum 5 emergency contacts" : undefined}
          >
            <PlusCircle className="h-3.5 w-3.5 mr-1" />
            Add contact
          </Button>
        </div>
      </div>

      {localContacts.length === 0 ? (
        <p className="text-sm text-muted-foreground">No emergency contacts on file.</p>
      ) : (
        <div className="space-y-2">
          {localContacts.map((c) => (
            <Card key={c.ec_id}>
              <CardContent className="py-3 flex items-center justify-between">
                <div className="space-y-0.5">
                  <p className="font-medium text-sm">{c.name}</p>
                  {c.relationship && (
                    <p className="text-xs text-muted-foreground">{c.relationship}</p>
                  )}
                  <p className="text-xs text-muted-foreground">
                    {[c.phone, c.email].filter(Boolean).join(" · ") || "No contact info"}
                  </p>
                </div>
                <Button
                  size="icon"
                  variant="ghost"
                  onClick={() => removeContact(c.ec_id)}
                >
                  <Trash2 className="h-3.5 w-3.5 text-destructive" />
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Dialog open={showAdd} onOpenChange={setShowAdd}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Add Emergency Contact</DialogTitle>
          </DialogHeader>
          <form onSubmit={onAddSubmit} className="space-y-4">
            <div className="space-y-1">
              <Label htmlFor="ec_name">Name *</Label>
              <Input id="ec_name" {...register("name")} />
              {ecErrors.name && (
                <p className="text-xs text-destructive">{ecErrors.name.message}</p>
              )}
            </div>
            <div className="space-y-1">
              <Label htmlFor="ec_rel">Relationship</Label>
              <Input id="ec_rel" placeholder="e.g. Spouse, Parent" {...register("relationship")} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="ec_phone">Phone</Label>
              <Input id="ec_phone" type="tel" {...register("phone")} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="ec_email">Email</Label>
              <Input id="ec_email" type="email" {...register("email")} />
              {ecErrors.email && (
                <p className="text-xs text-destructive">{ecErrors.email.message}</p>
              )}
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowAdd(false)}>
                Cancel
              </Button>
              <Button type="submit">Add</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function LeaseHistoryTab({ tenantId }: { tenantId: string }) {
  const { data, isLoading, fetchNextPage, hasNextPage, isFetchingNextPage } = useInfiniteQuery({
    queryKey: ["propertyTenants", "leases", tenantId],
    queryFn: ({ pageParam }: { pageParam: string | undefined }) =>
      listTenantLeases(tenantId, { cursor: pageParam }),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    initialPageParam: undefined as string | undefined,
    retry: false,
  });

  const leases: TenantLeaseSummaryOut[] = data?.pages.flatMap((p) => p.leases) ?? [];

  return (
    <div className="space-y-4">
      {isLoading ? (
        <Skeleton className="h-20 w-full" />
      ) : leases.length === 0 ? (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            No lease history.
          </CardContent>
        </Card>
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Unit</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Start</TableHead>
                <TableHead>End</TableHead>
                <TableHead>Rent / mo</TableHead>
                <TableHead>Deposit</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {leases.map((l) => (
                <TableRow key={l.lease_id}>
                  <TableCell className="font-mono text-xs">{l.unit_id}</TableCell>
                  <TableCell>{leaseStatusBadge(l.status)}</TableCell>
                  <TableCell className="text-muted-foreground">{fmtDate(l.start_date)}</TableCell>
                  <TableCell className="text-muted-foreground">{fmtDate(l.end_date)}</TableCell>
                  <TableCell>{fmtCents(l.monthly_rent_cents, l.currency)}</TableCell>
                  <TableCell>{fmtCents(l.security_deposit_cents, l.currency)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>

          {hasNextPage && (
            <div className="flex justify-center">
              <Button
                variant="outline"
                size="sm"
                onClick={() => void fetchNextPage()}
                disabled={isFetchingNextPage}
              >
                {isFetchingNextPage ? "Loading…" : "Load more"}
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function TenantProfilePage() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const navigate = useNavigate();
  const id = tenantId ?? "";

  const tenantQ = useQuery({
    queryKey: ["propertyTenants", "detail", id],
    queryFn: () => getPropertyTenant(id),
    enabled: !!id,
    retry: false,
  });

  const profileQ = useQuery({
    queryKey: ["propertyTenants", "profile", id],
    queryFn: () => getTenantProfile(id),
    enabled: !!id,
    retry: false,
  });

  // ─── Feature-disabled ─────────────────────────────────────────────────────

  if (tenantQ.isError && isFeatureDisabled(tenantQ.error)) {
    return (
      <div className="max-w-4xl mx-auto p-4 sm:p-6 space-y-4">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Link to="/property/tenants" className="hover:underline">
            Tenants
          </Link>
          <span>/</span>
          <span>—</span>
        </div>
        <Card>
          <CardContent className="py-8">
            <div className="flex items-center gap-2 text-muted-foreground">
              <AlertCircle className="h-5 w-5" />
              <p className="text-sm">
                Tenant management is currently disabled (
                <code className="font-mono">PROPERTY_TENANTS_ENABLED</code> is off). Contact your
                administrator.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // ─── 404 ─────────────────────────────────────────────────────────────────

  if (tenantQ.isError && tenantQ.error instanceof ApiError && tenantQ.error.status === 404) {
    return (
      <div className="max-w-4xl mx-auto p-4 sm:p-6 space-y-4">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Link to="/property/tenants" className="hover:underline">
            Tenants
          </Link>
          <span>/</span>
          <span>Not found</span>
        </div>
        <Card>
          <CardContent className="py-8 text-center space-y-3">
            <p className="text-lg font-medium">Tenant not found</p>
            <p className="text-sm text-muted-foreground">
              This tenant does not exist or you don't have access.
            </p>
            <Button variant="outline" onClick={() => navigate("/property/tenants")}>
              Back to tenants
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  // ─── Loading ──────────────────────────────────────────────────────────────

  if (tenantQ.isLoading) {
    return (
      <div className="max-w-4xl mx-auto p-4 sm:p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  const tenant = tenantQ.data;
  if (!tenant) return null;

  // ─── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="max-w-4xl mx-auto p-4 sm:p-6 space-y-4">
      {/* Breadcrumb */}
      <nav className="flex items-center gap-2 text-sm text-muted-foreground">
        <Link to="/property/tenants" className="hover:underline">
          Tenants
        </Link>
        <span>/</span>
        <span className="text-foreground font-medium">{tenant.display_name}</span>
      </nav>

      <PageHeader
        title={tenant.display_name}
        description={`Tenant profile`}
        actions={tenantStatusBadge(tenant.status)}
      />

      <Tabs defaultValue="identity">
        <TabsList className="grid grid-cols-5 w-full">
          <TabsTrigger value="identity">Identity</TabsTrigger>
          <TabsTrigger value="employment">Employment</TabsTrigger>
          <TabsTrigger value="income">Income</TabsTrigger>
          <TabsTrigger value="contacts">Emergency</TabsTrigger>
          <TabsTrigger value="leases">Leases</TabsTrigger>
        </TabsList>

        <TabsContent value="identity" className="mt-4">
          <IdentityTab tenant={tenant} />
        </TabsContent>

        <TabsContent value="employment" className="mt-4">
          <EmploymentTab tenantId={id} profile={profileQ.data} />
        </TabsContent>

        <TabsContent value="income" className="mt-4">
          <IncomeTab tenantId={id} profile={profileQ.data} />
        </TabsContent>

        <TabsContent value="contacts" className="mt-4">
          <EmergencyContactsTab tenantId={id} profile={profileQ.data} />
        </TabsContent>

        <TabsContent value="leases" className="mt-4">
          <LeaseHistoryTab tenantId={id} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
