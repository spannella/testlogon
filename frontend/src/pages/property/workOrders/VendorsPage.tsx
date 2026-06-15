/**
 * VendorsPage — Maintenance Vendor Directory (WOV-005)
 * Route: /property/vendors
 *
 * Feature flag: MAINTENANCE_ORDERS_ENABLED (backend default false → 404)
 *
 * Lists vendors with trade-category filter and status toggle.
 * Admins can create vendors, update details, and deactivate/reactivate.
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  AlertTriangle,
  Building,
  Mail,
  Phone,
  PlusCircle,
  RefreshCcw,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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
  createVendor,
  listVendors,
  listVendorCategories,
  setVendorStatus,
  type VendorOut,
  type VendorStatus,
} from "@/api/endpoints/maintenanceOrders";
import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function isFeatureDisabled(err: unknown): boolean {
  return (
    err instanceof ApiError &&
    (err.status === 404 || err.status === 503) &&
    /not enabled/i.test(err.detail ?? "")
  );
}

function fmtDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString();
}

const TRADE_LABEL: Record<string, string> = {
  plumbing: "Plumbing",
  electrical: "Electrical",
  hvac: "HVAC",
  handyman: "Handyman",
  cleaning: "Cleaning",
  landscaping: "Landscaping",
  general: "General",
};

// ─── Create vendor dialog ─────────────────────────────────────────────────────

interface CreateVendorDialogProps {
  categories: string[];
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}

function CreateVendorDialog({
  categories,
  open,
  onClose,
  onCreated,
}: CreateVendorDialogProps) {
  const [name, setName] = useState("");
  const [tradeCategory, setTradeCategory] = useState(categories[0] ?? "general");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [paymentTerms, setPaymentTerms] = useState("30");

  const createMut = useMutation({
    mutationFn: () =>
      createVendor({
        name: name.trim(),
        trade_category: tradeCategory,
        email: email.trim() || undefined,
        phone: phone.trim() || undefined,
        payment_terms_days: paymentTerms ? parseInt(paymentTerms, 10) : 30,
      }),
    onSuccess: () => {
      toast.success("Vendor created");
      setName("");
      setEmail("");
      setPhone("");
      setPaymentTerms("30");
      onCreated();
      onClose();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to create vendor"),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Add Vendor</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1">
            <Label>Vendor name *</Label>
            <Input
              placeholder="ABC Plumbing LLC"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={200}
            />
          </div>
          <div className="space-y-1">
            <Label>Trade category *</Label>
            <Select
              value={tradeCategory}
              onValueChange={setTradeCategory}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {categories.map((c) => (
                  <SelectItem key={c} value={c}>
                    {TRADE_LABEL[c] ?? c}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label>Email (optional)</Label>
            <Input
              type="email"
              placeholder="contact@vendor.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label>Phone (optional)</Label>
            <Input
              type="tel"
              placeholder="+1-555-000-0000"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label>Payment terms (days)</Label>
            <Input
              type="number"
              min="0"
              max="365"
              value={paymentTerms}
              onChange={(e) => setPaymentTerms(e.target.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={() => createMut.mutate()}
            disabled={!name.trim() || !tradeCategory || createMut.isPending}
          >
            {createMut.isPending ? "Creating…" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Vendor row actions ───────────────────────────────────────────────────────

interface VendorRowActionsProps {
  vendor: VendorOut;
  onDone: () => void;
}

function VendorRowActions({ vendor, onDone }: VendorRowActionsProps) {
  const targetStatus: VendorStatus =
    vendor.status === "active" ? "inactive" : "active";
  const label = vendor.status === "active" ? "Deactivate" : "Reactivate";

  const statusMut = useMutation({
    mutationFn: () => setVendorStatus(vendor.vendor_id, targetStatus),
    onSuccess: () => {
      toast.success(`Vendor ${targetStatus}`);
      onDone();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Status update failed"),
  });

  return (
    <div className="flex items-center gap-2">
      <Link
        to={`/property/vendors/${vendor.vendor_id}`}
        className="text-xs text-primary hover:underline"
      >
        View
      </Link>
      <Button
        variant="ghost"
        size="sm"
        className="text-xs h-6 px-2"
        onClick={() => statusMut.mutate()}
        disabled={statusMut.isPending}
      >
        {statusMut.isPending ? "…" : label}
      </Button>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function VendorsPage() {
  const token = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";

  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<VendorStatus>("active");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [createOpen, setCreateOpen] = useState(false);

  const categoriesQuery = useQuery({
    queryKey: ["vendor-categories"],
    queryFn: listVendorCategories,
    retry: false,
  });

  const vendorsQuery = useQuery({
    queryKey: ["vendors", statusFilter, categoryFilter],
    queryFn: () =>
      listVendors({
        status: statusFilter,
        trade_category: categoryFilter || undefined,
        limit: 100,
      }),
    retry: false,
  });

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["vendors"] });
  };

  // Feature disabled
  const error = categoriesQuery.error ?? vendorsQuery.error;
  if (isFeatureDisabled(error)) {
    return (
      <div className="p-6 space-y-4">
        <PageHeader title="Vendors" description="Maintenance vendor directory" />
        <Card>
          <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
            <AlertTriangle className="h-8 w-8 text-muted-foreground" />
            <p className="text-muted-foreground">
              Maintenance work orders are not enabled on this platform.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const categories = categoriesQuery.data?.categories ?? [];
  const vendors = vendorsQuery.data?.vendors ?? [];
  const loading = vendorsQuery.isLoading || categoriesQuery.isLoading;

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader
        title="Vendors"
        description="Trade-categorized maintenance vendor directory."
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refresh}>
              <RefreshCcw className="h-4 w-4 mr-1" />
              Refresh
            </Button>
            {isAdmin && (
              <Button size="sm" onClick={() => setCreateOpen(true)}>
                <PlusCircle className="h-4 w-4 mr-1" />
                Add Vendor
              </Button>
            )}
          </div>
        }
      />

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <Select
          value={statusFilter}
          onValueChange={(v) => setStatusFilter(v as VendorStatus)}
        >
          <SelectTrigger className="w-36">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="inactive">Inactive</SelectItem>
          </SelectContent>
        </Select>

        <Select
          value={categoryFilter || "all"}
          onValueChange={(v) => setCategoryFilter(v === "all" ? "" : v)}
        >
          <SelectTrigger className="w-44">
            <SelectValue placeholder="All categories" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All categories</SelectItem>
            {categories.map((c) => (
              <SelectItem key={c} value={c}>
                {TRADE_LABEL[c] ?? c}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Loading */}
      {loading && (
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      )}

      {/* Vendor table */}
      {!loading && (
        <>
          {vendors.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
                <Building className="h-8 w-8 text-muted-foreground" />
                <p className="text-muted-foreground">
                  No vendors found.
                  {isAdmin && ' Click "Add Vendor" to register one.'}
                </p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Contact</TableHead>
                      <TableHead>Terms</TableHead>
                      <TableHead>Created</TableHead>
                      {isAdmin && <TableHead>Actions</TableHead>}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {vendors.map((v) => (
                      <TableRow key={v.vendor_id}>
                        <TableCell>
                          <Link
                            to={`/property/vendors/${v.vendor_id}`}
                            className="font-medium text-primary hover:underline"
                          >
                            {v.name}
                          </Link>
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary">
                            {TRADE_LABEL[v.trade_category] ?? v.trade_category}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={
                              v.status === "active"
                                ? "bg-green-100 text-green-700"
                                : "bg-gray-100 text-gray-600"
                            }
                          >
                            {v.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="space-y-0.5">
                            {v.email && (
                              <div className="flex items-center gap-1 text-xs text-muted-foreground">
                                <Mail className="h-3 w-3" />
                                {v.email}
                              </div>
                            )}
                            {v.phone && (
                              <div className="flex items-center gap-1 text-xs text-muted-foreground">
                                <Phone className="h-3 w-3" />
                                {v.phone}
                              </div>
                            )}
                            {!v.email && !v.phone && (
                              <span className="text-xs text-muted-foreground">—</span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-sm">
                          Net {v.payment_terms_days}d
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {fmtDate(v.created_at)}
                        </TableCell>
                        {isAdmin && (
                          <TableCell>
                            <VendorRowActions vendor={v} onDone={refresh} />
                          </TableCell>
                        )}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Category stats */}
      {!loading && categories.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">By Category</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {categories.map((c) => {
                const count = vendors.filter((v) => v.trade_category === c).length;
                return (
                  <Button
                    key={c}
                    variant={categoryFilter === c ? "default" : "outline"}
                    size="sm"
                    onClick={() =>
                      setCategoryFilter(categoryFilter === c ? "" : c)
                    }
                  >
                    {TRADE_LABEL[c] ?? c}
                    <Badge variant="secondary" className="ml-2">
                      {count}
                    </Badge>
                  </Button>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {isAdmin && (
        <CreateVendorDialog
          categories={categories.length > 0 ? categories : ["general"]}
          open={createOpen}
          onClose={() => setCreateOpen(false)}
          onCreated={refresh}
        />
      )}
    </div>
  );
}
