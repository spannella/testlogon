import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { ShoppingCart, Plus } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
import { Skeleton } from "@/components/ui/skeleton";

import {
  listPurchaseOrders,
  listSuppliers,
  formatCents,
  type PurchaseOrder,
  type Supplier,
} from "@/api/endpoints/purchasing";
import { ApiError } from "@/api/client";
import { PoStatusBadge, SupplierStatusBadge, fmtTs } from "./poStatus";
import { CreatePoDialog } from "./CreatePoDialog";
import { SupplierDialog } from "./SupplierDialog";
import { ReorderPanel } from "./ReorderPanel";

const PO_STATUSES = [
  "draft",
  "submitted",
  "approved",
  "ordered",
  "partially_received",
  "received",
  "closed",
  "rejected",
  "cancelled",
];

function FeatureDisabledCard() {
  return (
    <Card>
      <CardContent className="py-12 text-center text-muted-foreground">
        <ShoppingCart className="mx-auto mb-3 h-10 w-10 opacity-40" />
        <p className="font-medium">Purchasing is not enabled</p>
        <p className="text-sm">
          The Purchasing &amp; SCM module is currently disabled for this platform.
        </p>
      </CardContent>
    </Card>
  );
}

function isFeatureDisabled(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

// ─── Purchase Orders tab ──────────────────────────────────────────────────────

function PurchaseOrdersTab() {
  const navigate = useNavigate();
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [createOpen, setCreateOpen] = useState(false);

  const poQuery = useQuery({
    queryKey: ["purchasing", "pos", statusFilter],
    queryFn: () =>
      listPurchaseOrders({
        status: statusFilter === "all" ? undefined : statusFilter,
        limit: 100,
      }),
    retry: (count, err) => !isFeatureDisabled(err) && count < 2,
  });

  if (isFeatureDisabled(poQuery.error)) return <FeatureDisabledCard />;

  const orders: PurchaseOrder[] = poQuery.data?.purchase_orders ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="All statuses" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            {PO_STATUSES.map((s) => (
              <SelectItem key={s} value={s} className="capitalize">
                {s.replace(/_/g, " ")}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> New Purchase Order
        </Button>
      </div>

      <Card>
        <CardContent className="p-0">
          {poQuery.isLoading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : orders.length === 0 ? (
            <div className="py-12 text-center text-sm text-muted-foreground">
              No purchase orders yet. Create one to get started.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>PO ID</TableHead>
                  <TableHead>Supplier</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Lines</TableHead>
                  <TableHead className="text-right">Subtotal</TableHead>
                  <TableHead>Expected</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {orders.map((po) => (
                  <TableRow
                    key={po.po_id}
                    className="cursor-pointer"
                    onClick={() => navigate(`/purchasing/purchase-orders/${po.po_id}`)}
                  >
                    <TableCell className="font-mono text-xs">{po.po_id}</TableCell>
                    <TableCell className="font-mono text-xs">{po.supplier_id}</TableCell>
                    <TableCell>
                      <PoStatusBadge status={po.status} />
                    </TableCell>
                    <TableCell className="text-right">{po.lines.length}</TableCell>
                    <TableCell className="text-right font-medium">
                      {formatCents(po.subtotal_cents, po.currency)}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {po.expected_delivery_date || "—"}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {fmtTs(po.created_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <CreatePoDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={(po) => {
          setCreateOpen(false);
          navigate(`/purchasing/purchase-orders/${po.po_id}`);
        }}
      />
    </div>
  );
}

// ─── Suppliers tab ────────────────────────────────────────────────────────────

function SuppliersTab() {
  const navigate = useNavigate();
  const [statusFilter, setStatusFilter] = useState<string>("active");
  const [createOpen, setCreateOpen] = useState(false);

  const supQuery = useQuery({
    queryKey: ["purchasing", "suppliers", statusFilter],
    queryFn: () => listSuppliers({ status: statusFilter, limit: 100 }),
    retry: (count, err) => !isFeatureDisabled(err) && count < 2,
  });

  if (isFeatureDisabled(supQuery.error)) return <FeatureDisabledCard />;

  const suppliers: Supplier[] = supQuery.data?.suppliers ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="inactive">Inactive</SelectItem>
          </SelectContent>
        </Select>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> New Supplier
        </Button>
      </div>

      <Card>
        <CardContent className="p-0">
          {supQuery.isLoading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : suppliers.length === 0 ? (
            <div className="py-12 text-center text-sm text-muted-foreground">
              No {statusFilter} suppliers.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Email</TableHead>
                  <TableHead>Phone</TableHead>
                  <TableHead>Currency</TableHead>
                  <TableHead className="text-right">Terms (days)</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {suppliers.map((s) => (
                  <TableRow
                    key={s.supplier_id}
                    className="cursor-pointer"
                    onClick={() => navigate(`/purchasing/suppliers/${s.supplier_id}`)}
                  >
                    <TableCell className="font-medium">{s.name}</TableCell>
                    <TableCell>
                      <SupplierStatusBadge status={s.status} />
                    </TableCell>
                    <TableCell className="text-sm">{s.email || "—"}</TableCell>
                    <TableCell className="text-sm">{s.phone || "—"}</TableCell>
                    <TableCell className="text-sm">{s.default_currency}</TableCell>
                    <TableCell className="text-right text-sm">{s.payment_terms_days}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <SupplierDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onSaved={(s) => {
          setCreateOpen(false);
          navigate(`/purchasing/suppliers/${s.supplier_id}`);
        }}
      />
    </div>
  );
}

// ─── Page shell ───────────────────────────────────────────────────────────────

export default function PurchasingPage() {
  const [tab, setTab] = useState("purchase-orders");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Purchasing"
        description="Manage suppliers, purchase orders, and reorder suggestions."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="purchase-orders">Purchase Orders</TabsTrigger>
          <TabsTrigger value="suppliers">Suppliers</TabsTrigger>
          <TabsTrigger value="reorder">Reorder</TabsTrigger>
        </TabsList>
        <TabsContent value="purchase-orders" className="mt-4">
          <PurchaseOrdersTab />
        </TabsContent>
        <TabsContent value="suppliers" className="mt-4">
          <SuppliersTab />
        </TabsContent>
        <TabsContent value="reorder" className="mt-4">
          <ReorderPanel />
        </TabsContent>
      </Tabs>
    </div>
  );
}
