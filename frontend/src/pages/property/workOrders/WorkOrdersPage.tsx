/**
 * WorkOrdersPage — Maintenance Work-Orders Board (WOV-005)
 * Route: /property/work-orders
 *
 * Feature flag: MAINTENANCE_ORDERS_ENABLED (backend default false → 404)
 * When the flag is off, the backend returns 404 "not enabled".
 * This page detects that case and shows a clean "feature not enabled" banner.
 *
 * Board view: columns per work-order status, each column lists WOs sorted newest-first.
 * List view: table of all work orders with status/priority filters.
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  AlertTriangle,
  Columns,
  List,
  PlusCircle,
  RefreshCcw,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
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
import { Textarea } from "@/components/ui/textarea";

import { ApiError } from "@/api/client";
import {
  getBoardColumns,
  listWorkOrders,
  createWorkOrder,
  transitionWorkOrder,
  type MaintenanceOrderOut,
  type WoBoardColumn,
  type WoPriority,
  type WoStatus,
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

function fmtDate(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

function fmtCents(cents: number | null | undefined): string {
  if (cents == null) return "—";
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

const PRIORITY_COLORS: Record<WoPriority, string> = {
  urgent: "bg-red-100 text-red-700",
  high: "bg-orange-100 text-orange-700",
  normal: "bg-blue-100 text-blue-700",
  low: "bg-gray-100 text-gray-600",
};

const STATUS_COLORS: Record<WoStatus, string> = {
  open: "bg-yellow-100 text-yellow-700",
  assigned: "bg-blue-100 text-blue-700",
  in_progress: "bg-purple-100 text-purple-700",
  completed: "bg-green-100 text-green-700",
  cancelled: "bg-gray-100 text-gray-600",
};

function PriorityBadge({ priority }: { priority: string }) {
  const cls =
    PRIORITY_COLORS[priority as WoPriority] ?? "bg-gray-100 text-gray-600";
  return (
    <Badge variant="outline" className={cls}>
      {priority}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cls =
    STATUS_COLORS[status as WoStatus] ?? "bg-gray-100 text-gray-600";
  return (
    <Badge variant="outline" className={cls}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

// ─── Create WO dialog ─────────────────────────────────────────────────────────

interface CreateWoDialogProps {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}

function CreateWoDialog({ open, onClose, onCreated }: CreateWoDialogProps) {
  const [propertyId, setPropertyId] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState<WoPriority>("normal");
  const [unitId, setUnitId] = useState("");

  const createMut = useMutation({
    mutationFn: () =>
      createWorkOrder(propertyId.trim(), {
        title: title.trim(),
        description: description.trim() || undefined,
        priority,
        property_id: propertyId.trim(),
        unit_id: unitId.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success("Work order created");
      setPropertyId("");
      setTitle("");
      setDescription("");
      setPriority("normal");
      setUnitId("");
      onCreated();
      onClose();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to create work order"),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>New Work Order</DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1">
            <Label>Property ID *</Label>
            <Input
              placeholder="property_id"
              value={propertyId}
              onChange={(e) => setPropertyId(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label>Title *</Label>
            <Input
              placeholder="Brief description of the issue"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              maxLength={200}
            />
          </div>
          <div className="space-y-1">
            <Label>Description</Label>
            <Textarea
              placeholder="Detailed notes..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={2000}
              rows={3}
            />
          </div>
          <div className="space-y-1">
            <Label>Priority</Label>
            <Select
              value={priority}
              onValueChange={(v) => setPriority(v as WoPriority)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="urgent">Urgent</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="normal">Normal</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label>Unit ID (optional)</Label>
            <Input
              placeholder="unit_id"
              value={unitId}
              onChange={(e) => setUnitId(e.target.value)}
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={() => createMut.mutate()}
            disabled={!propertyId.trim() || !title.trim() || createMut.isPending}
          >
            {createMut.isPending ? "Creating…" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Kanban column card ───────────────────────────────────────────────────────

function WoCard({ wo }: { wo: MaintenanceOrderOut }) {
  return (
    <Link to={`/property/work-orders/${wo.property_id}/${wo.work_order_id}`}>
      <Card className="hover:shadow-md transition-shadow cursor-pointer mb-2">
        <CardContent className="p-3 space-y-1">
          <p className="text-sm font-medium line-clamp-2">{wo.title}</p>
          <div className="flex items-center gap-1 flex-wrap">
            <PriorityBadge priority={wo.priority} />
            {wo.vendor_id && (
              <span className="text-xs text-muted-foreground">
                Vendor: {wo.vendor_id.slice(0, 8)}…
              </span>
            )}
          </div>
          {wo.scheduled_for && (
            <p className="text-xs text-muted-foreground">
              Sched: {fmtDate(wo.scheduled_for)}
            </p>
          )}
          <p className="text-xs text-muted-foreground">
            Updated {fmtDate(wo.updated_at)}
          </p>
        </CardContent>
      </Card>
    </Link>
  );
}

// ─── Kanban board ─────────────────────────────────────────────────────────────

interface KanbanBoardProps {
  columns: WoBoardColumn[];
  wosByStatus: Record<string, MaintenanceOrderOut[]>;
  isAdmin: boolean;
  onTransition: (wo: MaintenanceOrderOut, target: WoStatus) => void;
  transitioning: boolean;
}

function KanbanBoard({
  columns,
  wosByStatus,
}: KanbanBoardProps) {
  const sorted = [...columns].sort((a, b) => a.order - b.order);

  return (
    <div className="flex gap-4 overflow-x-auto pb-4">
      {sorted.map((col) => {
        const items = wosByStatus[col.status_key] ?? [];
        return (
          <div
            key={col.column_id}
            className="flex-shrink-0 w-64 bg-muted/40 rounded-lg p-3"
          >
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold">{col.title}</h3>
              <Badge variant="secondary" className="text-xs">
                {items.length}
              </Badge>
            </div>
            <div className="space-y-2">
              {items.map((wo) => (
                <WoCard key={wo.work_order_id} wo={wo} />
              ))}
              {items.length === 0 && (
                <p className="text-xs text-muted-foreground text-center py-4">
                  No orders
                </p>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function WorkOrdersPage() {
  const token = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";

  const qc = useQueryClient();
  const [viewMode, setViewMode] = useState<"board" | "list">("board");
  const [statusFilter, setStatusFilter] = useState<WoStatus | "">("");
  const [createOpen, setCreateOpen] = useState(false);

  // Board columns
  const columnsQuery = useQuery({
    queryKey: ["wo-board-columns"],
    queryFn: getBoardColumns,
    retry: false,
  });

  // Work orders — all statuses for board; filtered for list
  const woQueries = (
    ["open", "assigned", "in_progress", "completed", "cancelled"] as WoStatus[]
  ).map((status) =>
    // eslint-disable-next-line react-hooks/rules-of-hooks
    useQuery({
      queryKey: ["work-orders", "status", status],
      queryFn: () => listWorkOrders({ wo_status: status, limit: 100 }),
      retry: false,
      enabled: viewMode === "board",
    }),
  );

  const listQuery = useQuery({
    queryKey: ["work-orders", "list", statusFilter],
    queryFn: () =>
      listWorkOrders({ wo_status: statusFilter || undefined, limit: 100 }),
    retry: false,
    enabled: viewMode === "list",
  });

  const transitionMut = useMutation({
    mutationFn: ({
      wo,
      target,
    }: {
      wo: MaintenanceOrderOut;
      target: WoStatus;
    }) =>
      transitionWorkOrder(wo.work_order_id, {
        property_id: wo.property_id,
        target_status: target as "assigned" | "in_progress" | "completed" | "cancelled",
      }),
    onSuccess: () => {
      toast.success("Status updated");
      void qc.invalidateQueries({ queryKey: ["work-orders"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Transition failed"),
  });

  // Feature disabled detection
  const firstError =
    columnsQuery.error ?? woQueries.find((q) => q.error)?.error ?? listQuery.error;
  if (isFeatureDisabled(firstError)) {
    return (
      <div className="p-6 space-y-4">
        <PageHeader
          title="Work Orders"
          description="Maintenance work-order board"
        />
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

  // Build board data
  const wosByStatus: Record<string, MaintenanceOrderOut[]> = {};
  woQueries.forEach((q, i) => {
    const statuses: WoStatus[] = [
      "open",
      "assigned",
      "in_progress",
      "completed",
      "cancelled",
    ];
    const s = statuses[i]!;
    wosByStatus[s] = q.data?.items ?? [];
  });

  const columns = columnsQuery.data?.columns ?? [];
  const listItems = listQuery.data?.items ?? [];

  const loading =
    columnsQuery.isLoading ||
    (viewMode === "board" && woQueries.some((q) => q.isLoading)) ||
    (viewMode === "list" && listQuery.isLoading);

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["work-orders"] });
    void qc.invalidateQueries({ queryKey: ["wo-board-columns"] });
  };

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader
        title="Work Orders"
        description="Maintenance work-order board — create, assign, and track jobs."
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refresh}>
              <RefreshCcw className="h-4 w-4 mr-1" />
              Refresh
            </Button>
            {isAdmin && (
              <Button size="sm" onClick={() => setCreateOpen(true)}>
                <PlusCircle className="h-4 w-4 mr-1" />
                New Work Order
              </Button>
            )}
          </div>
        }
      />

      {/* View toggle */}
      <div className="flex items-center gap-2">
        <Button
          variant={viewMode === "board" ? "default" : "outline"}
          size="sm"
          onClick={() => setViewMode("board")}
          data-testid="view-board-btn"
        >
          <Columns className="h-4 w-4 mr-1" />
          Board
        </Button>
        <Button
          variant={viewMode === "list" ? "default" : "outline"}
          size="sm"
          onClick={() => setViewMode("list")}
          data-testid="view-list-btn"
        >
          <List className="h-4 w-4 mr-1" />
          List
        </Button>

        {viewMode === "list" && (
          <Select
            value={statusFilter || "all"}
            onValueChange={(v) => setStatusFilter(v === "all" ? "" : (v as WoStatus))}
          >
            <SelectTrigger className="w-40">
              <SelectValue placeholder="All statuses" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="open">Open</SelectItem>
              <SelectItem value="assigned">Assigned</SelectItem>
              <SelectItem value="in_progress">In Progress</SelectItem>
              <SelectItem value="completed">Completed</SelectItem>
              <SelectItem value="cancelled">Cancelled</SelectItem>
            </SelectContent>
          </Select>
        )}
      </div>

      {/* Loading skeletons */}
      {loading && (
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      )}

      {/* Board view */}
      {!loading && viewMode === "board" && (
        <KanbanBoard
          columns={columns}
          wosByStatus={wosByStatus}
          isAdmin={isAdmin}
          onTransition={(wo, target) => transitionMut.mutate({ wo, target })}
          transitioning={transitionMut.isPending}
        />
      )}

      {/* List view */}
      {!loading && viewMode === "list" && (
        <>
          {listItems.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
                <p className="text-muted-foreground">
                  No work orders found.
                  {isAdmin && ' Click "New Work Order" to create one.'}
                </p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Title</TableHead>
                      <TableHead>Priority</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Property</TableHead>
                      <TableHead>Scheduled</TableHead>
                      <TableHead>Cost</TableHead>
                      <TableHead>Updated</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {listItems.map((wo) => (
                      <TableRow key={wo.work_order_id}>
                        <TableCell>
                          <Link
                            to={`/property/work-orders/${wo.property_id}/${wo.work_order_id}`}
                            className="text-primary hover:underline font-medium"
                          >
                            {wo.title}
                          </Link>
                        </TableCell>
                        <TableCell>
                          <PriorityBadge priority={wo.priority} />
                        </TableCell>
                        <TableCell>
                          <StatusBadge status={wo.wo_status} />
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground font-mono">
                          {wo.property_id.slice(0, 12)}…
                        </TableCell>
                        <TableCell className="text-sm">
                          {fmtDate(wo.scheduled_for)}
                        </TableCell>
                        <TableCell className="text-sm">
                          {fmtCents(wo.cost_cents)}
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {fmtDate(wo.updated_at)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {isAdmin && (
        <CreateWoDialog
          open={createOpen}
          onClose={() => setCreateOpen(false)}
          onCreated={refresh}
        />
      )}
    </div>
  );
}
