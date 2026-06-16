/**
 * WorkOrderDetailPage — Work-Order Detail + Actions (WOV-005)
 * Route: /property/work-orders/:propertyId/:workOrderId
 *
 * Shows full work-order details, allows admins to:
 *  - Assign vendor / assignee (PATCH /assign)
 *  - Set scheduled date (PATCH /schedule)
 *  - Transition status (PATCH /:id)
 *  - Record cost (on "completed" transition)
 */

import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { AlertTriangle, ArrowLeft, CalendarClock, DollarSign, User, Wrench } from "lucide-react";

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

import { ApiError } from "@/api/client";
import {
  getWorkOrder,
  assignWorkOrder,
  scheduleWorkOrder,
  transitionWorkOrder,
  type MaintenanceOrderOut,
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
  return new Date(ts * 1000).toLocaleString();
}

function fmtCents(cents: number | null | undefined): string {
  if (cents == null) return "—";
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

const PRIORITY_COLORS: Record<string, string> = {
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

// Valid transitions per status (mirrors backend VALID_TRANSITIONS)
const VALID_TRANSITIONS: Record<WoStatus, WoStatus[]> = {
  open: ["assigned", "in_progress", "cancelled"],
  assigned: ["in_progress", "open", "cancelled"],
  in_progress: ["completed", "cancelled"],
  completed: [],
  cancelled: [],
};

// ─── Assign dialog ────────────────────────────────────────────────────────────

interface AssignDialogProps {
  wo: MaintenanceOrderOut;
  open: boolean;
  onClose: () => void;
  onDone: () => void;
}

function AssignDialog({ wo, open, onClose, onDone }: AssignDialogProps) {
  const [vendorId, setVendorId] = useState(wo.vendor_id ?? "");
  const [assigneeSub, setAssigneeSub] = useState(wo.assignee_sub ?? "");
  const [unitId, setUnitId] = useState(wo.unit_id ?? "");

  const assignMut = useMutation({
    mutationFn: () =>
      assignWorkOrder(wo.work_order_id, {
        property_id: wo.property_id,
        vendor_id: vendorId.trim() || undefined,
        assignee_sub: assigneeSub.trim() || undefined,
        unit_id: unitId.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success("Work order assigned");
      onDone();
      onClose();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Assignment failed"),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>Assign Work Order</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1">
            <Label>Vendor ID</Label>
            <Input
              placeholder="vendor_id (leave blank to skip)"
              value={vendorId}
              onChange={(e) => setVendorId(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label>Assignee user_sub</Label>
            <Input
              placeholder="user_sub (leave blank to skip)"
              value={assigneeSub}
              onChange={(e) => setAssigneeSub(e.target.value)}
            />
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
            onClick={() => assignMut.mutate()}
            disabled={
              (!vendorId.trim() && !assigneeSub.trim()) || assignMut.isPending
            }
          >
            {assignMut.isPending ? "Saving…" : "Assign"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Schedule dialog ──────────────────────────────────────────────────────────

interface ScheduleDialogProps {
  wo: MaintenanceOrderOut;
  open: boolean;
  onClose: () => void;
  onDone: () => void;
}

function ScheduleDialog({ wo, open, onClose, onDone }: ScheduleDialogProps) {
  const defaultDate = wo.scheduled_for
    ? new Date(wo.scheduled_for * 1000).toISOString().slice(0, 16)
    : "";
  const [dateStr, setDateStr] = useState(defaultDate);

  const scheduleMut = useMutation({
    mutationFn: () => {
      const ts = Math.floor(new Date(dateStr).getTime() / 1000);
      return scheduleWorkOrder(wo.work_order_id, {
        property_id: wo.property_id,
        scheduled_for: ts,
      });
    },
    onSuccess: () => {
      toast.success("Scheduled date set");
      onDone();
      onClose();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Schedule failed"),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>Schedule Work Order</DialogTitle>
        </DialogHeader>
        <div className="space-y-2">
          <Label>Planned date &amp; time</Label>
          <Input
            type="datetime-local"
            value={dateStr}
            onChange={(e) => setDateStr(e.target.value)}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={() => scheduleMut.mutate()}
            disabled={!dateStr || scheduleMut.isPending}
          >
            {scheduleMut.isPending ? "Saving…" : "Set Date"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Transition dialog ────────────────────────────────────────────────────────

interface TransitionDialogProps {
  wo: MaintenanceOrderOut;
  open: boolean;
  onClose: () => void;
  onDone: () => void;
}

function TransitionDialog({ wo, open, onClose, onDone }: TransitionDialogProps) {
  const targets = VALID_TRANSITIONS[wo.wo_status as WoStatus] ?? [];
  const [target, setTarget] = useState<WoStatus | "">(targets[0] ?? "");
  const [costCents, setCostCents] = useState("");

  const transitionMut = useMutation({
    mutationFn: () => {
      if (!target) throw new Error("Select a status");
      const cost =
        target === "completed" && costCents.trim()
          ? Math.round(parseFloat(costCents) * 100)
          : undefined;
      return transitionWorkOrder(wo.work_order_id, {
        property_id: wo.property_id,
        target_status: target as "assigned" | "in_progress" | "completed" | "cancelled",
        cost_cents: cost,
      });
    },
    onSuccess: () => {
      toast.success("Status updated");
      onDone();
      onClose();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Transition failed"),
  });

  if (targets.length === 0) {
    return (
      <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Change Status</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            This work order is in a terminal status and cannot be transitioned further.
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={onClose}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>Change Status</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1">
            <Label>New status</Label>
            <Select value={target} onValueChange={(v) => setTarget(v as WoStatus)}>
              <SelectTrigger>
                <SelectValue placeholder="Select…" />
              </SelectTrigger>
              <SelectContent>
                {targets.map((t) => (
                  <SelectItem key={t} value={t}>
                    {t.replace(/_/g, " ")}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {target === "completed" && (
            <div className="space-y-1">
              <Label>Actual cost (USD, optional)</Label>
              <Input
                type="number"
                min="0"
                step="0.01"
                placeholder="e.g. 250.00"
                value={costCents}
                onChange={(e) => setCostCents(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Leave blank to skip cost recording.
              </p>
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={() => transitionMut.mutate()}
            disabled={!target || transitionMut.isPending}
          >
            {transitionMut.isPending ? "Saving…" : "Update"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Detail row helper ────────────────────────────────────────────────────────

function DetailRow({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div className="flex justify-between py-2 border-b last:border-0">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="text-sm font-medium text-right max-w-xs">{value}</span>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function WorkOrderDetailPage() {
  const { propertyId = "", workOrderId = "" } = useParams<{
    propertyId: string;
    workOrderId: string;
  }>();
  const token = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";

  const qc = useQueryClient();
  const [assignOpen, setAssignOpen] = useState(false);
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const [transitionOpen, setTransitionOpen] = useState(false);

  const woQuery = useQuery({
    queryKey: ["work-order", propertyId, workOrderId],
    queryFn: () => getWorkOrder(propertyId, workOrderId),
    enabled: !!propertyId && !!workOrderId,
    retry: false,
  });

  const refresh = () =>
    void qc.invalidateQueries({ queryKey: ["work-order", propertyId, workOrderId] });

  if (woQuery.isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }

  if (isFeatureDisabled(woQuery.error)) {
    return (
      <div className="p-6 space-y-4">
        <Link
          to="/property/work-orders"
          className="flex items-center gap-1 text-sm text-muted-foreground hover:underline"
        >
          <ArrowLeft className="h-4 w-4" /> Back
        </Link>
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

  if (woQuery.error) {
    return (
      <div className="p-6 space-y-4">
        <Link
          to="/property/work-orders"
          className="flex items-center gap-1 text-sm text-muted-foreground hover:underline"
        >
          <ArrowLeft className="h-4 w-4" /> Back
        </Link>
        <p className="text-destructive text-sm">
          {woQuery.error instanceof Error
            ? woQuery.error.message
            : "Failed to load work order."}
        </p>
      </div>
    );
  }

  const wo = woQuery.data;
  if (!wo) return null;

  const statusColor =
    STATUS_COLORS[wo.wo_status as WoStatus] ?? "bg-gray-100 text-gray-600";
  const priorityColor =
    PRIORITY_COLORS[wo.priority] ?? "bg-gray-100 text-gray-600";

  return (
    <div className="p-4 md:p-6 lg:p-8 space-y-6 max-w-3xl">
      <div>
        <Link
          to="/property/work-orders"
          className="flex items-center gap-1 text-sm text-muted-foreground hover:underline mb-3"
        >
          <ArrowLeft className="h-4 w-4" /> Back to Work Orders
        </Link>
        <PageHeader
          title={wo.title}
          description={`Work order #${wo.work_order_id.slice(0, 12)}…`}
          actions={
            isAdmin ? (
              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setAssignOpen(true)}
                  disabled={
                    wo.wo_status === "completed" || wo.wo_status === "cancelled"
                  }
                >
                  <User className="h-4 w-4 mr-1" />
                  Assign
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setScheduleOpen(true)}
                  disabled={
                    wo.wo_status === "completed" || wo.wo_status === "cancelled"
                  }
                >
                  <CalendarClock className="h-4 w-4 mr-1" />
                  Schedule
                </Button>
                <Button
                  size="sm"
                  onClick={() => setTransitionOpen(true)}
                >
                  <Wrench className="h-4 w-4 mr-1" />
                  Change Status
                </Button>
              </div>
            ) : undefined
          }
        />
      </div>

      {/* Status + Priority */}
      <div className="flex items-center gap-3">
        <Badge variant="outline" className={statusColor}>
          {wo.wo_status.replace(/_/g, " ")}
        </Badge>
        <Badge variant="outline" className={priorityColor}>
          {wo.priority}
        </Badge>
      </div>

      {/* Description */}
      {wo.description && (
        <Card>
          <CardContent className="pt-4">
            <p className="text-sm whitespace-pre-wrap">{wo.description}</p>
          </CardContent>
        </Card>
      )}

      {/* Details */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Details</CardTitle>
        </CardHeader>
        <CardContent>
          <DetailRow
            label="Property"
            value={
              <span className="font-mono text-xs">{wo.property_id}</span>
            }
          />
          {wo.unit_id && (
            <DetailRow
              label="Unit"
              value={<span className="font-mono text-xs">{wo.unit_id}</span>}
            />
          )}
          {wo.vendor_id && (
            <DetailRow
              label="Vendor"
              value={
                <Link
                  to={`/property/vendors/${wo.vendor_id}`}
                  className="text-primary hover:underline font-mono text-xs"
                >
                  {wo.vendor_id}
                </Link>
              }
            />
          )}
          {wo.assignee_sub && (
            <DetailRow
              label="Assignee"
              value={
                <span className="font-mono text-xs">{wo.assignee_sub}</span>
              }
            />
          )}
          <DetailRow label="Scheduled" value={fmtDate(wo.scheduled_for)} />
          <DetailRow
            label="Cost"
            value={
              <span className="flex items-center gap-1">
                <DollarSign className="h-3 w-3" />
                {fmtCents(wo.cost_cents)}
              </span>
            }
          />
          <DetailRow label="Created" value={fmtDate(wo.created_at)} />
          <DetailRow label="Updated" value={fmtDate(wo.updated_at)} />
          {wo.completed_at && (
            <DetailRow label="Completed" value={fmtDate(wo.completed_at)} />
          )}
          <DetailRow
            label="Correlation ID"
            value={
              <span className="font-mono text-xs">{wo.correlation_id}</span>
            }
          />
        </CardContent>
      </Card>

      {/* WOV-003 escrow section (shown only when escrow data is present) */}
      {wo.escrow_amount_cents != null && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Escrow</CardTitle>
          </CardHeader>
          <CardContent>
            <DetailRow
              label="Escrowed amount"
              value={fmtCents(wo.escrow_amount_cents)}
            />
            <DetailRow
              label="Escrow status"
              value={
                <Badge variant="outline">
                  {wo.escrow_status ?? "—"}
                </Badge>
              }
            />
          </CardContent>
        </Card>
      )}

      {/* Dialogs */}
      {isAdmin && (
        <>
          <AssignDialog
            wo={wo}
            open={assignOpen}
            onClose={() => setAssignOpen(false)}
            onDone={refresh}
          />
          <ScheduleDialog
            wo={wo}
            open={scheduleOpen}
            onClose={() => setScheduleOpen(false)}
            onDone={refresh}
          />
          <TransitionDialog
            wo={wo}
            open={transitionOpen}
            onClose={() => setTransitionOpen(false)}
            onDone={refresh}
          />
        </>
      )}
    </div>
  );
}
