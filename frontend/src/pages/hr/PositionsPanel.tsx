import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Briefcase, Plus } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
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
import { EmptyState } from "@/components/shared/EmptyState";
import { ApiError } from "@/api/client";
import {
  createPosition,
  listPositions,
  updatePositionStatus,
  type Position,
  type PositionStatus,
} from "@/api/endpoints/hr";
import { fmtDateTime, isFeatureDisabled } from "./hrShared";

const STATUS_FILTERS: Array<{ label: string; value: string }> = [
  { label: "All statuses", value: "" },
  { label: "Open", value: "OPEN" },
  { label: "Filled", value: "FILLED" },
  { label: "Closed", value: "CLOSED" },
];

const NEXT_STATES: Record<PositionStatus, PositionStatus[]> = {
  OPEN: ["FILLED", "CLOSED"],
  FILLED: ["CLOSED"],
  CLOSED: [],
};

function statusBadge(status: PositionStatus) {
  const variant =
    status === "OPEN" ? "success" : status === "FILLED" ? "secondary" : "outline";
  return <Badge variant={variant as never}>{status}</Badge>;
}

export function PositionsPanel({ onDisabled }: { onDisabled: () => void }) {
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [department, setDepartment] = useState("");

  const positionsQuery = useQuery({
    queryKey: ["hr", "positions", { statusFilter }],
    queryFn: () => listPositions({ status: statusFilter || undefined, limit: 100 }),
    retry: false,
  });

  if (positionsQuery.isError && isFeatureDisabled(positionsQuery.error)) {
    onDisabled();
  }

  const createMut = useMutation({
    mutationFn: () =>
      createPosition({
        title: title.trim(),
        department: department.trim() || null,
      }),
    onSuccess: () => {
      toast.success("Position created");
      setCreateOpen(false);
      setTitle("");
      setDepartment("");
      qc.invalidateQueries({ queryKey: ["hr", "positions"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to create position"),
  });

  const statusMut = useMutation({
    mutationFn: (vars: { id: string; status: PositionStatus }) =>
      updatePositionStatus(vars.id, { status: vars.status }),
    onSuccess: () => {
      toast.success("Status updated");
      qc.invalidateQueries({ queryKey: ["hr", "positions"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to update status"),
  });

  const positions: Position[] = positionsQuery.data?.items ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <Select
          value={statusFilter || "__all__"}
          onValueChange={(v) => setStatusFilter(v === "__all__" ? "" : v)}
        >
          <SelectTrigger className="w-48" aria-label="Filter positions by status">
            <SelectValue placeholder="All statuses" />
          </SelectTrigger>
          <SelectContent>
            {STATUS_FILTERS.map((f) => (
              <SelectItem key={f.value || "all"} value={f.value || "__all__"}>
                {f.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> New position
        </Button>
      </div>

      <Card>
        <CardContent className="p-0">
          {positionsQuery.isLoading ? (
            <div className="p-8 text-center text-sm text-muted-foreground">Loading positions…</div>
          ) : positions.length === 0 ? (
            <EmptyState
              icon={<Briefcase className="h-10 w-10" />}
              title="No positions"
              description="Create a position to begin tracking your org's roles."
              action={{ label: "New position", onClick: () => setCreateOpen(true) }}
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Title</TableHead>
                  <TableHead>Department</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {positions.map((p) => (
                  <TableRow key={p.position_id}>
                    <TableCell className="font-medium">{p.title}</TableCell>
                    <TableCell>{p.department || "—"}</TableCell>
                    <TableCell>{statusBadge(p.status)}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {fmtDateTime(p.created_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        {NEXT_STATES[p.status].map((next) => (
                          <Button
                            key={next}
                            size="sm"
                            variant="outline"
                            disabled={statusMut.isPending}
                            onClick={() => statusMut.mutate({ id: p.position_id, status: next })}
                          >
                            Mark {next}
                          </Button>
                        ))}
                        {NEXT_STATES[p.status].length === 0 && (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New position</DialogTitle>
            <DialogDescription>Define a role within the organization.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="pos-title">Title</Label>
              <Input
                id="pos-title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Software Engineer"
                maxLength={200}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="pos-dept">Department (optional)</Label>
              <Input
                id="pos-dept"
                value={department}
                onChange={(e) => setDepartment(e.target.value)}
                placeholder="Engineering"
                maxLength={100}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMut.mutate()}
              disabled={!title.trim() || createMut.isPending}
            >
              {createMut.isPending ? "Creating…" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
