/**
 * Hotel Setup — Housekeeping Status Board (HTL-007)
 *
 * Route: hotels/:hotelId/housekeeping
 * Shows a Kanban-style board of housekeeping tasks with status columns.
 * Also shows per-room HK status summary.
 */

import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Wrench, Plus, CheckCircle, Clock, ArrowLeft } from "lucide-react";

import { ApiError } from "@/api/client";
import {
  listRooms,
  listHkTasks,
  createHkTask,
  assignHkTask,
  completeHkTask,
  type HkTaskOut,
  type HkTaskIn,
} from "@/api/endpoints/hotelSetup";
import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
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

type TaskStatus = "open" | "in_progress" | "done";

const COLUMNS: { key: TaskStatus; label: string; color: string }[] = [
  { key: "open", label: "Open", color: "border-yellow-400" },
  { key: "in_progress", label: "In Progress", color: "border-blue-400" },
  { key: "done", label: "Done", color: "border-green-400" },
];

function fmtDate(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

export default function HousekeepingBoardPage() {
  const { hotelId } = useParams<{ hotelId: string }>();
  const qc = useQueryClient();

  const [showCreate, setShowCreate] = useState(false);
  const [statusFilter, setStatusFilter] = useState<"" | TaskStatus>("");
  const [form, setForm] = useState<HkTaskIn>({
    room_id: "",
    assignee_sub: "",
    notes: "",
    due_at: 0,
  });

  const [assignTarget, setAssignTarget] = useState<HkTaskOut | null>(null);
  const [assigneeSub, setAssigneeSub] = useState("");

  // ── queries ──────────────────────────────────────────────────────
  const roomsQuery = useQuery({
    queryKey: ["hotels", hotelId, "rooms"],
    queryFn: () => listRooms(hotelId!),
    enabled: !!hotelId,
    retry: false,
  });

  const tasksQuery = useQuery({
    queryKey: ["hotels", hotelId, "hk-tasks", statusFilter],
    queryFn: () =>
      listHkTasks(hotelId!, { status: statusFilter || undefined }),
    enabled: !!hotelId,
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 2;
    },
  });

  // ── mutations ────────────────────────────────────────────────────
  const createMut = useMutation({
    mutationFn: () => createHkTask(hotelId!, form),
    onSuccess: () => {
      toast.success("Task created");
      qc.invalidateQueries({ queryKey: ["hotels", hotelId, "hk-tasks"] });
      setShowCreate(false);
      setForm({ room_id: "", assignee_sub: "", notes: "", due_at: 0 });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Create failed"),
  });

  const assignMut = useMutation({
    mutationFn: () => assignHkTask(hotelId!, assignTarget!.task_id, assigneeSub),
    onSuccess: () => {
      toast.success("Task assigned");
      qc.invalidateQueries({ queryKey: ["hotels", hotelId, "hk-tasks"] });
      setAssignTarget(null);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Assign failed"),
  });

  const completeMut = useMutation({
    mutationFn: (taskId: string) => completeHkTask(hotelId!, taskId),
    onSuccess: () => {
      toast.success("Task completed");
      qc.invalidateQueries({ queryKey: ["hotels", hotelId, "hk-tasks"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Complete failed"),
  });

  // ── feature-disabled guard ────────────────────────────────────────
  if (
    tasksQuery.error instanceof ApiError &&
    (tasksQuery.error.status === 404 || tasksQuery.error.status === 503)
  ) {
    return (
      <div className="p-6">
        <EmptyState
          icon={<Wrench className="h-8 w-8" />}
          title="Hotel PMS not enabled"
          description="HOTEL_PMS_ENABLED is off — contact your administrator."
        />
      </div>
    );
  }

  const tasks = tasksQuery.data?.tasks ?? [];
  const rooms = roomsQuery.data?.rooms ?? [];
  const roomNumberMap = Object.fromEntries(rooms.map((r) => [r.room_id, r.room_number]));

  // Rooms housekeeping summary
  const hkSummary = rooms.reduce<Record<string, number>>((acc, r) => {
    acc[r.housekeeping_status] = (acc[r.housekeeping_status] ?? 0) + 1;
    return acc;
  }, {});

  // Group tasks by status
  const tasksByStatus: Record<TaskStatus, HkTaskOut[]> = {
    open: [],
    in_progress: [],
    done: [],
  };
  for (const t of tasks) {
    if (t.status in tasksByStatus) {
      tasksByStatus[t.status as TaskStatus].push(t);
    }
  }

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Housekeeping Board"
        description={`Hotel ID: ${hotelId}`}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" asChild>
              <Link to={`/hotels/setup/${hotelId}`}>
                <ArrowLeft className="h-3 w-3 mr-1" />
                Hotel
              </Link>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to={`/hotels/${hotelId}/rooms`}>Rooms</Link>
            </Button>
            <Select
              value={statusFilter}
              onValueChange={(v) => setStatusFilter(v as "" | TaskStatus)}
            >
              <SelectTrigger className="w-36">
                <SelectValue placeholder="All statuses" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="">All statuses</SelectItem>
                <SelectItem value="open">Open</SelectItem>
                <SelectItem value="in_progress">In Progress</SelectItem>
                <SelectItem value="done">Done</SelectItem>
              </SelectContent>
            </Select>
            <Button onClick={() => setShowCreate(true)}>
              <Plus className="mr-2 h-4 w-4" />
              New Task
            </Button>
          </div>
        }
      />

      {/* Room HK summary */}
      {rooms.length > 0 && (
        <div className="grid grid-cols-4 gap-3">
          {(["clean", "dirty", "inspected", "out_of_service"] as const).map((s) => (
            <Card key={s} className="text-center py-3">
              <p className="text-2xl font-bold">{hkSummary[s] ?? 0}</p>
              <p className="text-xs text-muted-foreground capitalize">{s.replace("_", " ")}</p>
            </Card>
          ))}
        </div>
      )}

      {tasksQuery.isLoading && (
        <p className="text-sm text-muted-foreground">Loading tasks…</p>
      )}

      {!tasksQuery.isLoading && tasks.length === 0 && (
        <EmptyState
          icon={<Wrench className="h-8 w-8" />}
          title="No housekeeping tasks"
          description="Create tasks to assign cleaning and inspection work."
          action={{ label: "New Task", onClick: () => setShowCreate(true) }}
        />
      )}

      {/* Kanban board */}
      {tasks.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {COLUMNS.map((col) => (
            <div key={col.key} className={`rounded-lg border-t-4 ${col.color} bg-muted/30`}>
              <div className="p-3 flex items-center justify-between">
                <h3 className="font-semibold text-sm">{col.label}</h3>
                <Badge variant="secondary">{tasksByStatus[col.key].length}</Badge>
              </div>
              <div className="p-2 space-y-2 min-h-[200px]">
                {tasksByStatus[col.key].map((task) => (
                  <Card key={task.task_id} className="shadow-sm">
                    <CardContent className="p-3 space-y-1.5">
                      <div className="flex items-start justify-between gap-1">
                        <p className="text-sm font-medium">
                          Room {roomNumberMap[task.room_id] ?? task.room_id.slice(0, 8)}
                        </p>
                        {task.due_at > 0 && (
                          <span className="text-xs text-muted-foreground flex items-center gap-0.5">
                            <Clock className="h-3 w-3" />
                            {fmtDate(task.due_at)}
                          </span>
                        )}
                      </div>
                      {task.notes && (
                        <p className="text-xs text-muted-foreground line-clamp-2">{task.notes}</p>
                      )}
                      {task.assignee_sub && (
                        <p className="text-xs text-muted-foreground">
                          Assigned: {task.assignee_sub}
                        </p>
                      )}
                      <div className="flex gap-1 pt-1">
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-6 text-xs"
                          onClick={() => {
                            setAssigneeSub(task.assignee_sub || "");
                            setAssignTarget(task);
                          }}
                        >
                          Assign
                        </Button>
                        {task.status !== "done" && (
                          <Button
                            size="sm"
                            variant="default"
                            className="h-6 text-xs"
                            disabled={completeMut.isPending}
                            onClick={() => completeMut.mutate(task.task_id)}
                          >
                            <CheckCircle className="h-3 w-3 mr-0.5" />
                            Complete
                          </Button>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create Task Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Housekeeping Task</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1">
              <Label>Room *</Label>
              <Select value={form.room_id} onValueChange={(v) => setForm({ ...form, room_id: v })}>
                <SelectTrigger>
                  <SelectValue placeholder="Select room…" />
                </SelectTrigger>
                <SelectContent>
                  {rooms.map((r) => (
                    <SelectItem key={r.room_id} value={r.room_id}>
                      Room {r.room_number} (Floor {r.floor}) — {r.housekeeping_status}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>Assignee (user sub, optional)</Label>
              <Input
                value={form.assignee_sub ?? ""}
                onChange={(e) => setForm({ ...form, assignee_sub: e.target.value })}
                placeholder="Leave blank for unassigned"
              />
            </div>
            <div className="space-y-1">
              <Label>Notes</Label>
              <Input
                value={form.notes ?? ""}
                onChange={(e) => setForm({ ...form, notes: e.target.value })}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
            <Button
              disabled={!form.room_id || createMut.isPending}
              onClick={() => createMut.mutate()}
            >
              {createMut.isPending ? "Creating…" : "Create Task"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Assign Task Dialog */}
      <Dialog open={!!assignTarget} onOpenChange={(o) => !o && setAssignTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Assign Task</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <p className="text-sm text-muted-foreground">
              Enter the user sub (ID) to assign this task to. Leave blank to unassign.
            </p>
            <div className="space-y-1">
              <Label>Assignee Sub</Label>
              <Input
                value={assigneeSub}
                onChange={(e) => setAssigneeSub(e.target.value)}
                placeholder="user@example.com or user_id"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAssignTarget(null)}>
              Cancel
            </Button>
            <Button disabled={assignMut.isPending} onClick={() => assignMut.mutate()}>
              {assignMut.isPending ? "Saving…" : "Assign"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
