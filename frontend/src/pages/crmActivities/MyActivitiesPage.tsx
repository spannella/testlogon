import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Phone, CheckSquare, StickyNote, Trash2, Link2 } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { ApiError } from "@/api/client";
import {
  listCallLogs,
  listTasks,
  listNotes,
  deleteCallLog,
  deleteTask,
  deleteNote,
  updateTask,
  type CallLogOut,
  type CrmTaskOut,
  type CrmTaskStatus,
  type CrmNoteOut,
} from "@/api/endpoints/crmActivities";
import { CreateActivityDialog } from "./CreateActivityDialog";
import { ActivitiesNotEnabled } from "./ActivitiesNotEnabled";
import {
  fmtTs,
  fmtDuration,
  CALL_OUTCOME_LABELS,
  TASK_STATUS_LABELS,
  TASK_PRIORITY_LABELS,
  taskPriorityVariant,
  taskStatusVariant,
} from "./activityHelpers";

const TASK_STATUS_OPTS = [
  "not_started",
  "in_progress",
  "completed",
  "deferred",
  "waiting",
] as const;

function notEnabled(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

function EntityLink({
  type,
  id,
}: {
  type?: string | null;
  id?: string | null;
}) {
  if (!type || !id) return null;
  return (
    <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
      <Link2 className="h-3 w-3" />
      {type}: {id}
    </span>
  );
}

export default function MyActivitiesPage() {
  const qc = useQueryClient();
  const [tab, setTab] = useState<"calls" | "tasks" | "notes">("calls");
  const [createOpen, setCreateOpen] = useState(false);
  const [createKind, setCreateKind] = useState<"call" | "task" | "note">("call");
  const [taskStatusFilter, setTaskStatusFilter] = useState<string>("");

  const callsQuery = useQuery({
    queryKey: ["crm-activities", "calls"],
    queryFn: () => listCallLogs({ limit: 50 }),
    retry: false,
  });

  const tasksQuery = useQuery({
    queryKey: ["crm-activities", "tasks", taskStatusFilter],
    queryFn: () => listTasks({ limit: 50, status: taskStatusFilter || undefined }),
    retry: false,
  });

  const notesQuery = useQuery({
    queryKey: ["crm-activities", "notes"],
    queryFn: () => listNotes({ limit: 50 }),
    retry: false,
  });

  const delCallMut = useMutation({
    mutationFn: (id: string) => deleteCallLog(id),
    onSuccess: () => {
      toast.success("Call deleted");
      void qc.invalidateQueries({ queryKey: ["crm-activities", "calls"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Delete failed"),
  });

  const delTaskMut = useMutation({
    mutationFn: (id: string) => deleteTask(id),
    onSuccess: () => {
      toast.success("Task deleted");
      void qc.invalidateQueries({ queryKey: ["crm-activities", "tasks"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Delete failed"),
  });

  const delNoteMut = useMutation({
    mutationFn: (id: string) => deleteNote(id),
    onSuccess: () => {
      toast.success("Note deleted");
      void qc.invalidateQueries({ queryKey: ["crm-activities", "notes"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Delete failed"),
  });

  const taskStatusMut = useMutation({
    mutationFn: (vars: { id: string; status: CrmTaskStatus }) =>
      updateTask(vars.id, { status: vars.status }),
    onSuccess: () => {
      toast.success("Task updated");
      void qc.invalidateQueries({ queryKey: ["crm-activities", "tasks"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Update failed"),
  });

  const openCreate = (kind: "call" | "task" | "note") => {
    setCreateKind(kind);
    setCreateOpen(true);
  };

  // Treat a 404 on any tab as "feature disabled".
  const disabled =
    notEnabled(callsQuery.error) ||
    notEnabled(tasksQuery.error) ||
    notEnabled(notesQuery.error);

  return (
    <div className="space-y-6">
      <PageHeader
        title="My Activities"
        description="Calls, tasks, and notes you have logged across CRM records."
        actions={
          <Button onClick={() => openCreate(tab === "tasks" ? "task" : tab === "notes" ? "note" : "call")}>
            <Plus className="mr-1.5 h-4 w-4" />
            Log activity
          </Button>
        }
      />

      {disabled ? (
        <ActivitiesNotEnabled />
      ) : (
        <Tabs value={tab} onValueChange={(v) => setTab(v as typeof tab)}>
          <TabsList>
            <TabsTrigger value="calls">
              <Phone className="mr-1.5 h-4 w-4" /> Calls
            </TabsTrigger>
            <TabsTrigger value="tasks">
              <CheckSquare className="mr-1.5 h-4 w-4" /> Tasks
            </TabsTrigger>
            <TabsTrigger value="notes">
              <StickyNote className="mr-1.5 h-4 w-4" /> Notes
            </TabsTrigger>
          </TabsList>

          {/* ── Calls ── */}
          <TabsContent value="calls" className="pt-4">
            {callsQuery.isLoading ? (
              <ListSkeleton />
            ) : (callsQuery.data?.items.length ?? 0) === 0 ? (
              <EmptyState
                icon={<Phone className="h-8 w-8 text-muted-foreground" />}
                title="No calls logged"
                action={<Button variant="outline" onClick={() => openCreate("call")}>Log a call</Button>}
              />
            ) : (
              <div className="space-y-2">
                {callsQuery.data!.items.map((c: CallLogOut) => (
                  <Card key={c.call_id}>
                    <CardContent className="flex items-start justify-between gap-3 py-4">
                      <div className="min-w-0 space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-medium">{c.subject}</span>
                          <Badge variant="secondary">{c.direction}</Badge>
                          <Badge variant="outline">{c.call_type}</Badge>
                          <Badge>{CALL_OUTCOME_LABELS[c.outcome] ?? c.outcome}</Badge>
                        </div>
                        {c.description && (
                          <p className="text-sm text-muted-foreground">{c.description}</p>
                        )}
                        <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                          <span>{fmtTs(c.created_at)}</span>
                          <span>Duration: {fmtDuration(c.duration_seconds)}</span>
                          <EntityLink type={c.linked_entity_type} id={c.linked_entity_id} />
                        </div>
                      </div>
                      <Button
                        size="icon"
                        variant="ghost"
                        aria-label="Delete call"
                        onClick={() => delCallMut.mutate(c.call_id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </TabsContent>

          {/* ── Tasks ── */}
          <TabsContent value="tasks" className="pt-4">
            <div className="mb-3 flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Filter status</span>
              <Select
                value={taskStatusFilter || "all"}
                onValueChange={(v) => setTaskStatusFilter(v === "all" ? "" : v)}
              >
                <SelectTrigger className="w-48">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All statuses</SelectItem>
                  {TASK_STATUS_OPTS.map((s) => (
                    <SelectItem key={s} value={s}>
                      {TASK_STATUS_LABELS[s]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {tasksQuery.isLoading ? (
              <ListSkeleton />
            ) : (tasksQuery.data?.items.length ?? 0) === 0 ? (
              <EmptyState
                icon={<CheckSquare className="h-8 w-8 text-muted-foreground" />}
                title="No tasks"
                action={<Button variant="outline" onClick={() => openCreate("task")}>Create a task</Button>}
              />
            ) : (
              <div className="space-y-2">
                {tasksQuery.data!.items.map((t: CrmTaskOut) => (
                  <Card key={t.task_id}>
                    <CardContent className="flex items-start justify-between gap-3 py-4">
                      <div className="min-w-0 space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-medium">{t.subject}</span>
                          <Badge variant={taskPriorityVariant(t.priority)}>
                            {TASK_PRIORITY_LABELS[t.priority] ?? t.priority}
                          </Badge>
                          <Badge variant={taskStatusVariant(t.status)}>
                            {TASK_STATUS_LABELS[t.status] ?? t.status}
                          </Badge>
                        </div>
                        {t.description && (
                          <p className="text-sm text-muted-foreground">{t.description}</p>
                        )}
                        <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                          <span>Created {fmtTs(t.created_at)}</span>
                          {t.due_date_ts ? <span>Due {fmtTs(t.due_date_ts)}</span> : null}
                          <EntityLink type={t.linked_entity_type} id={t.linked_entity_id} />
                        </div>
                      </div>
                      <div className="flex items-center gap-1">
                        <Select
                          value={t.status}
                          onValueChange={(v) => taskStatusMut.mutate({ id: t.task_id, status: v as CrmTaskStatus })}
                        >
                          <SelectTrigger className="h-8 w-36 text-xs">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {TASK_STATUS_OPTS.map((s) => (
                              <SelectItem key={s} value={s}>
                                {TASK_STATUS_LABELS[s]}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <Button
                          size="icon"
                          variant="ghost"
                          aria-label="Delete task"
                          onClick={() => delTaskMut.mutate(t.task_id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </TabsContent>

          {/* ── Notes ── */}
          <TabsContent value="notes" className="pt-4">
            {notesQuery.isLoading ? (
              <ListSkeleton />
            ) : (notesQuery.data?.notes.length ?? 0) === 0 ? (
              <EmptyState
                icon={<StickyNote className="h-8 w-8 text-muted-foreground" />}
                title="No notes"
                action={<Button variant="outline" onClick={() => openCreate("note")}>Add a note</Button>}
              />
            ) : (
              <div className="space-y-2">
                {notesQuery.data!.notes.map((n: CrmNoteOut) => (
                  <Card key={n.note_id}>
                    <CardContent className="flex items-start justify-between gap-3 py-4">
                      <div className="min-w-0 space-y-1">
                        <p className="whitespace-pre-wrap text-sm">{n.body || "(empty note)"}</p>
                        <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                          <span>{fmtTs(n.created_at)}</span>
                          {n.attachment_filename ? (
                            <a
                              href={n.attachment_url ?? "#"}
                              className="underline"
                              target="_blank"
                              rel="noreferrer"
                            >
                              {n.attachment_filename}
                            </a>
                          ) : null}
                          <EntityLink type={n.linked_entity_type} id={n.linked_entity_id} />
                        </div>
                      </div>
                      <Button
                        size="icon"
                        variant="ghost"
                        aria-label="Delete note"
                        onClick={() => delNoteMut.mutate(n.note_id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </TabsContent>
        </Tabs>
      )}

      <CreateActivityDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        defaultKind={createKind}
        onCreated={() => {
          void qc.invalidateQueries({ queryKey: ["crm-activities"] });
        }}
      />
    </div>
  );
}

function ListSkeleton() {
  return (
    <div className="space-y-2">
      {[0, 1, 2].map((i) => (
        <Skeleton key={i} className="h-20 w-full" />
      ))}
    </div>
  );
}

function EmptyState({
  icon,
  title,
  action,
}: {
  icon: React.ReactNode;
  title: string;
  action?: React.ReactNode;
}) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
        {icon}
        <p className="text-lg font-medium">{title}</p>
        {action}
      </CardContent>
    </Card>
  );
}
