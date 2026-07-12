import { useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowLeft,
  Plus,
  Trash2,
  Flag,
  Users,
  Link2,
  History,
  ListChecks,
  GanttChartSquare,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";

import { ApiError } from "@/api/client";
import {
  getCrmProject,
  updateCrmProject,
  deleteCrmProject,
  listProjectTasks,
  deleteProjectTask,
  updateProjectTask,
  getMilestoneSummary,
  getProjectWorkload,
  listProjectMembers,
  removeProjectMember,
  listContactLinks,
  removeContactLink,
  getStatusHistory,
  type CrmProjectStatus,
  type CrmProjectTaskModel,
} from "@/api/endpoints/crmProjects";
import { CreateTaskDialog } from "./CreateTaskDialog";
import { TaskGantt } from "./TaskGantt";
import { ProjectsNotEnabled } from "./ProjectsNotEnabled";
import {
  isNotEnabled,
  fmtTs,
  fmtDate,
  PROJECT_STATUSES,
  PROJECT_STATUS_LABELS,
  statusVariant,
  priorityLabel,
  MEMBER_ROLE_LABELS,
} from "./projectHelpers";

export default function ProjectDetailPage() {
  const { projectId = "" } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [createTaskOpen, setCreateTaskOpen] = useState(false);
  const [taskView, setTaskView] = useState<"board" | "gantt">("board");

  const projectQuery = useQuery({
    queryKey: ["crm-projects", "detail", projectId],
    queryFn: () => getCrmProject(projectId),
    retry: false,
    enabled: !!projectId,
  });

  const updateStatusMut = useMutation({
    mutationFn: (status: CrmProjectStatus) => updateCrmProject(projectId, { status }),
    onSuccess: () => {
      toast.success("Status updated");
      qc.invalidateQueries({ queryKey: ["crm-projects", "detail", projectId] });
      qc.invalidateQueries({ queryKey: ["crm-project-status-history", projectId] });
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to update status"),
  });

  const deleteMut = useMutation({
    mutationFn: () => deleteCrmProject(projectId),
    onSuccess: () => {
      toast.success("Project deleted");
      qc.invalidateQueries({ queryKey: ["crm-projects"] });
      navigate("/crm/projects");
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to delete project"),
  });

  if (projectQuery.isError && isNotEnabled(projectQuery.error)) {
    return (
      <div className="space-y-6">
        <PageHeader title="CRM Projects" />
        <ProjectsNotEnabled />
      </div>
    );
  }

  if (projectQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-9 w-64" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  if (projectQuery.isError || !projectQuery.data) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" asChild>
          <Link to="/crm/projects">
            <ArrowLeft className="mr-1.5 h-4 w-4" />
            Back to projects
          </Link>
        </Button>
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            Project not found.
          </CardContent>
        </Card>
      </div>
    );
  }

  const project = projectQuery.data;

  return (
    <div className="space-y-6">
      <Button variant="ghost" size="sm" asChild className="-ml-2">
        <Link to="/crm/projects">
          <ArrowLeft className="mr-1.5 h-4 w-4" />
          Back to projects
        </Link>
      </Button>

      <PageHeader
        title={project.name}
        description={project.description ?? undefined}
        actions={
          <div className="flex items-center gap-2">
            <Select
              value={project.status}
              onValueChange={(v) => updateStatusMut.mutate(v as CrmProjectStatus)}
            >
              <SelectTrigger className="w-[160px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {PROJECT_STATUSES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {PROJECT_STATUS_LABELS[s]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="outline" size="icon">
                  <Trash2 className="h-4 w-4" />
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Delete project?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This permanently deletes “{project.name}” and its tasks. This
                    cannot be undone.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction onClick={() => deleteMut.mutate()}>
                    Delete
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
        }
      />

      <div className="flex flex-wrap items-center gap-3 text-sm">
        <Badge variant={statusVariant(project.status)}>
          {PROJECT_STATUS_LABELS[project.status]}
        </Badge>
        <span className="text-muted-foreground">
          Priority: <span className="text-foreground">{priorityLabel(project.priority)}</span>
        </span>
        <span className="text-muted-foreground">
          Schedule:{" "}
          <span className="text-foreground">
            {fmtDate(project.start_date)} – {fmtDate(project.end_date)}
          </span>
        </span>
        {project.assigned_user_sub && (
          <span className="text-muted-foreground">
            Lead: <span className="text-foreground">{project.assigned_user_sub}</span>
          </span>
        )}
      </div>

      <Tabs defaultValue="tasks">
        <TabsList>
          <TabsTrigger value="tasks">
            <ListChecks className="mr-1.5 h-4 w-4" />
            Tasks
          </TabsTrigger>
          <TabsTrigger value="milestones">
            <Flag className="mr-1.5 h-4 w-4" />
            Milestones
          </TabsTrigger>
          <TabsTrigger value="workload">
            <Users className="mr-1.5 h-4 w-4" />
            Workload
          </TabsTrigger>
          <TabsTrigger value="members">
            <Users className="mr-1.5 h-4 w-4" />
            Team
          </TabsTrigger>
          <TabsTrigger value="links">
            <Link2 className="mr-1.5 h-4 w-4" />
            Contacts
          </TabsTrigger>
          <TabsTrigger value="history">
            <History className="mr-1.5 h-4 w-4" />
            History
          </TabsTrigger>
        </TabsList>

        {/* Tasks */}
        <TabsContent value="tasks" className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1 rounded-md border p-0.5">
              <Button
                variant={taskView === "board" ? "secondary" : "ghost"}
                size="sm"
                onClick={() => setTaskView("board")}
              >
                <ListChecks className="mr-1.5 h-4 w-4" />
                Board
              </Button>
              <Button
                variant={taskView === "gantt" ? "secondary" : "ghost"}
                size="sm"
                onClick={() => setTaskView("gantt")}
              >
                <GanttChartSquare className="mr-1.5 h-4 w-4" />
                Gantt
              </Button>
            </div>
            <Button size="sm" onClick={() => setCreateTaskOpen(true)}>
              <Plus className="mr-1.5 h-4 w-4" />
              New task
            </Button>
          </div>
          <TasksTab projectId={projectId} view={taskView} />
        </TabsContent>

        {/* Milestones */}
        <TabsContent value="milestones">
          <MilestonesTab projectId={projectId} />
        </TabsContent>

        {/* Workload */}
        <TabsContent value="workload">
          <WorkloadTab projectId={projectId} />
        </TabsContent>

        {/* Members */}
        <TabsContent value="members">
          <MembersTab projectId={projectId} />
        </TabsContent>

        {/* Contact links */}
        <TabsContent value="links">
          <ContactLinksTab projectId={projectId} />
        </TabsContent>

        {/* Status history */}
        <TabsContent value="history">
          <HistoryTab projectId={projectId} />
        </TabsContent>
      </Tabs>

      <CreateTaskDialog
        projectId={projectId}
        open={createTaskOpen}
        onOpenChange={setCreateTaskOpen}
      />
    </div>
  );
}

// ─── Tasks tab ───────────────────────────────────────────────────────────────

function TasksTab({ projectId, view }: { projectId: string; view: "board" | "gantt" }) {
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: ["crm-project-tasks", projectId],
    queryFn: () => listProjectTasks(projectId, { limit: 200 }),
    retry: false,
  });

  const updateMut = useMutation({
    mutationFn: ({ taskId, percent }: { taskId: string; percent: number }) =>
      updateProjectTask(projectId, taskId, { percent_complete: percent }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["crm-project-tasks", projectId] });
      qc.invalidateQueries({ queryKey: ["crm-project-milestones", projectId] });
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to update task"),
  });

  const deleteMut = useMutation({
    mutationFn: (taskId: string) => deleteProjectTask(projectId, taskId),
    onSuccess: () => {
      toast.success("Task deleted");
      qc.invalidateQueries({ queryKey: ["crm-project-tasks", projectId] });
      qc.invalidateQueries({ queryKey: ["crm-project-workload", projectId] });
      qc.invalidateQueries({ queryKey: ["crm-project-milestones", projectId] });
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to delete task"),
  });

  if (query.isLoading) return <Skeleton className="h-40 w-full" />;
  if (query.isError)
    return (
      <Card>
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          Failed to load tasks.
        </CardContent>
      </Card>
    );

  const tasks = query.data?.items ?? [];

  if (tasks.length === 0) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-sm text-muted-foreground">
          No tasks yet. Add the first one to get started.
        </CardContent>
      </Card>
    );
  }

  if (view === "gantt") {
    return (
      <Card>
        <CardContent className="pt-6">
          <TaskGantt tasks={tasks} />
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-2">
      {tasks.map((t) => (
        <TaskRow
          key={t.id}
          task={t}
          onSetPercent={(percent) => updateMut.mutate({ taskId: t.id, percent })}
          onDelete={() => deleteMut.mutate(t.id)}
        />
      ))}
    </div>
  );
}

function TaskRow({
  task,
  onSetPercent,
  onDelete,
}: {
  task: CrmProjectTaskModel;
  onSetPercent: (percent: number) => void;
  onDelete: () => void;
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4 py-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            {task.is_milestone && <Flag className="h-3.5 w-3.5 text-amber-500" />}
            <span className="truncate font-medium">{task.name}</span>
            {task.assigned_user_sub && (
              <Badge variant="outline" className="text-[10px]">
                {task.assigned_user_sub}
              </Badge>
            )}
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {fmtDate(task.start_date)} – {fmtDate(task.end_date)} · {task.duration_days}d
          </p>
          <div className="mt-2 flex items-center gap-2">
            <Progress value={task.percent_complete} className="h-1.5 max-w-[200px]" />
            <span className="text-xs text-muted-foreground">{task.percent_complete}%</span>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Select
            value={String(task.percent_complete)}
            onValueChange={(v) => onSetPercent(Number(v))}
          >
            <SelectTrigger className="h-8 w-[88px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {[0, 25, 50, 75, 100].map((p) => (
                <SelectItem key={p} value={String(p)}>
                  {p}%
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8">
                <Trash2 className="h-4 w-4" />
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Delete task?</AlertDialogTitle>
                <AlertDialogDescription>
                  Delete “{task.name}”? This cannot be undone.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={onDelete}>Delete</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Milestones tab ──────────────────────────────────────────────────────────

function MilestonesTab({ projectId }: { projectId: string }) {
  const query = useQuery({
    queryKey: ["crm-project-milestones", projectId],
    queryFn: () => getMilestoneSummary(projectId, { limit: 200 }),
    retry: false,
  });

  if (query.isLoading) return <Skeleton className="h-40 w-full" />;
  if (query.isError)
    return (
      <Card>
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          Failed to load milestones.
        </CardContent>
      </Card>
    );

  const data = query.data!;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <SummaryCard label="Total" value={data.total_milestones} />
        <SummaryCard label="On track" value={data.on_track_count} tone="ok" />
        <SummaryCard label="Overdue" value={data.overdue_count} tone="warn" />
        <SummaryCard label="No date" value={data.no_date_count} />
      </div>

      {data.items.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            No milestones yet. Mark a task as a milestone to track it here.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {data.items.map((m) => (
            <Card key={m.id}>
              <CardContent className="flex items-center justify-between gap-4 py-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5">
                    <Flag className="h-3.5 w-3.5 text-amber-500" />
                    <span className="truncate font-medium">{m.name}</span>
                    {m.overdue ? (
                      <Badge variant="destructive">Overdue</Badge>
                    ) : m.on_track ? (
                      <Badge variant="secondary">On track</Badge>
                    ) : (
                      <Badge variant="outline">No date</Badge>
                    )}
                  </div>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    Due {fmtDate(m.end_date)} · {m.percent_complete}% complete
                  </p>
                </div>
                <Progress value={m.percent_complete} className="h-1.5 w-32" />
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function SummaryCard({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: "ok" | "warn";
}) {
  const color =
    tone === "ok"
      ? "text-emerald-600"
      : tone === "warn"
        ? "text-destructive"
        : "text-foreground";
  return (
    <Card>
      <CardContent className="py-4 text-center">
        <p className={`text-2xl font-semibold ${color}`}>{value}</p>
        <p className="text-xs text-muted-foreground">{label}</p>
      </CardContent>
    </Card>
  );
}

// ─── Workload tab ────────────────────────────────────────────────────────────

function WorkloadTab({ projectId }: { projectId: string }) {
  const query = useQuery({
    queryKey: ["crm-project-workload", projectId],
    queryFn: () => getProjectWorkload(projectId),
    retry: false,
  });

  if (query.isLoading) return <Skeleton className="h-40 w-full" />;
  if (query.isError)
    return (
      <Card>
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          Failed to load workload.
        </CardContent>
      </Card>
    );

  const entries = query.data?.entries ?? [];

  if (entries.length === 0) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-sm text-muted-foreground">
          No assigned tasks yet. Assign tasks to resources to see workload.
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-2">
      {entries.map((e) => (
        <Card key={e.assignee_key}>
          <CardContent className="flex items-center justify-between gap-4 py-3">
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="truncate font-medium">{e.assigned_id}</span>
                <Badge variant="outline" className="text-[10px]">
                  {e.resource_type}
                </Badge>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-4 text-sm">
              <span className="flex items-center gap-1 text-muted-foreground">
                <CheckCircle2 className="h-3.5 w-3.5" />
                {e.task_count} tasks
              </span>
              {e.overdue_count > 0 && (
                <span className="flex items-center gap-1 text-destructive">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  {e.overdue_count} overdue
                </span>
              )}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ─── Members tab ─────────────────────────────────────────────────────────────

function MembersTab({ projectId }: { projectId: string }) {
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: ["crm-project-members", projectId],
    queryFn: () => listProjectMembers(projectId, { limit: 200 }),
    retry: false,
  });

  const removeMut = useMutation({
    mutationFn: (userSub: string) => removeProjectMember(projectId, userSub),
    onSuccess: () => {
      toast.success("Member removed");
      qc.invalidateQueries({ queryKey: ["crm-project-members", projectId] });
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to remove member"),
  });

  if (query.isLoading) return <Skeleton className="h-40 w-full" />;
  if (query.isError)
    return (
      <Card>
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          Failed to load team members.
        </CardContent>
      </Card>
    );

  const members = query.data?.items ?? [];

  if (members.length === 0) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-sm text-muted-foreground">
          No team members yet.
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-2">
      {members.map((m) => (
        <Card key={m.user_sub}>
          <CardContent className="flex items-center justify-between gap-4 py-3">
            <div className="min-w-0">
              <p className="truncate font-medium">{m.user_sub}</p>
              <p className="text-xs text-muted-foreground">
                Added {fmtTs(m.added_at)} by {m.added_by}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <Badge variant="secondary">{MEMBER_ROLE_LABELS[m.role]}</Badge>
              {m.role !== "owner" && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  onClick={() => removeMut.mutate(m.user_sub)}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              )}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ─── Contact links tab ───────────────────────────────────────────────────────

function ContactLinksTab({ projectId }: { projectId: string }) {
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: ["crm-project-contact-links", projectId],
    queryFn: () => listContactLinks(projectId, { limit: 200 }),
    retry: false,
  });

  const removeMut = useMutation({
    mutationFn: (entityId: string) => removeContactLink(projectId, entityId),
    onSuccess: () => {
      toast.success("Link removed");
      qc.invalidateQueries({ queryKey: ["crm-project-contact-links", projectId] });
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to remove link"),
  });

  if (query.isLoading) return <Skeleton className="h-40 w-full" />;
  if (query.isError)
    return (
      <Card>
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          Failed to load contact links.
        </CardContent>
      </Card>
    );

  const links = query.data?.items ?? [];

  if (links.length === 0) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-sm text-muted-foreground">
          No linked contacts or accounts yet.
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-2">
      {links.map((l) => (
        <Card key={`${l.linked_entity_type}:${l.linked_entity_id}`}>
          <CardContent className="flex items-center justify-between gap-4 py-3">
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <Link2 className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="truncate font-medium">{l.linked_entity_id}</span>
                <Badge variant="outline" className="text-[10px]">
                  {l.linked_entity_type}
                </Badge>
              </div>
              {l.note && (
                <p className="mt-0.5 truncate text-xs text-muted-foreground">{l.note}</p>
              )}
            </div>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => removeMut.mutate(l.linked_entity_id)}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ─── Status history tab ──────────────────────────────────────────────────────

function HistoryTab({ projectId }: { projectId: string }) {
  const query = useQuery({
    queryKey: ["crm-project-status-history", projectId],
    queryFn: () => getStatusHistory(projectId, { limit: 200 }),
    retry: false,
  });

  if (query.isLoading) return <Skeleton className="h-40 w-full" />;
  if (query.isError)
    return (
      <Card>
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          Failed to load history.
        </CardContent>
      </Card>
    );

  const items = query.data?.items ?? [];

  if (items.length === 0) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-sm text-muted-foreground">
          No status changes recorded yet.
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Status history</CardTitle>
      </CardHeader>
      <CardContent>
        <ol className="space-y-3">
          {items.map((e) => (
            <li key={e.event_id} className="flex items-start gap-3 text-sm">
              <History className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
              <div>
                <p>
                  {e.from_status ? (
                    <>
                      <span className="text-muted-foreground">{e.from_status}</span>
                      {" → "}
                    </>
                  ) : (
                    <span className="text-muted-foreground">Created as </span>
                  )}
                  <span className="font-medium">{e.to_status}</span>
                </p>
                <p className="text-xs text-muted-foreground">
                  {fmtTs(e.changed_at)} by {e.changed_by}
                </p>
              </div>
            </li>
          ))}
        </ol>
      </CardContent>
    </Card>
  );
}
