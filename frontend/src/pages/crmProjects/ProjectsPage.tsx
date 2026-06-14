import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Plus, FolderKanban, Search } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import {
  listCrmProjects,
  type CrmProjectStatus,
} from "@/api/endpoints/crmProjects";
import { CreateProjectDialog } from "./CreateProjectDialog";
import { ProjectsNotEnabled } from "./ProjectsNotEnabled";
import {
  isNotEnabled,
  fmtDate,
  PROJECT_STATUSES,
  PROJECT_STATUS_LABELS,
  statusVariant,
  priorityLabel,
} from "./projectHelpers";

const ALL = "__all__";

export default function ProjectsPage() {
  const [createOpen, setCreateOpen] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>(ALL);
  const [search, setSearch] = useState("");
  const [debounced, setDebounced] = useState("");

  // simple debounce on submit (Enter) — also exposed via a button
  function applySearch() {
    setDebounced(search.trim());
  }

  const query = useQuery({
    queryKey: ["crm-projects", "list", statusFilter, debounced],
    queryFn: () =>
      listCrmProjects({
        limit: 50,
        status: statusFilter === ALL ? undefined : (statusFilter as CrmProjectStatus),
        name_query: debounced || undefined,
      }),
    retry: false,
  });

  if (query.isError && isNotEnabled(query.error)) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="CRM Projects"
          description="SuiteCRM project & task management"
        />
        <ProjectsNotEnabled />
      </div>
    );
  }

  const items = query.data?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="CRM Projects"
        description="SuiteCRM project & task management"
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="mr-1.5 h-4 w-4" />
            New project
          </Button>
        }
      />

      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <div className="flex flex-1 items-center gap-2">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") applySearch();
            }}
            placeholder="Search by name…"
            className="max-w-xs"
          />
          <Button variant="outline" size="icon" onClick={applySearch}>
            <Search className="h-4 w-4" />
          </Button>
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="All statuses" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>All statuses</SelectItem>
            {PROJECT_STATUSES.map((s) => (
              <SelectItem key={s} value={s}>
                {PROJECT_STATUS_LABELS[s]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {query.isLoading ? (
        <div className="space-y-2">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-20 w-full" />
          ))}
        </div>
      ) : query.isError ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            Failed to load projects. Please try again.
          </CardContent>
        </Card>
      ) : items.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
            <FolderKanban className="h-10 w-10 text-muted-foreground" />
            <div>
              <p className="text-lg font-medium">No projects yet</p>
              <p className="mt-1 text-sm text-muted-foreground">
                Create your first project to start tracking tasks and milestones.
              </p>
            </div>
            <Button onClick={() => setCreateOpen(true)}>
              <Plus className="mr-1.5 h-4 w-4" />
              New project
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {items.map((p) => (
            <Link key={p.id} to={`/crm/projects/${p.id}`} className="block">
              <Card className="transition-colors hover:bg-accent/50">
                <CardContent className="flex items-center justify-between gap-4 py-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="truncate font-medium">{p.name}</p>
                      <Badge variant={statusVariant(p.status)}>
                        {PROJECT_STATUS_LABELS[p.status]}
                      </Badge>
                    </div>
                    {p.description && (
                      <p className="mt-0.5 truncate text-sm text-muted-foreground">
                        {p.description}
                      </p>
                    )}
                  </div>
                  <div className="flex shrink-0 items-center gap-4 text-right text-xs text-muted-foreground">
                    <div>
                      <p className="font-medium text-foreground">
                        {priorityLabel(p.priority)}
                      </p>
                      <p>priority</p>
                    </div>
                    <div>
                      <p className="font-medium text-foreground">
                        {fmtDate(p.start_date)} – {fmtDate(p.end_date)}
                      </p>
                      <p>schedule</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}

      <CreateProjectDialog open={createOpen} onOpenChange={setCreateOpen} />
    </div>
  );
}
