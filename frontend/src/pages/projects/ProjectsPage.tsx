import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FolderKanban, Plus, Loader2 } from "lucide-react";
import { Link } from "react-router-dom";
import { toast } from "sonner";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { listProjects, createProject } from "@/api/endpoints/projects";
import type { ProjectCreateReq } from "@/api/types";

type FormState = {
  name: string;
  description: string;
  tagsCsv: string;
  settingsJson: string;
};

const INITIAL_FORM: FormState = {
  name: "",
  description: "",
  tagsCsv: "",
  settingsJson: "{}",
};

function parseTags(csv: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of csv.split(",")) {
    const value = raw.trim();
    if (!value) continue;
    const normalized = value.toLowerCase();
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(value);
  }
  return out;
}

function validateForm(form: FormState): { payload?: ProjectCreateReq; error?: string } {
  const name = form.name.trim();
  if (!name) return { error: "Project name is required" };
  if (name.length > 120) return { error: "Project name must be 120 characters or fewer" };

  const description = form.description.trim();
  if (description.length > 2000) return { error: "Description must be 2000 characters or fewer" };

  let settings: Record<string, unknown> = {};
  const rawSettings = form.settingsJson.trim();
  if (rawSettings) {
    try {
      const parsed = JSON.parse(rawSettings) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return { error: "Settings must be a JSON object" };
      }
      settings = parsed as Record<string, unknown>;
    } catch {
      return { error: "Settings must be valid JSON" };
    }
  }

  return {
    payload: {
      name,
      description: description || undefined,
      tags: parseTags(form.tagsCsv),
      settings,
    },
  };
}

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

export default function ProjectsPage() {
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [form, setForm] = React.useState<FormState>(INITIAL_FORM);
  const [formError, setFormError] = React.useState<string | null>(null);

  const projectsQuery = useQuery({
    queryKey: ["projects", "list"],
    queryFn: () => listProjects({ limit: 100 }),
  });

  const createMutation = useMutation({
    mutationFn: createProject,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["projects", "list"] });
      setDialogOpen(false);
      setForm(INITIAL_FORM);
      setFormError(null);
      toast.success("Project created");
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : "Failed to create project";
      setFormError(message);
      toast.error(message);
    },
  });

  const handleCreate = () => {
    const parsed = validateForm(form);
    if (parsed.error) {
      setFormError(parsed.error);
      return;
    }
    setFormError(null);
    createMutation.mutate(parsed.payload!);
  };

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Projects"
        description="Group and track important files by project."
        actions={
          <Button onClick={() => setDialogOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            New project
          </Button>
        }
      />

      {projectsQuery.isLoading && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground" data-testid="projects-loading">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading projects…
        </div>
      )}

      {projectsQuery.isError && (
        <Card data-testid="projects-error">
          <CardHeader>
            <CardTitle>Could not load projects</CardTitle>
            <CardDescription>Please try again.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button variant="outline" onClick={() => projectsQuery.refetch()}>Retry</Button>
          </CardContent>
        </Card>
      )}

      {!projectsQuery.isLoading && !projectsQuery.isError && projectsQuery.data?.items?.length === 0 && (
        <EmptyState
          icon={<FolderKanban className="h-8 w-8" />}
          title="No projects yet"
          description="Create your first project to start grouping files."
          action={{
            label: "Create project",
            onClick: () => setDialogOpen(true),
          }}
        />
      )}

      {!projectsQuery.isLoading && !projectsQuery.isError && (projectsQuery.data?.items?.length ?? 0) > 0 && (
        <div className="grid gap-4 sm:grid-cols-2" data-testid="projects-list">
          {projectsQuery.data?.items.map((project) => (
            <Card key={project.id}>
              <CardHeader>
                <CardTitle className="text-base">
                  <Link to={`/projects/${project.id}`} className="hover:underline">
                    {project.name}
                  </Link>
                </CardTitle>
                <CardDescription>{project.description || "No description"}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                <div className="text-muted-foreground">Updated {formatDate(project.updated_at)}</div>
                <div className="flex flex-wrap gap-2">
                  {project.tags.length > 0 ? (
                    project.tags.map((tag) => (
                      <span key={tag} className="rounded-full bg-muted px-2 py-0.5 text-xs">
                        {tag}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-muted-foreground">No tags</span>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create project</DialogTitle>
            <DialogDescription>
              Add a project name, optional description, tags, and JSON settings.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="project-name">Name</Label>
              <Input
                id="project-name"
                value={form.name}
                onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
                placeholder="My Project"
                maxLength={120}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="project-description">Description</Label>
              <Textarea
                id="project-description"
                value={form.description}
                onChange={(e) => setForm((prev) => ({ ...prev, description: e.target.value }))}
                placeholder="Optional description"
                maxLength={2000}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="project-tags">Tags (comma separated)</Label>
              <Input
                id="project-tags"
                value={form.tagsCsv}
                onChange={(e) => setForm((prev) => ({ ...prev, tagsCsv: e.target.value }))}
                placeholder="alpha, billing"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="project-settings">Settings JSON</Label>
              <Textarea
                id="project-settings"
                value={form.settingsJson}
                onChange={(e) => setForm((prev) => ({ ...prev, settingsJson: e.target.value }))}
                className="font-mono text-xs"
              />
            </div>

            {formError && <p className="text-sm text-destructive">{formError}</p>}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)} disabled={createMutation.isPending}>
              Cancel
            </Button>
            <Button onClick={handleCreate} disabled={createMutation.isPending}>
              {createMutation.isPending ? "Creating…" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
