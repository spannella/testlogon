import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Link, useNavigate } from "react-router-dom";
import { ClipboardList, Plus, Archive, BarChart3, Pencil } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  listSurveys,
  createSurvey,
  archiveSurvey,
  type SurveyDraft,
  type SurveyStatus,
} from "@/api/endpoints/crmSurveys";

function fmt(ts?: string | number | null): string {
  if (!ts) return "—";
  const n = typeof ts === "string" ? Number(ts) : ts;
  if (!n || Number.isNaN(n)) return "—";
  return new Date(n * 1000).toLocaleString();
}

function slugifyId(title: string): string {
  const base = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  const suffix = Math.random().toString(36).slice(2, 7);
  return `${base || "survey"}-${suffix}`;
}

function statusVariant(s: SurveyStatus): "default" | "secondary" | "outline" {
  if (s === "published") return "default";
  if (s === "archived") return "outline";
  return "secondary";
}

export default function CrmSurveysPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();

  const [includeArchived, setIncludeArchived] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");

  const listQuery = useQuery({
    queryKey: ["crm-surveys", { includeArchived }],
    queryFn: () => listSurveys(includeArchived),
  });

  const createMut = useMutation({
    mutationFn: () =>
      createSurvey({
        questionnaire_id: slugifyId(title),
        title: title.trim(),
        description: description.trim(),
        visibility: "public",
      }),
    onSuccess: (res) => {
      toast.success("Survey created");
      setCreateOpen(false);
      setTitle("");
      setDescription("");
      qc.invalidateQueries({ queryKey: ["crm-surveys"] });
      navigate(`/crm/surveys/${encodeURIComponent(res.draft.questionnaire_id)}/build`);
    },
    onError: (e: unknown) => {
      toast.error(e instanceof Error ? e.message : "Failed to create survey");
    },
  });

  const archiveMut = useMutation({
    mutationFn: (id: string) => archiveSurvey(id),
    onSuccess: () => {
      toast.success("Survey archived");
      qc.invalidateQueries({ queryKey: ["crm-surveys"] });
    },
    onError: (e: unknown) => {
      toast.error(e instanceof Error ? e.message : "Failed to archive survey");
    },
  });

  const surveys: SurveyDraft[] = listQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Surveys"
        description="Build, publish, and distribute customer surveys."
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            New survey
          </Button>
        }
      />

      <div className="flex items-center gap-2">
        <Switch
          id="include-archived"
          checked={includeArchived}
          onCheckedChange={setIncludeArchived}
        />
        <Label htmlFor="include-archived" className="text-sm text-muted-foreground">
          Show archived
        </Label>
      </div>

      {listQuery.isLoading ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            Loading surveys…
          </CardContent>
        </Card>
      ) : listQuery.isError ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-destructive">
            Failed to load surveys.
            <div className="mt-3">
              <Button variant="outline" size="sm" onClick={() => listQuery.refetch()}>
                Retry
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : surveys.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
            <ClipboardList className="h-10 w-10 text-muted-foreground" />
            <div>
              <p className="font-medium">No surveys yet</p>
              <p className="text-sm text-muted-foreground">
                Create your first survey to start collecting responses.
              </p>
            </div>
            <Button onClick={() => setCreateOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              New survey
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {surveys.map((s) => (
            <Card key={s.questionnaire_id} className="flex flex-col">
              <CardHeader>
                <div className="flex items-start justify-between gap-2">
                  <CardTitle className="text-base">{s.title}</CardTitle>
                  <Badge variant={statusVariant(s.status)}>{s.status}</Badge>
                </div>
                {s.description ? (
                  <CardDescription className="line-clamp-2">{s.description}</CardDescription>
                ) : null}
              </CardHeader>
              <CardContent className="mt-auto space-y-3">
                <p className="text-xs text-muted-foreground">
                  Updated {fmt(s.updated_at)} · {s.visibility}
                </p>
                <div className="flex flex-wrap gap-2">
                  <Button asChild variant="outline" size="sm">
                    <Link to={`/crm/surveys/${encodeURIComponent(s.questionnaire_id)}/build`}>
                      <Pencil className="mr-1.5 h-3.5 w-3.5" />
                      Build
                    </Link>
                  </Button>
                  <Button asChild variant="outline" size="sm">
                    <Link to={`/crm/surveys/${encodeURIComponent(s.questionnaire_id)}/results`}>
                      <BarChart3 className="mr-1.5 h-3.5 w-3.5" />
                      Results
                    </Link>
                  </Button>
                  {s.status !== "archived" ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={archiveMut.isPending}
                      onClick={() => {
                        if (confirm(`Archive "${s.title}"?`)) archiveMut.mutate(s.questionnaire_id);
                      }}
                    >
                      <Archive className="mr-1.5 h-3.5 w-3.5" />
                      Archive
                    </Button>
                  ) : null}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New survey</DialogTitle>
            <DialogDescription>Give your survey a title to get started.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="survey-title">Title</Label>
              <Input
                id="survey-title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Customer Satisfaction Survey"
                maxLength={240}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="survey-desc">Description</Label>
              <Textarea
                id="survey-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Optional description shown to respondents."
                maxLength={4000}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!title.trim() || createMut.isPending}
              onClick={() => createMut.mutate()}
            >
              {createMut.isPending ? "Creating…" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
