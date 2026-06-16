import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { FileText, Plus, Trash2, Eye, Save } from "lucide-react";

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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import {
  createEmailTemplate,
  deleteEmailTemplate,
  listEmailTemplates,
  previewEmailTemplate,
  updateEmailTemplate,
  type MarketingEmailTemplate,
  type MarketingEmailTemplatePreviewOut,
} from "@/api/endpoints/crmEmail";
import { NotEnabledState, isNotEnabledError } from "./NotEnabledState";

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

const BLANK = { name: "", subject_template: "", body_html_template: "" };

export default function EmailTemplatesPage() {
  const qc = useQueryClient();

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draft, setDraft] = useState<{
    name: string;
    subject_template: string;
    body_html_template: string;
    status?: "draft" | "active";
  }>(BLANK);
  const [isCreating, setIsCreating] = useState(false);

  const [previewOpen, setPreviewOpen] = useState(false);
  const [preview, setPreview] = useState<MarketingEmailTemplatePreviewOut | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<MarketingEmailTemplate | null>(null);

  const listQuery = useQuery({
    queryKey: ["crm-email", "templates"],
    queryFn: () => listEmailTemplates({ limit: 100 }),
    retry: false,
  });

  const templates = listQuery.data?.templates ?? [];

  const selectTemplate = (t: MarketingEmailTemplate) => {
    setIsCreating(false);
    setSelectedId(t.template_id);
    setDraft({
      name: t.name,
      subject_template: t.subject_template,
      body_html_template: t.body_html_template,
      status: t.status === "active" ? "active" : "draft",
    });
  };

  const startCreate = () => {
    setIsCreating(true);
    setSelectedId(null);
    setDraft(BLANK);
  };

  const createMut = useMutation({
    mutationFn: () =>
      createEmailTemplate({
        name: draft.name.trim(),
        subject_template: draft.subject_template.trim(),
        body_html_template: draft.body_html_template,
      }),
    onSuccess: (res) => {
      toast.success("Template created");
      setIsCreating(false);
      setSelectedId(res.template_id);
      void qc.invalidateQueries({ queryKey: ["crm-email", "templates"] });
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to create template"),
  });

  const updateMut = useMutation({
    mutationFn: () =>
      updateEmailTemplate(selectedId!, {
        name: draft.name.trim(),
        subject_template: draft.subject_template.trim(),
        body_html_template: draft.body_html_template,
        status: draft.status,
      }),
    onSuccess: () => {
      toast.success("Template saved");
      void qc.invalidateQueries({ queryKey: ["crm-email", "templates"] });
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to save template"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteEmailTemplate(id),
    onSuccess: (_res, id) => {
      toast.success("Template deleted");
      if (selectedId === id) {
        setSelectedId(null);
        setDraft(BLANK);
      }
      setDeleteTarget(null);
      void qc.invalidateQueries({ queryKey: ["crm-email", "templates"] });
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to delete template"),
  });

  const previewMut = useMutation({
    mutationFn: () => previewEmailTemplate(selectedId!, {}),
    onSuccess: (res) => {
      setPreview(res);
      setPreviewOpen(true);
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to render preview"),
  });

  const canSave = useMemo(
    () =>
      draft.name.trim().length > 0 &&
      draft.subject_template.trim().length > 0 &&
      draft.body_html_template.trim().length > 0,
    [draft],
  );

  const editorOpen = isCreating || selectedId !== null;

  // Feature-flag OFF → friendly empty state
  if (listQuery.isError && isNotEnabledError(listQuery.error)) {
    return (
      <div className="space-y-6">
        <PageHeader title="Email Templates" description="SuiteCRM HTML email template library" />
        <NotEnabledState feature="Email templates" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Email Templates"
        description="Build reusable HTML email templates with merge tags like {{first_name}}."
        actions={
          <Button onClick={startCreate}>
            <Plus className="mr-2 h-4 w-4" /> New template
          </Button>
        }
      />

      <div className="grid gap-6 lg:grid-cols-[340px_1fr]">
        {/* Template list */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Templates</CardTitle>
            <CardDescription>
              {listQuery.data ? `${listQuery.data.count} template(s)` : "Loading…"}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {listQuery.isLoading && (
              <>
                <Skeleton className="h-12 w-full" />
                <Skeleton className="h-12 w-full" />
                <Skeleton className="h-12 w-full" />
              </>
            )}
            {listQuery.isError && !isNotEnabledError(listQuery.error) && (
              <p className="text-sm text-destructive">
                {(listQuery.error as ApiError)?.detail ?? "Failed to load templates"}
              </p>
            )}
            {!listQuery.isLoading && templates.length === 0 && (
              <p className="py-8 text-center text-sm text-muted-foreground">
                No templates yet. Create your first one.
              </p>
            )}
            {templates.map((t) => (
              <button
                key={t.template_id}
                onClick={() => selectTemplate(t)}
                className={`flex w-full flex-col gap-1 rounded-md border p-3 text-left transition hover:bg-accent ${
                  selectedId === t.template_id ? "border-primary bg-accent" : "border-border"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="flex items-center gap-2 truncate font-medium">
                    <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />
                    {t.name}
                  </span>
                  <Badge variant={t.status === "active" ? "default" : "secondary"}>
                    {t.status}
                  </Badge>
                </div>
                <span className="truncate text-xs text-muted-foreground">
                  {t.subject_template}
                </span>
                <span className="text-xs text-muted-foreground">Updated {fmt(t.updated_at)}</span>
              </button>
            ))}
          </CardContent>
        </Card>

        {/* Editor */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {isCreating ? "New template" : selectedId ? "Edit template" : "Editor"}
            </CardTitle>
            <CardDescription>
              Use <code>{"{{variable}}"}</code> merge tags. They are auto-detected and listed on
              save.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {!editorOpen ? (
              <p className="py-12 text-center text-sm text-muted-foreground">
                Select a template or create a new one to start editing.
              </p>
            ) : (
              <>
                <div className="space-y-2">
                  <Label htmlFor="tpl-name">Name</Label>
                  <Input
                    id="tpl-name"
                    value={draft.name}
                    maxLength={120}
                    placeholder="Welcome email"
                    onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="tpl-subject">Subject</Label>
                  <Input
                    id="tpl-subject"
                    value={draft.subject_template}
                    maxLength={500}
                    placeholder="Welcome, {{first_name}}!"
                    onChange={(e) =>
                      setDraft((d) => ({ ...d, subject_template: e.target.value }))
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="tpl-body">HTML body</Label>
                  <Textarea
                    id="tpl-body"
                    value={draft.body_html_template}
                    maxLength={50000}
                    rows={14}
                    className="font-mono text-xs"
                    placeholder="<h1>Hello {{first_name}}</h1><p>…</p>"
                    onChange={(e) =>
                      setDraft((d) => ({ ...d, body_html_template: e.target.value }))
                    }
                  />
                </div>

                {!isCreating && selectedId && (
                  <div className="flex items-center gap-3">
                    <Label htmlFor="tpl-status" className="text-sm">
                      Status
                    </Label>
                    <Button
                      id="tpl-status"
                      type="button"
                      variant={draft.status === "active" ? "default" : "outline"}
                      size="sm"
                      onClick={() =>
                        setDraft((d) => ({
                          ...d,
                          status: d.status === "active" ? "draft" : "active",
                        }))
                      }
                    >
                      {draft.status === "active" ? "Active" : "Draft"}
                    </Button>
                  </div>
                )}

                <div className="flex flex-wrap gap-2 pt-2">
                  {isCreating ? (
                    <Button onClick={() => createMut.mutate()} disabled={!canSave || createMut.isPending}>
                      <Save className="mr-2 h-4 w-4" />
                      {createMut.isPending ? "Creating…" : "Create template"}
                    </Button>
                  ) : (
                    <>
                      <Button
                        onClick={() => updateMut.mutate()}
                        disabled={!canSave || updateMut.isPending}
                      >
                        <Save className="mr-2 h-4 w-4" />
                        {updateMut.isPending ? "Saving…" : "Save changes"}
                      </Button>
                      <Button
                        variant="outline"
                        onClick={() => previewMut.mutate()}
                        disabled={previewMut.isPending}
                      >
                        <Eye className="mr-2 h-4 w-4" /> Preview
                      </Button>
                      <Button
                        variant="ghost"
                        className="text-destructive hover:text-destructive"
                        onClick={() => {
                          const t = templates.find((x) => x.template_id === selectedId);
                          if (t) setDeleteTarget(t);
                        }}
                      >
                        <Trash2 className="mr-2 h-4 w-4" /> Delete
                      </Button>
                    </>
                  )}
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Preview dialog */}
      <Dialog open={previewOpen} onOpenChange={setPreviewOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Template preview</DialogTitle>
            <DialogDescription>Rendered with sample merge values.</DialogDescription>
          </DialogHeader>
          {preview && (
            <div className="space-y-4">
              <div>
                <Label className="text-xs text-muted-foreground">Subject</Label>
                <p className="font-medium">{preview.subject}</p>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Body</Label>
                <div
                  className="mt-1 max-h-80 overflow-auto rounded-md border bg-white p-4 text-sm text-black"
                  dangerouslySetInnerHTML={{ __html: preview.body_html }}
                />
              </div>
              {preview.variables.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {preview.variables.map((v) => (
                    <Badge key={v} variant="secondary">
                      {v}
                    </Badge>
                  ))}
                </div>
              )}
              {preview.missing_vars.length > 0 && (
                <p className="text-xs text-amber-600">
                  Missing values: {preview.missing_vars.join(", ")}
                </p>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Delete confirmation */}
      <Dialog open={!!deleteTarget} onOpenChange={(o) => !o && setDeleteTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete template?</DialogTitle>
            <DialogDescription>
              This permanently deletes “{deleteTarget?.name}”. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => deleteTarget && deleteMut.mutate(deleteTarget.template_id)}
              disabled={deleteMut.isPending}
            >
              {deleteMut.isPending ? "Deleting…" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
