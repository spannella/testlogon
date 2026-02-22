import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, ArrowLeft, FolderSearch, Loader2, Plus, Trash2 } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";

import { addTrackedFile, getProjectDetail, removeTrackedFile } from "@/api/endpoints/projects";
import type { ProjectDetailResp, TrackedFile } from "@/api/types";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/shared/EmptyState";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

function formatDate(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function normalizeProviderRef(value: string): string {
  return value.trim();
}

export default function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const queryClient = useQueryClient();
  const [providerRef, setProviderRef] = React.useState("");
  const [displayPath, setDisplayPath] = React.useState("");
  const [removeDialogOpen, setRemoveDialogOpen] = React.useState(false);
  const [removeTarget, setRemoveTarget] = React.useState<TrackedFile | null>(null);

  const detailQuery = useQuery({
    queryKey: ["projects", "detail", projectId],
    queryFn: () => getProjectDetail(projectId!, { limit: 200 }),
    enabled: Boolean(projectId),
  });

  const addTrackedFileMutation = useMutation({
    mutationFn: (payload: { provider_ref: string; display_path?: string }) =>
      addTrackedFile(projectId!, {
        provider: "local",
        provider_ref: payload.provider_ref,
        display_path: payload.display_path,
        metadata: {},
      }),
    onMutate: async (payload) => {
      const optimisticRef = normalizeProviderRef(payload.provider_ref);
      if (!optimisticRef) return { previous: undefined as ProjectDetailResp | undefined };

      await queryClient.cancelQueries({ queryKey: ["projects", "detail", projectId] });
      const previous = queryClient.getQueryData<ProjectDetailResp>(["projects", "detail", projectId]);

      if (previous) {
        const optimisticFile: TrackedFile = {
          id: `optimistic-${Date.now()}`,
          project_id: projectId!,
          owner: previous.project.owner,
          provider: "local",
          provider_ref: optimisticRef,
          display_path: payload.display_path?.trim() || optimisticRef,
          status: "active",
          metadata: {},
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          last_seen_at: new Date().toISOString(),
          archived_at: null,
        };

        queryClient.setQueryData<ProjectDetailResp>(["projects", "detail", projectId], {
          ...previous,
          files: [optimisticFile, ...previous.files],
        });
      }

      setProviderRef("");
      setDisplayPath("");
      return { previous };
    },
    onError: (err, _payload, ctx) => {
      if (ctx?.previous) {
        queryClient.setQueryData(["projects", "detail", projectId], ctx.previous);
      }
      const message = err instanceof Error ? err.message : "Failed to add tracked file";
      toast.error(message);
    },
    onSuccess: () => {
      toast.success("Tracked file added");
    },
    onSettled: async () => {
      await queryClient.invalidateQueries({ queryKey: ["projects", "detail", projectId] });
    },
  });

  const removeTrackedFileMutation = useMutation({
    mutationFn: (trackedFileId: string) => removeTrackedFile(projectId!, trackedFileId),
    onMutate: async (trackedFileId) => {
      await queryClient.cancelQueries({ queryKey: ["projects", "detail", projectId] });
      const previous = queryClient.getQueryData<ProjectDetailResp>(["projects", "detail", projectId]);

      if (previous) {
        queryClient.setQueryData<ProjectDetailResp>(["projects", "detail", projectId], {
          ...previous,
          files: previous.files.filter((f) => f.id !== trackedFileId),
        });
      }

      return { previous };
    },
    onError: (err, _trackedFileId, ctx) => {
      if (ctx?.previous) {
        queryClient.setQueryData(["projects", "detail", projectId], ctx.previous);
      }
      const message = err instanceof Error ? err.message : "Failed to remove tracked file";
      toast.error(message);
    },
    onSuccess: () => {
      toast.success("Tracked file removed");
      setRemoveDialogOpen(false);
      setRemoveTarget(null);
    },
    onSettled: async () => {
      await queryClient.invalidateQueries({ queryKey: ["projects", "detail", projectId] });
    },
  });

  if (!projectId) {
    return (
      <div className="mx-auto w-full max-w-6xl p-4 sm:p-6">
        <Card>
          <CardHeader>
            <CardTitle>Invalid project route</CardTitle>
            <CardDescription>A project id is required to load this page.</CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  const missingCount = detailQuery.data?.files.filter((file) => file.status === "missing").length ?? 0;

  const onAddTrackedFile = () => {
    const normalizedRef = normalizeProviderRef(providerRef);
    if (!normalizedRef) {
      toast.error("File reference is required");
      return;
    }
    addTrackedFileMutation.mutate({
      provider_ref: normalizedRef,
      display_path: displayPath.trim() || undefined,
    });
  };

  const onRequestRemove = (file: TrackedFile) => {
    setRemoveTarget(file);
    setRemoveDialogOpen(true);
  };

  const onConfirmRemove = () => {
    if (!removeTarget) return;
    removeTrackedFileMutation.mutate(removeTarget.id);
  };

  return (
    <div className="mx-auto w-full max-w-6xl space-y-6 p-4 sm:p-6">
      <Button variant="ghost" asChild className="w-fit px-2">
        <Link to="/projects">
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to projects
        </Link>
      </Button>

      {detailQuery.isLoading && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground" data-testid="project-detail-loading">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading project details…
        </div>
      )}

      {detailQuery.isError && (
        <Card data-testid="project-detail-error">
          <CardHeader>
            <CardTitle>Could not load project details</CardTitle>
            <CardDescription>Please try again.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button variant="outline" onClick={() => detailQuery.refetch()}>Retry</Button>
          </CardContent>
        </Card>
      )}

      {!detailQuery.isLoading && !detailQuery.isError && detailQuery.data && (
        <>
          <Card>
            <CardHeader>
              <CardTitle>{detailQuery.data.project.name}</CardTitle>
              <CardDescription>
                {detailQuery.data.project.description || "No description provided."}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid gap-3 md:grid-cols-[1fr_1fr_auto]">
                <div className="space-y-1">
                  <Label htmlFor="tracked-provider-ref">File reference</Label>
                  <Input
                    id="tracked-provider-ref"
                    placeholder="/workspace/path/to/file.txt"
                    value={providerRef}
                    onChange={(e) => setProviderRef(e.target.value)}
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="tracked-display-path">Display path (optional)</Label>
                  <Input
                    id="tracked-display-path"
                    placeholder="Readable label/path"
                    value={displayPath}
                    onChange={(e) => setDisplayPath(e.target.value)}
                  />
                </div>
                <div className="flex items-end">
                  <Button onClick={onAddTrackedFile} disabled={addTrackedFileMutation.isPending}>
                    {addTrackedFileMutation.isPending ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Adding…
                      </>
                    ) : (
                      <>
                        <Plus className="mr-2 h-4 w-4" />
                        Add file
                      </>
                    )}
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          {missingCount > 0 && (
            <Card className="border-warning/40 bg-warning/10" data-testid="missing-files-warning">
              <CardContent className="flex items-center gap-2 p-4 text-sm">
                <AlertTriangle className="h-4 w-4 text-warning-foreground" />
                <span>
                  {missingCount} tracked {missingCount === 1 ? "file is" : "files are"} currently missing from provider.
                </span>
              </CardContent>
            </Card>
          )}

          {detailQuery.data.files.length === 0 ? (
            <EmptyState
              icon={<FolderSearch className="h-8 w-8" />}
              title="No tracked files"
              description="Add files to this project to monitor their status and metadata."
            />
          ) : (
            <Card data-testid="tracked-files-table">
              <CardHeader>
                <CardTitle>Tracked files</CardTitle>
                <CardDescription>File path, provider, status, and last-seen metadata.</CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Path</TableHead>
                      <TableHead>Provider</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Last seen</TableHead>
                      <TableHead className="w-[80px] text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {detailQuery.data.files.map((file) => {
                      const isMissing = file.status === "missing";
                      return (
                        <TableRow
                          key={file.id}
                          className={cn(isMissing && "bg-warning/5 hover:bg-warning/10")}
                          data-testid={isMissing ? "tracked-file-row-missing" : "tracked-file-row"}
                        >
                          <TableCell className="font-mono text-xs sm:text-sm">{file.display_path || file.provider_ref}</TableCell>
                          <TableCell className="capitalize">{file.provider}</TableCell>
                          <TableCell>
                            <Badge variant={isMissing ? "warning" : "secondary"}>{file.status}</Badge>
                          </TableCell>
                          <TableCell>{formatDate(file.last_seen_at)}</TableCell>
                          <TableCell className="text-right">
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => onRequestRemove(file)}
                              aria-label={`Remove tracked file ${file.display_path || file.provider_ref}`}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}

          <ConfirmDialog
            open={removeDialogOpen}
            onOpenChange={setRemoveDialogOpen}
            title="Remove tracked file?"
            description={
              removeTarget
                ? `This removes ${removeTarget.display_path || removeTarget.provider_ref} from this project.`
                : "This removes the selected tracked file from this project."
            }
            confirmLabel="Remove"
            variant="danger"
            loading={removeTrackedFileMutation.isPending}
            onConfirm={onConfirmRemove}
          />
        </>
      )}
    </div>
  );
}
