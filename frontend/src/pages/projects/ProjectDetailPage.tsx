import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, ArrowLeft, CheckCircle2, FolderSearch, Link2, Loader2, Plus, Trash2, Unlink2 } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";

import { ApiError } from "@/api/client";
import {
  addTrackedFile,
  completeGoogleDriveOauth,
  deleteProviderCredential,
  getProjectDetail,
  getProviderCredential,
  removeTrackedFile,
  startGoogleDriveOauth,
} from "@/api/endpoints/projects";
import type { ProjectDetailResp, ProviderCredential, TrackedFile } from "@/api/types";
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
import {
  buildGoogleDriveReturnUrl,
  isGoogleDriveCallback,
  parseGoogleDriveCallbackParams,
  stripGoogleDriveCallbackParams,
} from "@/lib/googleDriveOauth";
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

const GDRIVE_PROVIDER = "google_drive";

export default function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const queryClient = useQueryClient();
  const [providerRef, setProviderRef] = React.useState("");
  const [displayPath, setDisplayPath] = React.useState("");
  const [removeDialogOpen, setRemoveDialogOpen] = React.useState(false);
  const [removeTarget, setRemoveTarget] = React.useState<TrackedFile | null>(null);
  // When the credential endpoint 404s the provider surface is simply not
  // available on this deployment — degrade to "hidden" rather than erroring.
  const [gdriveAvailable, setGdriveAvailable] = React.useState(true);

  const detailQuery = useQuery({
    queryKey: ["projects", "detail", projectId],
    queryFn: () => getProjectDetail(projectId!, { limit: 200 }),
    enabled: Boolean(projectId),
  });

  const gdriveCredentialQuery = useQuery<ProviderCredential | null>({
    queryKey: ["projects", "provider-credential", GDRIVE_PROVIDER],
    queryFn: async () => {
      try {
        return await getProviderCredential(GDRIVE_PROVIDER);
      } catch (err) {
        // 404 = no credential stored yet (honest-empty). Any other status that
        // signals the provider surface is absent also degrades to "no feature".
        if (err instanceof ApiError && err.status === 404) {
          return null;
        }
        throw err;
      }
    },
    enabled: Boolean(projectId),
    retry: false,
  });

  React.useEffect(() => {
    const err = gdriveCredentialQuery.error;
    if (err instanceof ApiError && (err.status === 404 || err.status === 405 || err.status === 501)) {
      setGdriveAvailable(false);
    }
  }, [gdriveCredentialQuery.error]);

  const gdriveConnected = Boolean(gdriveCredentialQuery.data);

  const connectGdriveMutation = useMutation({
    mutationFn: () => startGoogleDriveOauth(),
    onSuccess: (data) => {
      // Persist where to return so the callback effect knows this is our page.
      window.location.href = data.authorization_url;
    },
    onError: (err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 405 || err.status === 501)) {
        setGdriveAvailable(false);
        return;
      }
      const message = err instanceof Error ? err.message : "Unable to start Google Drive connection";
      toast.error(message);
    },
  });

  const completeGdriveMutation = useMutation({
    mutationFn: (body: { code: string; state: string }) => completeGoogleDriveOauth(body),
    onSuccess: () => {
      toast.success("Google Drive connected");
      queryClient.invalidateQueries({ queryKey: ["projects", "provider-credential", GDRIVE_PROVIDER] });
    },
    onError: (err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 405 || err.status === 501)) {
        setGdriveAvailable(false);
        return;
      }
      const message = err instanceof Error ? err.message : "Unable to complete Google Drive connection";
      toast.error(message);
    },
  });

  const disconnectGdriveMutation = useMutation({
    mutationFn: () => deleteProviderCredential(GDRIVE_PROVIDER),
    onSuccess: () => {
      toast.success("Google Drive disconnected");
      queryClient.invalidateQueries({ queryKey: ["projects", "provider-credential", GDRIVE_PROVIDER] });
    },
    onError: (err) => {
      const message = err instanceof Error ? err.message : "Unable to disconnect Google Drive";
      toast.error(message);
    },
  });

  // Handle the OAuth redirect landing back on this page (?code=&state=&provider=).
  const completeGdriveRef = React.useRef(completeGdriveMutation);
  completeGdriveRef.current = completeGdriveMutation;
  React.useEffect(() => {
    const parsed = parseGoogleDriveCallbackParams(window.location.search);
    if (parsed.error) {
      toast.error(`Google Drive authorization failed: ${parsed.error}`);
      const next = stripGoogleDriveCallbackParams(window.location.search);
      window.history.replaceState({}, "", `${window.location.pathname}${next ? `?${next}` : ""}`);
      return;
    }
    if (!isGoogleDriveCallback(parsed) || !parsed.code || !parsed.state) return;
    const mutation = completeGdriveRef.current;
    if (mutation.isPending || mutation.isSuccess) return;
    mutation.mutate({ code: parsed.code, state: parsed.state });
    const next = stripGoogleDriveCallbackParams(window.location.search);
    window.history.replaceState({}, "", `${window.location.pathname}${next ? `?${next}` : ""}`);
  }, []);

  const onConnectGdrive = () => {
    // buildGoogleDriveReturnUrl documents the return contract; the backend owns
    // the configured redirect_uri, but we tag our own origin path for clarity.
    void buildGoogleDriveReturnUrl(window.location.origin, window.location.pathname);
    connectGdriveMutation.mutate();
  };

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

          {gdriveAvailable && (
            <Card data-testid="gdrive-provider-card">
              <CardHeader>
                <CardTitle>Google Drive</CardTitle>
                <CardDescription>
                  Connect Google Drive to track files stored in your Drive from this project.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {gdriveCredentialQuery.isLoading ? (
                  <p className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Checking connection…
                  </p>
                ) : gdriveConnected ? (
                  <div className="rounded-md border bg-muted/20 p-3 text-sm">
                    <p className="mb-1 flex items-center gap-2 font-medium">
                      <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                      Google Drive connected
                    </p>
                    {gdriveCredentialQuery.data?.scopes?.length ? (
                      <p className="text-muted-foreground">
                        Scopes: {gdriveCredentialQuery.data.scopes.join(", ")}
                      </p>
                    ) : null}
                    <p className="text-muted-foreground">
                      Connected {formatDate(gdriveCredentialQuery.data?.updated_at)}
                    </p>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    Google Drive is not connected for your account.
                  </p>
                )}

                <div className="flex flex-wrap gap-2">
                  <Button
                    onClick={onConnectGdrive}
                    disabled={connectGdriveMutation.isPending || completeGdriveMutation.isPending}
                  >
                    {connectGdriveMutation.isPending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Link2 className="mr-2 h-4 w-4" />
                    )}
                    {gdriveConnected ? "Reconnect Google Drive" : "Connect Google Drive"}
                  </Button>
                  {gdriveConnected && (
                    <Button
                      variant="outline"
                      onClick={() => disconnectGdriveMutation.mutate()}
                      disabled={disconnectGdriveMutation.isPending}
                    >
                      {disconnectGdriveMutation.isPending ? (
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      ) : (
                        <Unlink2 className="mr-2 h-4 w-4" />
                      )}
                      Disconnect
                    </Button>
                  )}
                </div>

                {completeGdriveMutation.isPending && (
                  <p className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Completing Google Drive authorization…
                  </p>
                )}
              </CardContent>
            </Card>
          )}

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
