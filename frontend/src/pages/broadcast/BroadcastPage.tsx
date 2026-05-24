import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Radio,
  Plus,
  RefreshCw,
  Loader2,
  Play,
  Square,
  Trash2,
  Copy,
  ExternalLink,
  Eye,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import {
  listSessions,
  listProfiles,
  createProfile,
  createSession,
  startSession,
  stopSession,
  deleteSession,
  getSession,
  mintPlaybackUrl,
  getAuditLog,
  type BroadcastSession,
  type BroadcastProfile,
  type BroadcastSessionStatus,
  type BroadcastAuditEntry,
} from "@/api/endpoints/broadcast";

// ─── Status Badge Colors ────────────────────────────────���───────

const STATUS_STYLES: Record<BroadcastSessionStatus, string> = {
  draft: "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300",
  provisioning: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
  ready: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
  live: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
  stopping: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200",
  stopped: "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400",
  error: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
};

function StatusBadge({ status }: { status: BroadcastSessionStatus }) {
  return (
    <Badge variant="secondary" className={`${STATUS_STYLES[status] ?? ""} gap-1`}>
      {status === "live" && (
        <span className="inline-block h-2 w-2 rounded-full bg-green-500 animate-pulse" />
      )}
      {(status === "provisioning" || status === "stopping") && (
        <Loader2 className="h-3 w-3 animate-spin" />
      )}
      {status}
    </Badge>
  );
}

// ─── Main Page Component ───────────────────���────────────────────

export default function BroadcastPage() {
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [createSessionOpen, setCreateSessionOpen] = useState(false);
  const [createProfileOpen, setCreateProfileOpen] = useState(false);
  const [confirmAction, setConfirmAction] = useState<{
    type: "start" | "stop" | "delete";
    sessionId: string;
    sessionName?: string;
  } | null>(null);

  // ─── Queries ──────────��─────────────────────────────────────────

  const sessionsQuery = useQuery({
    queryKey: ["broadcast", "sessions", statusFilter],
    queryFn: () => listSessions(statusFilter !== "all" ? { status: statusFilter } : undefined),
    refetchInterval: 10_000,
    refetchIntervalInBackground: false,
  });

  const profilesQuery = useQuery({
    queryKey: ["broadcast", "profiles"],
    queryFn: () => listProfiles(),
    staleTime: 60_000,
  });

  const sessionDetailQuery = useQuery({
    queryKey: ["broadcast", "sessions", selectedSessionId],
    queryFn: () => getSession(selectedSessionId!),
    enabled: !!selectedSessionId,
    refetchInterval: selectedSessionId ? 5_000 : false,
  });

  const auditQuery = useQuery({
    queryKey: ["broadcast", "audit"],
    queryFn: () => getAuditLog({ limit: 100 }),
    staleTime: 30_000,
  });

  // ─── Mutations ──────────────────────────────────────────────────

  const startMut = useMutation({
    mutationFn: (id: string) => startSession(id, { reason: "operator-request" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast", "sessions"] });
      toast.success("Session starting...");
      setConfirmAction(null);
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to start session"),
  });

  const stopMut = useMutation({
    mutationFn: (id: string) => stopSession(id, { reason: "operator-request" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast", "sessions"] });
      toast.success("Session stopping...");
      setConfirmAction(null);
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to stop session"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteSession(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast", "sessions"] });
      toast.success("Session deleted");
      setConfirmAction(null);
      setSelectedSessionId(null);
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to delete session"),
  });

  // ─── Helpers ────────────────────��───────────────────────────────

  const sessions: BroadcastSession[] = sessionsQuery.data?.items ?? [];
  const profiles: BroadcastProfile[] = profilesQuery.data?.items ?? [];
  const auditEntries: BroadcastAuditEntry[] = auditQuery.data?.items ?? [];
  const selectedSession = sessionDetailQuery.data ?? null;

  const getProfileName = (profileId: string) => {
    const p = profiles.find((pr) => pr.id === profileId);
    return p?.name ?? profileId.slice(0, 8) + "...";
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success("Copied to clipboard");
    } catch {
      toast.error("Failed to copy");
    }
  };

  // ─── Render ───────────────────────���───────────────��─────────────

  return (
    <div className="p-4 md:p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <Radio className="h-7 w-7 text-primary" />
          <div>
            <h1 className="text-2xl font-bold">Broadcast</h1>
            <p className="text-sm text-muted-foreground">
              Manage broadcast profiles, sessions, and live streams
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setCreateProfileOpen(true)}>
            <Plus className="h-4 w-4 mr-1" /> New Profile
          </Button>
          <Button size="sm" onClick={() => setCreateSessionOpen(true)}>
            <Plus className="h-4 w-4 mr-1" /> New Session
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="sessions" className="space-y-4">
        <TabsList>
          <TabsTrigger value="sessions">Sessions</TabsTrigger>
          <TabsTrigger value="profiles">Profiles</TabsTrigger>
          <TabsTrigger value="audit">Audit Log</TabsTrigger>
        </TabsList>

        {/* ── Sessions Tab ─────────────────────────────────────── */}
        <TabsContent value="sessions" className="space-y-4">
          {/* Filter bar */}
          <div className="flex items-center gap-3">
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="Filter by status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                <SelectItem value="draft">Draft</SelectItem>
                <SelectItem value="provisioning">Provisioning</SelectItem>
                <SelectItem value="ready">Ready</SelectItem>
                <SelectItem value="live">Live</SelectItem>
                <SelectItem value="stopping">Stopping</SelectItem>
                <SelectItem value="stopped">Stopped</SelectItem>
                <SelectItem value="error">Error</SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => queryClient.invalidateQueries({ queryKey: ["broadcast", "sessions"] })}
            >
              <RefreshCw className="h-4 w-4" />
            </Button>
            <Badge variant="outline" className="text-xs">
              Auto-refresh: 10s
            </Badge>
          </div>

          {/* Session cards */}
          {sessionsQuery.isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : sessions.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                <Radio className="h-12 w-12 text-muted-foreground/50 mb-4" />
                <h3 className="text-lg font-medium">No broadcast sessions</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Create a session to get started with live streaming.
                </p>
                <Button className="mt-4" onClick={() => setCreateSessionOpen(true)}>
                  <Plus className="h-4 w-4 mr-1" /> Create Session
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              {sessions.map((session) => (
                <Card key={session.id} className="relative">
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-sm font-medium truncate">
                        {session.id.slice(0, 8)}...
                      </CardTitle>
                      <StatusBadge status={session.status} />
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Profile:</span>
                      <span className="font-medium truncate ml-2">
                        {getProfileName(session.profile_id)}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Created:</span>
                      <span>{new Date(session.created_at).toLocaleString()}</span>
                    </div>
                    {session.started_at && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Started:</span>
                        <span>{new Date(session.started_at).toLocaleString()}</span>
                      </div>
                    )}
                    {session.ingest_url && (
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Ingest:</span>
                        <div className="flex items-center gap-1">
                          <span className="truncate max-w-[150px] text-xs">{session.ingest_url}</span>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-5 w-5"
                            onClick={() => copyToClipboard(session.ingest_url!)}
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    )}
                    <div className="flex gap-2 pt-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setSelectedSessionId(session.id)}
                      >
                        <Eye className="h-3 w-3 mr-1" /> Details
                      </Button>
                      {(session.status === "draft" || session.status === "ready") && (
                        <Button
                          variant="default"
                          size="sm"
                          onClick={() =>
                            setConfirmAction({ type: "start", sessionId: session.id })
                          }
                        >
                          <Play className="h-3 w-3 mr-1" /> Start
                        </Button>
                      )}
                      {session.status === "live" && (
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() =>
                            setConfirmAction({ type: "stop", sessionId: session.id })
                          }
                        >
                          <Square className="h-3 w-3 mr-1" /> Stop
                        </Button>
                      )}
                      {(session.status === "stopped" || session.status === "error" || session.status === "draft") && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-destructive"
                          onClick={() =>
                            setConfirmAction({ type: "delete", sessionId: session.id })
                          }
                        >
                          <Trash2 className="h-3 w-3 mr-1" /> Delete
                        </Button>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ── Profiles Tab ─────────────────────���───────────────── */}
        <TabsContent value="profiles" className="space-y-4">
          {profilesQuery.isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : profiles.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                <Radio className="h-12 w-12 text-muted-foreground/50 mb-4" />
                <h3 className="text-lg font-medium">No broadcast profiles</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Create a profile to define encoding settings for your sessions.
                </p>
                <Button className="mt-4" onClick={() => setCreateProfileOpen(true)}>
                  <Plus className="h-4 w-4 mr-1" /> Create Profile
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              {profiles.map((profile) => (
                <Card key={profile.id}>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium">{profile.name}</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Region:</span>
                      <span>{profile.region}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Preset:</span>
                      <span>{profile.rendition_preset}</span>
                    </div>
                    {profile.watermark_asset && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Watermark:</span>
                        <Badge variant="secondary" className="text-xs">Yes</Badge>
                      </div>
                    )}
                    {profile.drm_policy_id && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">DRM:</span>
                        <span className="truncate max-w-[150px] text-xs">{profile.drm_policy_id}</span>
                      </div>
                    )}
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Created:</span>
                      <span>{new Date(profile.created_at).toLocaleString()}</span>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ── Audit Log Tab ───────────────────────��────────────── */}
        <TabsContent value="audit" className="space-y-4">
          {auditQuery.isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : auditQuery.isError ? (
            <Card>
              <CardContent className="py-8 text-center">
                <p className="text-sm text-muted-foreground">
                  Unable to load audit log. Admin role required.
                </p>
              </CardContent>
            </Card>
          ) : auditEntries.length === 0 ? (
            <Card>
              <CardContent className="py-8 text-center">
                <p className="text-sm text-muted-foreground">No audit entries yet.</p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Action</TableHead>
                      <TableHead>Resource</TableHead>
                      <TableHead>Actor</TableHead>
                      <TableHead>Time</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {auditEntries.map((entry) => (
                      <TableRow key={entry.audit_id}>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {entry.action}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs">
                          {entry.resource_type}/{entry.resource_id.slice(0, 8)}...
                        </TableCell>
                        <TableCell className="text-xs truncate max-w-[120px]">
                          {entry.actor.slice(0, 12)}...
                        </TableCell>
                        <TableCell className="text-xs">
                          {new Date(entry.created_at).toLocaleString()}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>

      {/* ── Session Detail Dialog ─────────────────��────────────── */}
      <SessionDetailDialog
        session={selectedSession}
        open={!!selectedSessionId}
        onClose={() => setSelectedSessionId(null)}
        getProfileName={getProfileName}
        copyToClipboard={copyToClipboard}
        onStart={(id) => setConfirmAction({ type: "start", sessionId: id })}
        onStop={(id) => setConfirmAction({ type: "stop", sessionId: id })}
        onDelete={(id) => setConfirmAction({ type: "delete", sessionId: id })}
      />

      {/* ── Create Session Dialog ───────────────���──────────────── */}
      <CreateSessionDialog
        open={createSessionOpen}
        onClose={() => setCreateSessionOpen(false)}
        profiles={profiles}
      />

      {/* ── Create Profile Dialog ──────────────────────────────── */}
      <CreateProfileDialog
        open={createProfileOpen}
        onClose={() => setCreateProfileOpen(false)}
      />

      {/* ── Confirmation Dialog ────────────────────��───────────── */}
      <AlertDialog open={!!confirmAction} onOpenChange={() => setConfirmAction(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {confirmAction?.type === "start" && "Start Session?"}
              {confirmAction?.type === "stop" && "Stop Session?"}
              {confirmAction?.type === "delete" && "Delete Session?"}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {confirmAction?.type === "start" &&
                "This will begin provisioning and start the live broadcast."}
              {confirmAction?.type === "stop" &&
                "This will stop the live broadcast. The session can be restarted later."}
              {confirmAction?.type === "delete" &&
                "This will permanently delete the session. This action cannot be undone."}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (!confirmAction) return;
                if (confirmAction.type === "start") startMut.mutate(confirmAction.sessionId);
                if (confirmAction.type === "stop") stopMut.mutate(confirmAction.sessionId);
                if (confirmAction.type === "delete") deleteMut.mutate(confirmAction.sessionId);
              }}
              className={confirmAction?.type === "delete" ? "bg-destructive text-destructive-foreground hover:bg-destructive/90" : ""}
            >
              {confirmAction?.type === "start" && "Start"}
              {confirmAction?.type === "stop" && "Stop"}
              {confirmAction?.type === "delete" && "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

// ─── Session Detail Dialog ────────────────��─────────────────────

function SessionDetailDialog({
  session,
  open,
  onClose,
  getProfileName,
  copyToClipboard,
  onStart,
  onStop,
  onDelete,
}: {
  session: BroadcastSession | null;
  open: boolean;
  onClose: () => void;
  getProfileName: (id: string) => string;
  copyToClipboard: (text: string) => void;
  onStart: (id: string) => void;
  onStop: (id: string) => void;
  onDelete: (id: string) => void;
}) {
  const [playbackUrl, setPlaybackUrl] = useState<string | null>(null);

  const mintMut = useMutation({
    mutationFn: (id: string) => mintPlaybackUrl(id),
    onSuccess: (data) => {
      setPlaybackUrl(data.playback_url);
      toast.success("Playback URL generated");
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to mint URL"),
  });

  if (!session) return null;

  return (
    <Dialog open={open} onOpenChange={() => { onClose(); setPlaybackUrl(null); }}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            Session: {session.id.slice(0, 12)}...
            <StatusBadge status={session.status} />
          </DialogTitle>
          <DialogDescription>
            Profile: {getProfileName(session.profile_id)}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Timestamps */}
          <div className="grid grid-cols-2 gap-2 text-sm">
            <div>
              <span className="text-muted-foreground">Created: </span>
              {new Date(session.created_at).toLocaleString()}
            </div>
            {session.started_at && (
              <div>
                <span className="text-muted-foreground">Started: </span>
                {new Date(session.started_at).toLocaleString()}
              </div>
            )}
            {session.stopped_at && (
              <div>
                <span className="text-muted-foreground">Stopped: </span>
                {new Date(session.stopped_at).toLocaleString()}
              </div>
            )}
          </div>

          {/* Ingest Configuration */}
          {session.ingest_url && (
            <div className="space-y-2">
              <h4 className="text-sm font-medium">Ingest Configuration</h4>
              <div className="rounded-md border p-3 space-y-2 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">RTMP URL:</span>
                  <div className="flex items-center gap-1">
                    <code className="text-xs bg-muted px-2 py-1 rounded">{session.ingest_url}</code>
                    <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => copyToClipboard(session.ingest_url!)}>
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
                {session.stream_key_ref && (
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Stream Key:</span>
                    <div className="flex items-center gap-1">
                      <code className="text-xs bg-muted px-2 py-1 rounded truncate max-w-[250px]">
                        {session.stream_key_ref}
                      </code>
                      <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => copyToClipboard(session.stream_key_ref!)}>
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Playback */}
          <div className="space-y-2">
            <h4 className="text-sm font-medium">Playback</h4>
            <div className="rounded-md border p-3 space-y-2 text-sm">
              {session.cloudfront_playback_url && (
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">CloudFront URL:</span>
                  <div className="flex items-center gap-1">
                    <code className="text-xs bg-muted px-2 py-1 rounded truncate max-w-[200px]">
                      {session.cloudfront_playback_url}
                    </code>
                    <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => copyToClipboard(session.cloudfront_playback_url!)}>
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              )}
              {playbackUrl && (
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Minted URL:</span>
                  <div className="flex items-center gap-1">
                    <code className="text-xs bg-muted px-2 py-1 rounded truncate max-w-[200px]">
                      {playbackUrl}
                    </code>
                    <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => copyToClipboard(playbackUrl)}>
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              )}
              <Button
                variant="outline"
                size="sm"
                onClick={() => mintMut.mutate(session.id)}
                disabled={mintMut.isPending}
              >
                {mintMut.isPending ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <ExternalLink className="h-3 w-3 mr-1" />}
                Mint Playback URL
              </Button>
            </div>
          </div>

          {/* AWS Resources */}
          {(session.aws_input_arn || session.aws_channel_arn || session.mediapackage_endpoint || session.s3_archive_prefix) && (
            <div className="space-y-2">
              <h4 className="text-sm font-medium">AWS Resources</h4>
              <div className="rounded-md border p-3 space-y-1 text-xs">
                {session.aws_input_arn && (
                  <div><span className="text-muted-foreground">Input ARN:</span> {session.aws_input_arn}</div>
                )}
                {session.aws_channel_arn && (
                  <div><span className="text-muted-foreground">Channel ARN:</span> {session.aws_channel_arn}</div>
                )}
                {session.mediapackage_endpoint && (
                  <div><span className="text-muted-foreground">MediaPackage:</span> {session.mediapackage_endpoint}</div>
                )}
                {session.s3_archive_prefix && (
                  <div><span className="text-muted-foreground">S3 Archive:</span> {session.s3_archive_prefix}</div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Actions */}
        <DialogFooter className="gap-2 sm:gap-0">
          {(session.status === "draft" || session.status === "ready") && (
            <Button onClick={() => onStart(session.id)}>
              <Play className="h-4 w-4 mr-1" /> Start
            </Button>
          )}
          {session.status === "live" && (
            <Button variant="destructive" onClick={() => onStop(session.id)}>
              <Square className="h-4 w-4 mr-1" /> Stop
            </Button>
          )}
          {(session.status === "stopped" || session.status === "error" || session.status === "draft") && (
            <Button variant="outline" className="text-destructive" onClick={() => onDelete(session.id)}>
              <Trash2 className="h-4 w-4 mr-1" /> Delete
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Create Session Dialog ─────────────────────────────��────────

function CreateSessionDialog({
  open,
  onClose,
  profiles,
}: {
  open: boolean;
  onClose: () => void;
  profiles: BroadcastProfile[];
}) {
  const queryClient = useQueryClient();
  const [profileId, setProfileId] = useState("");
  const [ingestUrl, setIngestUrl] = useState("");
  const [streamKeyRef, setStreamKeyRef] = useState("");

  const createMut = useMutation({
    mutationFn: () =>
      createSession({
        profile_id: profileId,
        ingest_url: ingestUrl || undefined,
        stream_key_ref: streamKeyRef || undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast", "sessions"] });
      toast.success("Session created");
      onClose();
      setProfileId("");
      setIngestUrl("");
      setStreamKeyRef("");
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to create session"),
  });

  return (
    <Dialog open={open} onOpenChange={() => onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create Broadcast Session</DialogTitle>
          <DialogDescription>
            Create a new session linked to an encoding profile.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="session-profile">Profile</Label>
            <Select value={profileId} onValueChange={setProfileId}>
              <SelectTrigger id="session-profile">
                <SelectValue placeholder="Select a profile" />
              </SelectTrigger>
              <SelectContent>
                {profiles.map((p) => (
                  <SelectItem key={p.id} value={p.id}>
                    {p.name} ({p.region} / {p.rendition_preset})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="session-ingest">Ingest URL (optional)</Label>
            <Input
              id="session-ingest"
              placeholder="rtmp://ingest.example.com/live"
              value={ingestUrl}
              onChange={(e) => setIngestUrl(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="session-key">Stream Key Reference (optional)</Label>
            <Input
              id="session-key"
              placeholder="arn:aws:secretsmanager:..."
              value={streamKeyRef}
              onChange={(e) => setStreamKeyRef(e.target.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={() => createMut.mutate()} disabled={!profileId || createMut.isPending}>
            {createMut.isPending && <Loader2 className="h-4 w-4 mr-1 animate-spin" />}
            Create Session
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Create Profile Dialog ───────────────────────────��──────────

function CreateProfileDialog({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [region, setRegion] = useState("us-east-1");
  const [preset, setPreset] = useState("720p_3mbps");

  const createMut = useMutation({
    mutationFn: () =>
      createProfile({
        name,
        region,
        rendition_preset: preset,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast", "profiles"] });
      toast.success("Profile created");
      onClose();
      setName("");
      setRegion("us-east-1");
      setPreset("720p_3mbps");
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to create profile"),
  });

  return (
    <Dialog open={open} onOpenChange={() => onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create Broadcast Profile</DialogTitle>
          <DialogDescription>
            Define encoding settings for your broadcast sessions.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="profile-name">Name</Label>
            <Input
              id="profile-name"
              placeholder="Main Encoder"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="profile-region">Region</Label>
            <Select value={region} onValueChange={setRegion}>
              <SelectTrigger id="profile-region">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="us-east-1">us-east-1</SelectItem>
                <SelectItem value="us-west-2">us-west-2</SelectItem>
                <SelectItem value="eu-west-1">eu-west-1</SelectItem>
                <SelectItem value="ap-southeast-1">ap-southeast-1</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="profile-preset">Rendition Preset</Label>
            <Select value={preset} onValueChange={setPreset}>
              <SelectTrigger id="profile-preset">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="480p_1mbps">480p @ 1 Mbps</SelectItem>
                <SelectItem value="720p_3mbps">720p @ 3 Mbps</SelectItem>
                <SelectItem value="1080p_6mbps">1080p @ 6 Mbps</SelectItem>
                <SelectItem value="4k_15mbps">4K @ 15 Mbps</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={() => createMut.mutate()} disabled={!name || createMut.isPending}>
            {createMut.isPending && <Loader2 className="h-4 w-4 mr-1 animate-spin" />}
            Create Profile
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
