import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getPrivacyRequests,
  requestExport,
  requestDeletion,
  cancelDeletion,
  getExportDownloadUrl,
} from "@/api/endpoints/privacy";
import type { DataRequest } from "@/api/types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Download, Trash2, ShieldAlert, Clock, CheckCircle2, Loader2 } from "lucide-react";
import { toast } from "sonner";

function statusBadge(status: string) {
  const map: Record<string, { variant: "default" | "secondary" | "destructive" | "outline"; label: string }> = {
    pending: { variant: "secondary", label: "Pending" },
    processing: { variant: "default", label: "Processing" },
    completed: { variant: "default", label: "Completed" },
    cancelled: { variant: "outline", label: "Cancelled" },
    failed: { variant: "destructive", label: "Failed" },
    rejected: { variant: "destructive", label: "Rejected" },
    held: { variant: "destructive", label: "On Hold" },
  };
  const cfg = map[status] ?? { variant: "outline" as const, label: status };
  return <Badge variant={cfg.variant}>{cfg.label}</Badge>;
}

function formatDate(ts?: number) {
  if (!ts) return "--";
  return new Date(ts * 1000).toLocaleString();
}

function formatSize(bytes?: number) {
  if (!bytes) return "--";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function GracePeriodCountdown({ endsAt }: { endsAt: number }) {
  const now = Math.floor(Date.now() / 1000);
  const remaining = endsAt - now;
  if (remaining <= 0) return <span className="text-destructive font-medium">Grace period expired</span>;
  const days = Math.floor(remaining / 86400);
  const hours = Math.floor((remaining % 86400) / 3600);
  return (
    <span className="flex items-center gap-1 text-amber-600">
      <Clock className="h-4 w-4" />
      {days}d {hours}h remaining
    </span>
  );
}

export default function PrivacyPage() {
  const queryClient = useQueryClient();
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [reason, setReason] = useState("");
  const [includeMessages, setIncludeMessages] = useState(true);
  const [includeFiles, setIncludeFiles] = useState(true);
  const [includeBilling, setIncludeBilling] = useState(true);
  const [includeProfile, setIncludeProfile] = useState(true);

  const { data, isLoading } = useQuery({
    queryKey: ["privacy", "requests"],
    queryFn: getPrivacyRequests,
    refetchInterval: 10_000,
  });

  const exportMut = useMutation({
    mutationFn: () =>
      requestExport({
        include_messages: includeMessages,
        include_files: includeFiles,
        include_billing: includeBilling,
        include_profile: includeProfile,
      }),
    onSuccess: () => {
      toast.success("Data export requested");
      queryClient.invalidateQueries({ queryKey: ["privacy", "requests"] });
    },
    onError: (err: any) => {
      const detail = err?.response?.data?.detail;
      if (err?.response?.status === 429) {
        toast.error("You can only request one export every 24 hours");
      } else {
        toast.error(detail || "Failed to request export");
      }
    },
  });

  const deleteMut = useMutation({
    mutationFn: () => requestDeletion({ password, reason: reason || undefined }),
    onSuccess: () => {
      toast.success("Account deletion requested");
      setDeleteDialogOpen(false);
      setPassword("");
      setReason("");
      queryClient.invalidateQueries({ queryKey: ["privacy", "requests"] });
    },
    onError: (err: any) => {
      const status = err?.response?.status;
      const detail = err?.response?.data?.detail;
      if (status === 401) {
        toast.error("Incorrect password");
      } else if (status === 409) {
        toast.error("You already have a pending deletion request");
      } else if (status === 403) {
        toast.error(detail || "Account deletion is not available");
      } else {
        toast.error(detail || "Failed to request deletion");
      }
    },
  });

  const cancelMut = useMutation({
    mutationFn: (requestId: string) => cancelDeletion(requestId),
    onSuccess: () => {
      toast.success("Deletion cancelled");
      queryClient.invalidateQueries({ queryKey: ["privacy", "requests"] });
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.detail || "Failed to cancel deletion");
    },
  });

  const requests = data?.requests ?? [];
  const pendingExport = requests.find(
    (r: DataRequest) => r.request_type === "export" && (r.status === "pending" || r.status === "processing"),
  );
  const completedExport = requests.find(
    (r: DataRequest) => r.request_type === "export" && r.status === "completed",
  );
  const activeDeletion = requests.find(
    (r: DataRequest) => r.request_type === "deletion" && r.status === "pending",
  );

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-4 md:p-8">
      <div>
        <h1 className="text-2xl font-bold">Privacy & Data</h1>
        <p className="text-muted-foreground">
          Manage your personal data. Download a copy or request account deletion.
        </p>
      </div>

      {/* ─── Export Section ───────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            Download Your Data
          </CardTitle>
          <CardDescription>
            Request a copy of all your personal data in machine-readable JSON format (ZIP archive).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {pendingExport && (
            <div className="flex items-center gap-2 rounded-md border bg-muted/40 p-3">
              <Loader2 className="h-4 w-4 animate-spin" />
              <span>Your export is being prepared...</span>
              {statusBadge(pendingExport.status)}
            </div>
          )}

          {completedExport && (
            <div className="flex items-center justify-between rounded-md border bg-green-50 p-3 dark:bg-green-950/30">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-green-600" />
                <span>Export ready ({formatSize(completedExport.export_size_bytes)})</span>
              </div>
              <a href={getExportDownloadUrl(completedExport.request_id)} target="_blank" rel="noopener noreferrer">
                <Button variant="outline" size="sm">
                  <Download className="mr-1 h-4 w-4" />
                  Download
                </Button>
              </a>
            </div>
          )}

          <div className="space-y-2">
            <p className="text-sm font-medium">Include in export:</p>
            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={includeProfile} onCheckedChange={(v) => setIncludeProfile(!!v)} />
                Profile & contacts
              </label>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={includeMessages} onCheckedChange={(v) => setIncludeMessages(!!v)} />
                Messages
              </label>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={includeFiles} onCheckedChange={(v) => setIncludeFiles(!!v)} />
                Files
              </label>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={includeBilling} onCheckedChange={(v) => setIncludeBilling(!!v)} />
                Billing & subscriptions
              </label>
            </div>
          </div>

          <Button
            onClick={() => exportMut.mutate()}
            disabled={exportMut.isPending || !!pendingExport}
          >
            {exportMut.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Requesting...
              </>
            ) : (
              "Request Export"
            )}
          </Button>
        </CardContent>
      </Card>

      {/* ─── Deletion Section ────────────────────────────────── */}
      <Card className="border-destructive/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive">
            <Trash2 className="h-5 w-5" />
            Delete Account
          </CardTitle>
          <CardDescription>
            Permanently delete your account and all associated data. A 14-day grace period allows you to cancel.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {activeDeletion && (
            <div className="space-y-3 rounded-md border border-destructive/30 bg-destructive/5 p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-5 w-5 text-destructive" />
                  <span className="font-medium">Account deletion scheduled</span>
                </div>
                {statusBadge(activeDeletion.status)}
              </div>
              {activeDeletion.grace_period_ends_at && (
                <GracePeriodCountdown endsAt={activeDeletion.grace_period_ends_at} />
              )}
              <Button
                variant="outline"
                size="sm"
                onClick={() => cancelMut.mutate(activeDeletion.request_id)}
                disabled={cancelMut.isPending}
              >
                {cancelMut.isPending ? "Cancelling..." : "Cancel Deletion"}
              </Button>
            </div>
          )}

          {!activeDeletion && (
            <Button variant="destructive" onClick={() => setDeleteDialogOpen(true)}>
              Delete My Account
            </Button>
          )}
        </CardContent>
      </Card>

      {/* ─── Request History ─────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle>Request History</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : requests.length === 0 ? (
            <p className="py-4 text-center text-muted-foreground">No privacy requests yet.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left">
                    <th className="pb-2 pr-4 font-medium">Type</th>
                    <th className="pb-2 pr-4 font-medium">Status</th>
                    <th className="pb-2 pr-4 font-medium">Requested</th>
                    <th className="pb-2 font-medium">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {requests.map((r: DataRequest) => (
                    <tr key={r.request_id} className="border-b last:border-0">
                      <td className="py-2 pr-4 capitalize">{r.request_type}</td>
                      <td className="py-2 pr-4">{statusBadge(r.status)}</td>
                      <td className="py-2 pr-4 text-muted-foreground">{formatDate(r.created_at)}</td>
                      <td className="py-2">
                        {r.request_type === "export" && r.status === "completed" && (
                          <a
                            href={getExportDownloadUrl(r.request_id)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-primary hover:underline"
                          >
                            Download ({formatSize(r.export_size_bytes)})
                          </a>
                        )}
                        {r.request_type === "deletion" && r.grace_period_ends_at && r.status === "pending" && (
                          <GracePeriodCountdown endsAt={r.grace_period_ends_at} />
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ─── Delete Account Dialog ───────────────────────────── */}
      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="text-destructive">Delete Account</DialogTitle>
            <DialogDescription>
              This will permanently delete your account after a 14-day grace period. All your data
              will be removed, except anonymized billing records required for regulatory compliance.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="rounded-md bg-destructive/10 p-3 text-sm">
              <p className="font-medium">What will be deleted:</p>
              <ul className="mt-1 list-inside list-disc text-muted-foreground">
                <li>Profile, contacts, and preferences</li>
                <li>Messages and conversations</li>
                <li>Files and uploads</li>
                <li>Calendar events and subscriptions</li>
                <li>Sessions and security credentials</li>
              </ul>
            </div>
            <div>
              <Label htmlFor="delete-password">Confirm your password</Label>
              <Input
                id="delete-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
              />
            </div>
            <div>
              <Label htmlFor="delete-reason">Reason (optional)</Label>
              <Textarea
                id="delete-reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Why are you leaving?"
                rows={2}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => deleteMut.mutate()}
              disabled={!password || deleteMut.isPending}
            >
              {deleteMut.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Submitting...
                </>
              ) : (
                "I understand, delete my account"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
