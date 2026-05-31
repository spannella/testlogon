import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listAccountDeletions,
  requestAccountDeletion,
  cancelAccountDeletion,
  requestPrivacyExport,
} from "@/api/endpoints/accountDeletion";
import type { AccountDeletionStatus, PrivacyExportStatus } from "@/api/types";
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
import { AlertTriangle, Download, ShieldAlert, Clock, Loader2 } from "lucide-react";
import { toast } from "sonner";

const CONFIRM_TEXT = "DELETE MY ACCOUNT";

const EXPORT_CATEGORIES: { key: string; label: string }[] = [
  { key: "profile", label: "Profile" },
  { key: "messages", label: "Messages" },
  { key: "posts", label: "Posts" },
  { key: "billing", label: "Billing" },
  { key: "files", label: "Files" },
  { key: "contacts", label: "Contacts" },
  { key: "calendar", label: "Calendar" },
  { key: "subscriptions", label: "Subscriptions" },
  { key: "push_devices", label: "Push Devices" },
  { key: "tickets", label: "Tickets" },
  { key: "sessions", label: "Sessions" },
];

const QKEY = ["account-deletion", "requests"] as const;

function statusVariant(s: string): "default" | "secondary" | "destructive" | "outline" {
  if (s === "pending") return "default";
  if (s === "completed") return "secondary";
  if (s === "cancelled") return "outline";
  return "destructive";
}

export default function AccountDeletionPage() {
  const qc = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [confirmText, setConfirmText] = useState("");
  const [reason, setReason] = useState("");
  const [lastExport, setLastExport] = useState<PrivacyExportStatus | null>(null);
  const [categories, setCategories] = useState<Record<string, boolean>>(
    Object.fromEntries(EXPORT_CATEGORIES.map((c) => [c.key, true])),
  );

  const { data, isLoading } = useQuery({
    queryKey: QKEY,
    queryFn: () => listAccountDeletions(),
  });

  const requests = data?.requests ?? [];
  const activeRequest = useMemo(
    () => requests.find((r) => r.status === "pending"),
    [requests],
  );

  const deleteMut = useMutation({
    mutationFn: () =>
      requestAccountDeletion({ password, confirm_text: confirmText, reason: reason || undefined }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QKEY });
      toast.success("Deletion scheduled. You can cancel during the grace period.");
      setDialogOpen(false);
      setPassword("");
      setConfirmText("");
      setReason("");
    },
    onError: () => toast.error("Could not schedule deletion. Check your password."),
  });

  const cancelMut = useMutation({
    mutationFn: (id: string) => cancelAccountDeletion(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QKEY });
      toast.success("Deletion cancelled.");
    },
    onError: () => toast.error("Could not cancel deletion."),
  });

  const exportMut = useMutation({
    mutationFn: () => requestPrivacyExport({ categories }),
    onSuccess: (res) => {
      setLastExport(res);
      toast.success("Data export ready.");
    },
    onError: () => toast.error("Export request failed (you may be rate-limited)."),
  });

  const isValid = password.length > 0 && confirmText === CONFIRM_TEXT;

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-4" data-testid="account-deletion-page">
      <div>
        <h1 className="text-2xl font-semibold">Privacy &amp; Account Deletion</h1>
        <p className="text-muted-foreground">
          Export a copy of your data or permanently delete your account.
        </p>
      </div>

      {/* Data export */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" /> Data Export
          </CardTitle>
          <CardDescription>
            Download a copy of your data. Select the categories to include.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {EXPORT_CATEGORIES.map((c) => (
              <label key={c.key} className="flex items-center gap-2 text-sm">
                <Checkbox
                  data-testid={`export-cat-${c.key}`}
                  checked={!!categories[c.key]}
                  onCheckedChange={(v) =>
                    setCategories((prev) => ({ ...prev, [c.key]: !!v }))
                  }
                />
                {c.label}
              </label>
            ))}
          </div>
          <Button
            data-testid="request-export-btn"
            onClick={() => exportMut.mutate()}
            disabled={exportMut.isPending}
          >
            {exportMut.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Request Export
          </Button>
          {lastExport && (
            <div data-testid="export-result" className="text-sm">
              Export <Badge variant="secondary">{lastExport.status}</Badge> —{" "}
              <a
                data-testid="export-download-link"
                className="text-primary underline"
                href={lastExport.download_url ?? "#"}
              >
                Download ({lastExport.categories_requested} categories)
              </a>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Active deletion banner */}
      {activeRequest && (
        <Card className="border-destructive" data-testid="active-deletion-banner">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-destructive">
              <Clock className="h-5 w-5" /> Account scheduled for deletion
            </CardTitle>
            <CardDescription>
              {activeRequest.scheduled_for
                ? `Scheduled for ${new Date(activeRequest.scheduled_for * 1000).toLocaleDateString()}`
                : "Scheduled"}{" "}
              —{" "}
              <span data-testid="grace-days-remaining">
                {activeRequest.grace_days_remaining ?? 0} days remaining
              </span>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button
              variant="destructive"
              data-testid="cancel-deletion-btn"
              disabled={!activeRequest.can_cancel || cancelMut.isPending}
              onClick={() => cancelMut.mutate(activeRequest.request_id)}
            >
              Cancel Deletion
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Delete account */}
      <Card className="border-destructive/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive">
            <ShieldAlert className="h-5 w-5" /> Delete Account
          </CardTitle>
          <CardDescription>
            This schedules permanent deletion after a grace period. You can cancel before it runs.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <ul className="list-disc pl-5 text-sm text-muted-foreground">
            <li>Your profile will be permanently deleted</li>
            <li>Your messages and posts will be anonymized</li>
            <li>Your files will be permanently deleted</li>
            <li>Active subscriptions will be cancelled</li>
            <li>Wallet balance will be refunded</li>
          </ul>
          <Button
            variant="destructive"
            data-testid="open-delete-dialog-btn"
            disabled={!!activeRequest}
            onClick={() => setDialogOpen(true)}
          >
            <AlertTriangle className="mr-2 h-4 w-4" /> Delete My Account
          </Button>
        </CardContent>
      </Card>

      {/* Request history */}
      <Card>
        <CardHeader>
          <CardTitle>Deletion Requests</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : requests.length === 0 ? (
            <p className="text-sm text-muted-foreground">No deletion requests.</p>
          ) : (
            <ul className="space-y-2" data-testid="request-history">
              {requests.map((r: AccountDeletionStatus) => (
                <li
                  key={r.request_id}
                  className="flex items-center justify-between rounded border p-2 text-sm"
                >
                  <span>{new Date(r.created_at * 1000).toLocaleString()}</span>
                  <Badge variant={statusVariant(r.status)}>{r.status}</Badge>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      {/* Delete dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent data-testid="delete-account-dialog">
          <DialogHeader>
            <DialogTitle>Delete Your Account</DialogTitle>
            <DialogDescription>
              Re-enter your password and type the confirmation phrase to schedule deletion.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1">
              <Label htmlFor="del-password">Enter your password</Label>
              <Input
                id="del-password"
                data-testid="delete-password-input"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="del-confirm">Type "{CONFIRM_TEXT}" to confirm</Label>
              <Input
                id="del-confirm"
                data-testid="delete-confirm-input"
                value={confirmText}
                onChange={(e) => setConfirmText(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="del-reason">Why are you leaving? (optional)</Label>
              <Textarea
                id="del-reason"
                data-testid="delete-reason-input"
                maxLength={500}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </div>
            <p className="text-sm text-muted-foreground">
              You will have a grace period to cancel before deletion runs.
            </p>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              data-testid="confirm-delete-btn"
              disabled={!isValid || deleteMut.isPending}
              onClick={() => deleteMut.mutate()}
            >
              {deleteMut.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete My Account
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
