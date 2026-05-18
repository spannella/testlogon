import * as React from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  getTicketJiraSyncStatus,
  linkExistingJiraIssueToTicket,
  resolveJiraConflict,
  unlinkJiraIssueFromTicket,
} from "@/api/endpoints/jira";

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export function JiraLinkedPanel({ ticketId, currentTicket }: { ticketId: string; currentTicket: Record<string, unknown> }) {
  const [workspaceId, setWorkspaceId] = React.useState("");
  const [issueKey, setIssueKey] = React.useState("");
  const [confirmOpen, setConfirmOpen] = React.useState(false);
  const [resolveOpen, setResolveOpen] = React.useState(false);
  const [validationError, setValidationError] = React.useState<string | null>(null);

  const syncQuery = useQuery({
    queryKey: ["ticket-jira-sync", ticketId],
    queryFn: () => getTicketJiraSyncStatus(ticketId),
    enabled: !!ticketId,
  });

  const linkMutation = useMutation({
    mutationFn: () => linkExistingJiraIssueToTicket({ ticketId, workspaceId, externalIssueKey: issueKey }),
    onSuccess: () => {
      toast.success("Jira issue linked");
      setIssueKey("");
      setValidationError(null);
      void syncQuery.refetch();
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : "Unable to link Jira issue");
    },
  });

  const unlinkMutation = useMutation({
    mutationFn: (linkId: string) => unlinkJiraIssueFromTicket(ticketId, linkId),
    onSuccess: () => {
      toast.success("Jira issue unlinked");
      setConfirmOpen(false);
      void syncQuery.refetch();
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : "Unable to unlink Jira issue");
    },
  });

  const resolveMutation = useMutation({
    mutationFn: (action: "keep_internal" | "keep_jira") => {
      if (!syncQuery.data?.link_id) throw new Error("No active Jira link");
      return resolveJiraConflict({
        ticketId,
        linkId: syncQuery.data.link_id,
        workspaceId,
        action,
        currentTicket,
      });
    },
    onSuccess: () => {
      toast.success("Conflict resolved");
      setResolveOpen(false);
      void syncQuery.refetch();
    },
    onError: (err: unknown) => {
      toast.error(err instanceof Error ? err.message : "Unable to resolve conflict");
    },
  });

  const status = syncQuery.data;
  const isLinked = !!status?.linked && !!status?.link_id;

  function onLink() {
    if (!workspaceId.trim()) {
      setValidationError("Workspace ID is required to link a Jira issue.");
      return;
    }
    if (!issueKey.trim()) {
      setValidationError("Jira issue key is required.");
      return;
    }
    setValidationError(null);
    linkMutation.mutate();
  }

  function onOpenResolve() {
    if (!workspaceId.trim()) {
      setValidationError("Workspace ID is required to resolve conflicts.");
      return;
    }
    if (!status?.link_id) {
      setValidationError("No active Jira link available for conflict resolution.");
      return;
    }
    setValidationError(null);
    setResolveOpen(true);
  }

  return (
    <div className="space-y-3 rounded-md border p-3">
      <div>
        <h4 className="text-sm font-semibold">Linked Jira Issue</h4>
        <p className="text-xs text-muted-foreground">View sync status and manage Jira linkage for this ticket.</p>
      </div>

      {syncQuery.isError && <p className="text-sm text-destructive">Failed to load Jira sync status.</p>}
      {status?.linked ? (
        <div className="space-y-1 text-sm">
          <div><span className="font-medium">Jira key:</span> {status.external_issue_key || "—"}</div>
          <div><span className="font-medium">Jira status:</span> {status.jira_status || "—"}</div>
          <div><span className="font-medium">Sync state:</span> {status.sync_state}</div>
          <div><span className="font-medium">Last synced:</span> {fmt(status.last_synced_at)}</div>
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">No Jira issue linked.</p>
      )}

      <div className="grid gap-2">
        <Label htmlFor="jira-workspace-link">Workspace ID</Label>
        <Input
          id="jira-workspace-link"
          placeholder="ws_123"
          value={workspaceId}
          onChange={(e) => setWorkspaceId(e.target.value)}
        />
        <Label htmlFor="jira-issue-key-link">Jira issue key</Label>
        <Input
          id="jira-issue-key-link"
          placeholder="PROJ-123"
          value={issueKey}
          onChange={(e) => setIssueKey(e.target.value)}
        />
        {validationError && <p className="text-sm text-destructive">{validationError}</p>}
      </div>

      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="outline" onClick={onLink} disabled={linkMutation.isPending}>
          {linkMutation.isPending ? "Linking..." : "Link Jira Issue"}
        </Button>
        <Button
          size="sm"
          variant="destructive"
          onClick={() => setConfirmOpen(true)}
          disabled={!isLinked || unlinkMutation.isPending}
        >
          Unlink
        </Button>
        <Button size="sm" variant="ghost" onClick={() => void syncQuery.refetch()} disabled={syncQuery.isFetching}>
          Refresh sync status
        </Button>
        <Button
          size="sm"
          variant="secondary"
          onClick={onOpenResolve}
          disabled={status?.sync_state !== "conflict"}
        >
          Resolve conflict
        </Button>
      </div>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title="Unlink Jira issue"
        description="This will disconnect the linked Jira issue from this ticket."
        confirmLabel="Unlink"
        variant="danger"
        loading={unlinkMutation.isPending}
        onConfirm={() => {
          if (!status?.link_id) return;
          unlinkMutation.mutate(status.link_id);
        }}
      />

      <Dialog open={resolveOpen} onOpenChange={setResolveOpen}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Resolve Jira Sync Conflict</DialogTitle>
            <DialogDescription>
              Compare internal and Jira values, then choose which side should win.
            </DialogDescription>
          </DialogHeader>

          <div className="max-h-80 overflow-auto rounded-md border">
            <table className="w-full text-sm">
              <thead className="bg-muted/50">
                <tr>
                  <th className="p-2 text-left">Field</th>
                  <th className="p-2 text-left">Internal value</th>
                  <th className="p-2 text-left">Jira value</th>
                </tr>
              </thead>
              <tbody>
                {(status?.conflict_fields ?? []).map((field) => (
                  <tr key={field} className="border-t">
                    <td className="p-2 font-medium">{field}</td>
                    <td className="p-2">{String(status?.conflict_local_values?.[field] ?? "—")}</td>
                    <td className="p-2">{String(status?.conflict_remote_values?.[field] ?? "—")}</td>
                  </tr>
                ))}
                {!(status?.conflict_fields?.length) && (
                  <tr>
                    <td className="p-2 text-muted-foreground" colSpan={3}>No conflict fields found.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setResolveOpen(false)} disabled={resolveMutation.isPending}>
              Cancel
            </Button>
            <Button
              variant="secondary"
              onClick={() => resolveMutation.mutate("keep_jira")}
              disabled={resolveMutation.isPending}
            >
              Keep Jira
            </Button>
            <Button
              onClick={() => resolveMutation.mutate("keep_internal")}
              disabled={resolveMutation.isPending}
            >
              Keep Internal
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
