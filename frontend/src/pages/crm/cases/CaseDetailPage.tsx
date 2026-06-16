import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft, LifeBuoy, Link2, UserPlus, X } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";
import { ApiError } from "@/api/client";
import {
  addCaseMessage,
  addCaseWatcher,
  assignCase,
  createCaseLink,
  deleteCaseLink,
  getCase,
  listCaseLinks,
  listCaseWatchers,
  removeCaseWatcher,
  setCaseContactAccount,
  setCasePriority,
  setCaseStatus,
  type CaseLinkType,
  type CasePriority,
  type CaseStatusWritable,
} from "@/api/endpoints/cases";

const STATUS_LABEL: Record<string, string> = {
  open: "Open",
  in_progress: "In Progress",
  waiting_on_user: "Waiting on User",
  done: "Closed",
  reopened: "Reopened",
};

const LINK_TYPE_LABEL: Record<CaseLinkType, string> = {
  duplicate: "Duplicate of",
  blocks: "Blocks",
  relates_to: "Relates to",
};

function priorityVariant(p?: string | null): "default" | "secondary" | "destructive" | "outline" {
  switch (p) {
    case "urgent":
      return "destructive";
    case "high":
      return "default";
    case "medium":
      return "secondary";
    default:
      return "outline";
  }
}

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export default function CaseDetailPage() {
  const { caseId = "" } = useParams<{ caseId: string }>();
  const token = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";
  const queryClient = useQueryClient();

  const [reply, setReply] = useState("");
  const [assignTarget, setAssignTarget] = useState("");
  const [contactId, setContactId] = useState("");
  const [accountId, setAccountId] = useState("");
  const [watcherSub, setWatcherSub] = useState("");
  const [linkTarget, setLinkTarget] = useState("");
  const [linkType, setLinkType] = useState<CaseLinkType>("relates_to");

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["crm-case", caseId] });

  const caseQuery = useQuery({
    queryKey: ["crm-case", caseId, "detail"],
    queryFn: () => getCase(caseId),
    enabled: !!caseId,
    retry: false,
  });

  const c = caseQuery.data?.ticket;

  const watchersQuery = useQuery({
    queryKey: ["crm-case", caseId, "watchers"],
    queryFn: () => listCaseWatchers(caseId),
    enabled: !!caseId,
    retry: false,
  });

  const linksQuery = useQuery({
    queryKey: ["crm-case", caseId, "links"],
    queryFn: () => listCaseLinks(caseId),
    enabled: !!caseId,
    retry: false,
  });

  const onMutError = (fallback: string) => (err: unknown) =>
    toast.error(err instanceof ApiError ? err.detail : fallback);

  const replyMut = useMutation({
    mutationFn: () => addCaseMessage(caseId, reply.trim()),
    onSuccess: () => {
      toast.success("Reply added");
      setReply("");
      invalidate();
    },
    onError: onMutError("Failed to add reply"),
  });

  const statusMut = useMutation({
    mutationFn: (status: CaseStatusWritable) => setCaseStatus(caseId, status),
    onSuccess: () => {
      toast.success("Status updated");
      invalidate();
    },
    onError: onMutError("Failed to update status"),
  });

  const priorityMut = useMutation({
    mutationFn: (priority: CasePriority) => setCasePriority(caseId, priority),
    onSuccess: () => {
      toast.success("Priority updated");
      invalidate();
    },
    onError: onMutError("Failed to update priority"),
  });

  const assignMut = useMutation({
    mutationFn: () => assignCase(caseId, assignTarget.trim()),
    onSuccess: () => {
      toast.success("Case assigned");
      setAssignTarget("");
      invalidate();
    },
    onError: onMutError("Failed to assign case"),
  });

  const contactMut = useMutation({
    mutationFn: () =>
      setCaseContactAccount(caseId, {
        contact_id: contactId.trim() || null,
        account_id: accountId.trim() || null,
      }),
    onSuccess: () => {
      toast.success("Contact / account linked");
      invalidate();
    },
    onError: onMutError("Failed to link contact / account"),
  });

  const addWatcherMut = useMutation({
    mutationFn: () => addCaseWatcher(caseId, watcherSub.trim()),
    onSuccess: () => {
      toast.success("Watcher added");
      setWatcherSub("");
      queryClient.invalidateQueries({ queryKey: ["crm-case", caseId, "watchers"] });
    },
    onError: onMutError("Failed to add watcher"),
  });

  const removeWatcherMut = useMutation({
    mutationFn: (sub: string) => removeCaseWatcher(caseId, sub),
    onSuccess: () => {
      toast.success("Watcher removed");
      queryClient.invalidateQueries({ queryKey: ["crm-case", caseId, "watchers"] });
    },
    onError: onMutError("Failed to remove watcher"),
  });

  const addLinkMut = useMutation({
    mutationFn: () =>
      createCaseLink(caseId, { related_ticket_id: linkTarget.trim(), link_type: linkType }),
    onSuccess: () => {
      toast.success("Case linked");
      setLinkTarget("");
      queryClient.invalidateQueries({ queryKey: ["crm-case", caseId, "links"] });
    },
    onError: onMutError("Failed to link case"),
  });

  const removeLinkMut = useMutation({
    mutationFn: (relatedId: string) => deleteCaseLink(caseId, relatedId),
    onSuccess: () => {
      toast.success("Link removed");
      queryClient.invalidateQueries({ queryKey: ["crm-case", caseId, "links"] });
    },
    onError: onMutError("Failed to remove link"),
  });

  const error = caseQuery.error;
  const notEnabledOrMissing = error instanceof ApiError && (error.status === 404 || error.status === 503);

  if (caseQuery.isLoading) {
    return <p className="py-8 text-center text-sm text-muted-foreground">Loading case…</p>;
  }

  if (notEnabledOrMissing || !c) {
    return (
      <div className="space-y-6">
        <PageHeader title="Case" />
        <Card>
          <CardContent className="flex flex-col items-center gap-2 py-12 text-center">
            <LifeBuoy className="h-10 w-10 text-muted-foreground" />
            <p className="font-medium">Case not available</p>
            <p className="max-w-md text-sm text-muted-foreground">
              {error instanceof ApiError && error.status === 403
                ? "You are not authorized to view this case."
                : "This case does not exist or the Cases module is disabled."}
            </p>
            <Button variant="outline" asChild>
              <Link to="/crm/cases">
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back to cases
              </Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const watchers = watchersQuery.data?.watchers ?? [];
  const links = linksQuery.data?.links ?? [];
  const casFeatureDisabled =
    watchersQuery.error instanceof ApiError && watchersQuery.error.status === 404;

  return (
    <div className="space-y-6">
      <PageHeader
        title={c.case_number ? `Case ${c.case_number}` : "Case"}
        description={c.subject}
        actions={
          <Button variant="outline" size="sm" asChild>
            <Link to="/crm/cases">
              <ArrowLeft className="mr-2 h-4 w-4" />
              All cases
            </Link>
          </Button>
        }
      />

      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="secondary">{STATUS_LABEL[c.status] ?? c.status}</Badge>
        {c.priority && (
          <Badge variant={priorityVariant(c.priority)} className="capitalize">
            {c.priority} priority
          </Badge>
        )}
        <span className="text-sm text-muted-foreground">Owner: {c.owner_sub}</span>
        <span className="text-sm text-muted-foreground">· Opened {fmt(c.created_at)}</span>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* ─── Conversation ─── */}
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Conversation</CardTitle>
              <CardDescription>Messages and activity on this case.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {c.messages.length === 0 ? (
                <p className="text-sm text-muted-foreground">No messages yet.</p>
              ) : (
                <ul className="space-y-3">
                  {c.messages.map((m) => (
                    <li key={m.message_id} className="rounded-md border p-3">
                      <div className="mb-1 flex items-center justify-between gap-2">
                        <span className="text-sm font-medium">{m.sender_sub}</span>
                        <span className="text-xs text-muted-foreground">
                          {m.sender_role} · {fmt(m.created_at)}
                        </span>
                      </div>
                      <p className="whitespace-pre-wrap text-sm">{m.body}</p>
                    </li>
                  ))}
                </ul>
              )}
              <Separator />
              <div className="space-y-2">
                <Label htmlFor="case-reply">Add a reply</Label>
                <Textarea
                  id="case-reply"
                  value={reply}
                  onChange={(e) => setReply(e.target.value)}
                  rows={3}
                  placeholder="Type your reply…"
                  maxLength={4000}
                />
                <Button
                  size="sm"
                  onClick={() => replyMut.mutate()}
                  disabled={replyMut.isPending || reply.trim().length === 0}
                >
                  Send reply
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* ─── Side panel ─── */}
        <div className="space-y-4">
          {/* Status / priority */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Case fields</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {isAdmin ? (
                <>
                  <div className="space-y-2">
                    <Label>Status</Label>
                    <Select
                      value={c.status}
                      onValueChange={(v) => statusMut.mutate(v as CaseStatusWritable)}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="open">Open</SelectItem>
                        <SelectItem value="in_progress">In Progress</SelectItem>
                        <SelectItem value="waiting_on_user">Waiting on User</SelectItem>
                        <SelectItem value="done">Closed</SelectItem>
                        <SelectItem value="reopened">Reopened</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Priority</Label>
                    <Select
                      value={(c.priority as string) || "medium"}
                      onValueChange={(v) => priorityMut.mutate(v as CasePriority)}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="urgent">Urgent</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="low">Low</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </>
              ) : (
                <div className="space-y-1 text-sm">
                  <p>
                    <span className="text-muted-foreground">Status: </span>
                    {STATUS_LABEL[c.status] ?? c.status}
                  </p>
                  <p>
                    <span className="text-muted-foreground">Priority: </span>
                    <span className="capitalize">{c.priority ?? "—"}</span>
                  </p>
                </div>
              )}
              <div className="space-y-1 text-sm">
                <p>
                  <span className="text-muted-foreground">Assignee: </span>
                  {c.assigned_admin_sub ?? c.assigned_to_sub ?? "Unassigned"}
                </p>
                <p>
                  <span className="text-muted-foreground">Contact: </span>
                  {c.contact_id ?? "—"}
                </p>
                <p>
                  <span className="text-muted-foreground">Account: </span>
                  {c.account_id ?? "—"}
                </p>
                <p>
                  <span className="text-muted-foreground">Updated: </span>
                  {fmt(c.updated_at)}
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Admin-only: assignment + contact/account + watchers + links */}
          {isAdmin && !casFeatureDisabled && (
            <>
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Assign case</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <Input
                    value={assignTarget}
                    onChange={(e) => setAssignTarget(e.target.value)}
                    placeholder="Admin user sub"
                  />
                  <Button
                    size="sm"
                    className="w-full"
                    onClick={() => assignMut.mutate()}
                    disabled={assignMut.isPending || assignTarget.trim().length === 0}
                  >
                    Assign
                  </Button>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Link contact / account</CardTitle>
                  <CardDescription>Soft references for CRM rollups.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  <Input
                    value={contactId}
                    onChange={(e) => setContactId(e.target.value)}
                    placeholder={c.contact_id ?? "Contact ID"}
                  />
                  <Input
                    value={accountId}
                    onChange={(e) => setAccountId(e.target.value)}
                    placeholder={c.account_id ?? "Account ID"}
                  />
                  <Button
                    size="sm"
                    className="w-full"
                    onClick={() => contactMut.mutate()}
                    disabled={contactMut.isPending}
                  >
                    Save links
                  </Button>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Watchers</CardTitle>
                  <CardDescription>CC list notified on case activity.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  {watchers.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No watchers.</p>
                  ) : (
                    <ul className="space-y-1">
                      {watchers.map((w) => (
                        <li
                          key={w.watcher_sub}
                          className="flex items-center justify-between gap-2 text-sm"
                        >
                          <span className="truncate">{w.watcher_sub}</span>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-6 w-6"
                            onClick={() => removeWatcherMut.mutate(w.watcher_sub)}
                          >
                            <X className="h-3.5 w-3.5" />
                          </Button>
                        </li>
                      ))}
                    </ul>
                  )}
                  <div className="flex gap-2">
                    <Input
                      value={watcherSub}
                      onChange={(e) => setWatcherSub(e.target.value)}
                      placeholder="Watcher user sub"
                    />
                    <Button
                      size="icon"
                      onClick={() => addWatcherMut.mutate()}
                      disabled={addWatcherMut.isPending || watcherSub.trim().length === 0}
                    >
                      <UserPlus className="h-4 w-4" />
                    </Button>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Related cases</CardTitle>
                  <CardDescription>Case-to-case relationships.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  {links.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No linked cases.</p>
                  ) : (
                    <ul className="space-y-1">
                      {links.map((l) => (
                        <li
                          key={`${l.link_type}:${l.related_ticket_id}`}
                          className="flex items-center justify-between gap-2 text-sm"
                        >
                          <span className="flex items-center gap-1 truncate">
                            <Link2 className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                            <span className="text-muted-foreground">
                              {LINK_TYPE_LABEL[l.link_type]}
                            </span>
                            <Link
                              to={`/crm/cases/${l.related_ticket_id}`}
                              className="font-mono text-xs text-primary hover:underline"
                            >
                              {l.related_ticket_id.slice(0, 8)}
                            </Link>
                          </span>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-6 w-6"
                            onClick={() => removeLinkMut.mutate(l.related_ticket_id)}
                          >
                            <X className="h-3.5 w-3.5" />
                          </Button>
                        </li>
                      ))}
                    </ul>
                  )}
                  <div className="space-y-2">
                    <Select value={linkType} onValueChange={(v) => setLinkType(v as CaseLinkType)}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="relates_to">Relates to</SelectItem>
                        <SelectItem value="blocks">Blocks</SelectItem>
                        <SelectItem value="duplicate">Duplicate of</SelectItem>
                      </SelectContent>
                    </Select>
                    <div className="flex gap-2">
                      <Input
                        value={linkTarget}
                        onChange={(e) => setLinkTarget(e.target.value)}
                        placeholder="Related case ticket_id"
                      />
                      <Button
                        size="icon"
                        onClick={() => addLinkMut.mutate()}
                        disabled={addLinkMut.isPending || linkTarget.trim().length === 0}
                      >
                        <Link2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
