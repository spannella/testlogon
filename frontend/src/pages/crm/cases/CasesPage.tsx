import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { LifeBuoy, Plus, RefreshCw } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
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
import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";
import { ApiError } from "@/api/client";
import {
  createCase,
  getCaseSummary,
  listCases,
  type CaseListItem,
  type CasePriority,
  type CaseStatus,
} from "@/api/endpoints/cases";

const POLL_MS = 20000;

const STATUS_LABEL: Record<string, string> = {
  open: "Open",
  in_progress: "In Progress",
  waiting_on_user: "Waiting on User",
  done: "Closed",
  reopened: "Reopened",
};

function priorityVariant(p?: string | null): "default" | "secondary" | "destructive" | "outline" {
  switch (p) {
    case "urgent":
      return "destructive";
    case "high":
      return "default";
    case "medium":
      return "secondary";
    case "low":
      return "outline";
    default:
      return "outline";
  }
}

function statusVariant(s: string): "default" | "secondary" | "destructive" | "outline" {
  switch (s) {
    case "open":
      return "default";
    case "in_progress":
      return "secondary";
    case "waiting_on_user":
      return "outline";
    case "done":
      return "secondary";
    default:
      return "outline";
  }
}

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export default function CasesPage() {
  const token = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";
  const queryClient = useQueryClient();

  const [statusFilter, setStatusFilter] = useState<"" | CaseStatus>("");
  const [priorityFilter, setPriorityFilter] = useState<"" | CasePriority>("");
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const cursor = cursorStack[cursorStack.length - 1];

  const [showCreate, setShowCreate] = useState(false);
  const [subject, setSubject] = useState("");
  const [description, setDescription] = useState("");
  const [newPriority, setNewPriority] = useState<CasePriority>("medium");
  const [contactId, setContactId] = useState("");
  const [accountId, setAccountId] = useState("");

  const listQuery = useQuery({
    queryKey: ["crm-cases", "list", { statusFilter, priorityFilter, cursor, isAdmin }],
    queryFn: () =>
      listCases({
        limit: 25,
        cursor,
        status: statusFilter || undefined,
        priority: isAdmin && priorityFilter ? priorityFilter : undefined,
      }),
    refetchInterval: POLL_MS,
    retry: false,
  });

  const summaryQuery = useQuery({
    queryKey: ["crm-cases", "summary"],
    queryFn: () => getCaseSummary(),
    enabled: isAdmin,
    retry: false,
  });

  const createMut = useMutation({
    mutationFn: () =>
      createCase({
        subject: subject.trim(),
        description: description.trim(),
        priority: newPriority,
        contact_id: contactId.trim() || undefined,
        account_id: accountId.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success("Case opened");
      setSubject("");
      setDescription("");
      setContactId("");
      setAccountId("");
      setNewPriority("medium");
      setShowCreate(false);
      setCursorStack([]);
      queryClient.invalidateQueries({ queryKey: ["crm-cases"] });
    },
    onError: (err) => {
      toast.error(err instanceof ApiError ? err.detail : "Failed to open case");
    },
  });

  const cases: CaseListItem[] = listQuery.data?.items ?? [];
  const nextCursor = listQuery.data?.next_cursor ?? null;

  const summary = summaryQuery.data?.summary;
  const summaryCards = useMemo(() => {
    if (!summary) return [];
    return [
      { label: "Total cases", value: summary.total_count },
      { label: "Open", value: summary.by_status?.open ?? 0 },
      { label: "Unassigned", value: summary.unassigned_count },
      { label: "Stale", value: summary.stale_count },
    ];
  }, [summary]);

  const error = listQuery.error;
  const notEnabled = error instanceof ApiError && (error.status === 404 || error.status === 503);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cases"
        description="SuiteCRM customer cases — case number, priority, status and contact/account links."
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => listQuery.refetch()}
              disabled={listQuery.isFetching}
            >
              <RefreshCw className={`mr-2 h-4 w-4 ${listQuery.isFetching ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setShowCreate((v) => !v)}>
              <Plus className="mr-2 h-4 w-4" />
              New Case
            </Button>
          </div>
        }
      />

      {isAdmin && summaryCards.length > 0 && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {summaryCards.map((c) => (
            <Card key={c.label}>
              <CardHeader className="pb-2">
                <CardDescription>{c.label}</CardDescription>
                <CardTitle className="text-2xl">{c.value}</CardTitle>
              </CardHeader>
            </Card>
          ))}
        </div>
      )}

      {showCreate && (
        <Card>
          <CardHeader>
            <CardTitle>Open a new case</CardTitle>
            <CardDescription>
              Cases extend the support ticket system with a case number and priority.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="case-subject">Subject</Label>
              <Input
                id="case-subject"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="Brief summary of the issue"
                maxLength={160}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="case-description">Description</Label>
              <Textarea
                id="case-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Describe the problem in detail"
                rows={4}
                maxLength={4000}
              />
            </div>
            <div className="grid gap-4 sm:grid-cols-3">
              <div className="space-y-2">
                <Label>Priority</Label>
                <Select value={newPriority} onValueChange={(v) => setNewPriority(v as CasePriority)}>
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
              <div className="space-y-2">
                <Label htmlFor="case-contact">Contact ID (optional)</Label>
                <Input
                  id="case-contact"
                  value={contactId}
                  onChange={(e) => setContactId(e.target.value)}
                  placeholder="contact_…"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="case-account">Account ID (optional)</Label>
                <Input
                  id="case-account"
                  value={accountId}
                  onChange={(e) => setAccountId(e.target.value)}
                  placeholder="account_…"
                />
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button
                onClick={() => createMut.mutate()}
                disabled={
                  createMut.isPending || subject.trim().length < 3 || description.trim().length < 1
                }
              >
                Open case
              </Button>
              <Button variant="ghost" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle>Case queue</CardTitle>
            <CardDescription>All cases visible to you, newest first.</CardDescription>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Select
              value={statusFilter || "all"}
              onValueChange={(v) => {
                setStatusFilter(v === "all" ? "" : (v as CaseStatus));
                setCursorStack([]);
              }}
            >
              <SelectTrigger className="w-[170px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                <SelectItem value="open">Open</SelectItem>
                <SelectItem value="in_progress">In Progress</SelectItem>
                <SelectItem value="waiting_on_user">Waiting on User</SelectItem>
                <SelectItem value="done">Closed</SelectItem>
              </SelectContent>
            </Select>
            {isAdmin && (
              <Select
                value={priorityFilter || "all"}
                onValueChange={(v) => {
                  setPriorityFilter(v === "all" ? "" : (v as CasePriority));
                  setCursorStack([]);
                }}
              >
                <SelectTrigger className="w-[150px]">
                  <SelectValue placeholder="Priority" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All priorities</SelectItem>
                  <SelectItem value="urgent">Urgent</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {notEnabled ? (
            <div className="flex flex-col items-center gap-2 py-12 text-center">
              <LifeBuoy className="h-10 w-10 text-muted-foreground" />
              <p className="font-medium">Cases are not enabled</p>
              <p className="max-w-md text-sm text-muted-foreground">
                The SuiteCRM Cases module is currently disabled on this platform. Ask an
                administrator to enable the cases feature flag.
              </p>
            </div>
          ) : listQuery.isLoading ? (
            <p className="py-8 text-center text-sm text-muted-foreground">Loading cases…</p>
          ) : error ? (
            <p className="py-8 text-center text-sm text-destructive">
              {error instanceof ApiError ? error.detail : "Failed to load cases"}
            </p>
          ) : cases.length === 0 ? (
            <div className="flex flex-col items-center gap-2 py-12 text-center">
              <LifeBuoy className="h-10 w-10 text-muted-foreground" />
              <p className="font-medium">No cases yet</p>
              <p className="text-sm text-muted-foreground">
                Open a new case to start tracking a customer issue.
              </p>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Case #</TableHead>
                      <TableHead>Subject</TableHead>
                      <TableHead>Priority</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Assignee</TableHead>
                      <TableHead>Updated</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {cases.map((c) => (
                      <TableRow key={c.ticket_id} className="cursor-pointer">
                        <TableCell className="font-mono text-xs">
                          <Link
                            to={`/crm/cases/${c.ticket_id}`}
                            className="text-primary hover:underline"
                          >
                            {c.case_number ?? c.ticket_id.slice(0, 8)}
                          </Link>
                        </TableCell>
                        <TableCell className="max-w-[280px]">
                          <Link
                            to={`/crm/cases/${c.ticket_id}`}
                            className="line-clamp-1 hover:underline"
                          >
                            {c.subject}
                          </Link>
                        </TableCell>
                        <TableCell>
                          {c.priority ? (
                            <Badge variant={priorityVariant(c.priority)} className="capitalize">
                              {c.priority}
                            </Badge>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge variant={statusVariant(c.status)}>
                            {STATUS_LABEL[c.status] ?? c.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {c.assigned_admin_sub ?? c.assigned_to_sub ?? "Unassigned"}
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {fmt(c.updated_at)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <div className="mt-4 flex items-center justify-between">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={cursorStack.length === 0}
                  onClick={() => setCursorStack((s) => s.slice(0, -1))}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!nextCursor}
                  onClick={() => nextCursor && setCursorStack((s) => [...s, nextCursor])}
                >
                  Next
                </Button>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
