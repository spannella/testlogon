import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { ScrollText, Search } from "lucide-react";

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
import { ApiError } from "@/api/client";
import {
  AUDIT_CATEGORIES,
  browseAuditLog,
  type AuditCategory,
  type AuditEventItem,
} from "@/api/endpoints/crmAudit";

function isoToLocal(d: Date): string {
  // datetime-local value (yyyy-MM-ddThh:mm) in local time
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(
    d.getHours(),
  )}:${pad(d.getMinutes())}`;
}

function localToTs(value: string): number {
  if (!value) return 0;
  const ms = new Date(value).getTime();
  return Number.isNaN(ms) ? 0 : Math.floor(ms / 1000);
}

function fmtTs(ts?: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

const DEFAULT_FROM = (() => {
  const d = new Date();
  d.setDate(d.getDate() - 7);
  return isoToLocal(d);
})();
const DEFAULT_TO = isoToLocal(new Date());

interface Filters {
  category: AuditCategory;
  from: string;
  to: string;
  userSub: string;
  eventType: string;
}

export default function CrmAuditLogPage() {
  const [draft, setDraft] = useState<Filters>({
    category: "auth",
    from: DEFAULT_FROM,
    to: DEFAULT_TO,
    userSub: "",
    eventType: "",
  });
  // Applied filters drive the query (only updated on "Search").
  const [applied, setApplied] = useState<Filters | null>(null);

  const fromTs = applied ? localToTs(applied.from) : 0;
  const toTs = applied ? localToTs(applied.to) : 0;

  const query = useQuery({
    queryKey: [
      "crm-audit-log",
      applied?.category,
      fromTs,
      toTs,
      applied?.userSub,
      applied?.eventType,
    ],
    enabled: !!applied,
    retry: false,
    queryFn: () =>
      browseAuditLog({
        category: applied!.category,
        from_ts: fromTs,
        to_ts: toTs,
        user_sub: applied!.userSub || undefined,
        event_type: applied!.eventType || undefined,
        limit: 100,
      }),
  });

  const apply = () => {
    const f = localToTs(draft.from);
    const t = localToTs(draft.to);
    if (!f || !t) {
      toast.error("Please choose a valid date range.");
      return;
    }
    if (f > t) {
      toast.error("'From' must be before 'To'.");
      return;
    }
    setApplied({ ...draft });
  };

  const err = query.error;
  const flagOff =
    query.isError && err instanceof ApiError && err.status === 404;
  const forbidden =
    query.isError && err instanceof ApiError && err.status === 403;
  const badRange =
    query.isError && err instanceof ApiError && err.status === 400;

  if (flagOff) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Audit Log"
          description="Browse platform audit events."
        />
        <Card>
          <CardHeader>
            <CardTitle>Audit log browse is not enabled</CardTitle>
            <CardDescription>
              This feature is turned off. Ask an operator to enable{" "}
              <code className="rounded bg-muted px-1">
                CRM_AUDIT_LOG_BROWSE_ENABLED
              </code>
              .
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  if (forbidden) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Audit Log"
          description="Browse platform audit events."
        />
        <Card>
          <CardHeader>
            <CardTitle>Root access required</CardTitle>
            <CardDescription>
              Only root operators can browse the audit log.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  const items: AuditEventItem[] = query.data?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit Log"
        description="Filterable browse of platform audit events (root-only)."
      />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ScrollText className="h-4 w-4" /> Filters
          </CardTitle>
          <CardDescription>
            Pick a category and date range, then search.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <div className="space-y-2">
              <Label htmlFor="audit-category">Category</Label>
              <Select
                value={draft.category}
                onValueChange={(v) =>
                  setDraft((d) => ({ ...d, category: v as AuditCategory }))
                }
              >
                <SelectTrigger id="audit-category">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {AUDIT_CATEGORIES.map((c) => (
                    <SelectItem key={c} value={c}>
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="audit-from">From</Label>
              <Input
                id="audit-from"
                type="datetime-local"
                value={draft.from}
                onChange={(e) =>
                  setDraft((d) => ({ ...d, from: e.target.value }))
                }
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="audit-to">To</Label>
              <Input
                id="audit-to"
                type="datetime-local"
                value={draft.to}
                onChange={(e) =>
                  setDraft((d) => ({ ...d, to: e.target.value }))
                }
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="audit-actor">Actor user_sub (optional)</Label>
              <Input
                id="audit-actor"
                value={draft.userSub}
                onChange={(e) =>
                  setDraft((d) => ({ ...d, userSub: e.target.value }))
                }
                placeholder="Filter by actor"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="audit-event">Event type (optional)</Label>
              <Input
                id="audit-event"
                value={draft.eventType}
                onChange={(e) =>
                  setDraft((d) => ({ ...d, eventType: e.target.value }))
                }
                placeholder="e.g. login_success"
              />
            </div>
            <div className="flex items-end">
              <Button onClick={apply} disabled={query.isFetching}>
                <Search className="mr-2 h-4 w-4" />
                {query.isFetching ? "Searching…" : "Search"}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Results</CardTitle>
          <CardDescription>
            {applied
              ? `${items.length} shown · scanned ${
                  query.data?.total_scanned ?? 0
                }`
              : "Run a search to see audit events."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!applied ? (
            <p className="text-sm text-muted-foreground">
              Choose filters above and click Search.
            </p>
          ) : badRange ? (
            <p className="text-sm text-destructive">
              {(err as ApiError).detail || "Invalid date range."}
            </p>
          ) : query.isFetching ? (
            <p className="text-sm text-muted-foreground">Loading events…</p>
          ) : items.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No audit events found for this filter.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Actor</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Outcome</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((row, idx) => (
                    <TableRow key={row.event_id ?? idx}>
                      <TableCell className="whitespace-nowrap">
                        {row.timestamp_unix
                          ? fmtTs(row.timestamp_unix)
                          : row.timestamp ?? "—"}
                      </TableCell>
                      <TableCell className="font-medium">
                        {row.event_action ?? "—"}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {row.event_type ?? "—"}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {row.actor_user_id ?? "—"}
                        {row.actor_role ? (
                          <span className="ml-1 text-muted-foreground">
                            ({row.actor_role})
                          </span>
                        ) : null}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {row.target_resource_id ??
                          row.target_user_id ??
                          "—"}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            row.outcome === "success" ? "outline" : "destructive"
                          }
                        >
                          {row.outcome ?? "—"}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          {query.data?.cursor ? (
            <div className="mt-3 text-xs text-muted-foreground">
              <Badge variant="outline">More results available</Badge>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
