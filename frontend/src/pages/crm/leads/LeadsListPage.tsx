import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { Plus, Search, Target, RefreshCw } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
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
import { Skeleton } from "@/components/ui/skeleton";
import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";
import {
  listLeads,
  adminListAllLeads,
  LEAD_STATUSES,
  LEAD_SOURCES,
  type Lead,
} from "@/api/endpoints/leads";
import { LeadsNotEnabled } from "./LeadsNotEnabled";
import { fmtTs, humanize, statusVariant, isNotEnabled, fullName } from "./leadUtils";

const ALL = "__all__";

export default function LeadsListPage() {
  const navigate = useNavigate();
  const token = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";

  const [statusFilter, setStatusFilter] = useState<string>(ALL);
  const [sourceFilter, setSourceFilter] = useState<string>(ALL);
  const [scope, setScope] = useState<"mine" | "all">("mine");
  const [search, setSearch] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const adminScope = isAdmin && scope === "all";

  const query = useQuery({
    queryKey: ["crm-leads", { statusFilter, sourceFilter, adminScope, cursor }],
    queryFn: () => {
      const status = statusFilter === ALL ? undefined : statusFilter;
      const lead_source = sourceFilter === ALL ? undefined : sourceFilter;
      if (adminScope) {
        return adminListAllLeads({ status, lead_source, cursor, limit: 50 });
      }
      return listLeads({ status, lead_source, cursor, limit: 50 });
    },
    retry: false,
  });

  if (query.isError && isNotEnabled(query.error)) {
    return (
      <div className="space-y-6">
        <PageHeader title="Leads" description="SuiteCRM lead management" />
        <LeadsNotEnabled />
      </div>
    );
  }

  const allLeads: Lead[] = query.data?.leads ?? [];
  const term = search.trim().toLowerCase();
  const leads = term
    ? allLeads.filter((l) =>
        [l.first_name, l.last_name, l.email, l.company, l.title]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(term)),
      )
    : allLeads;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Leads"
        description="Capture, qualify, and convert SuiteCRM leads"
        actions={
          <Button onClick={() => navigate("/crm/leads/new")}>
            <Plus className="mr-2 h-4 w-4" /> New Lead
          </Button>
        }
      />

      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 py-4">
          <div className="relative min-w-[200px] flex-1">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search name, email, company…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8"
            />
          </div>

          <Select
            value={statusFilter}
            onValueChange={(v) => {
              setStatusFilter(v);
              setCursor(undefined);
            }}
          >
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>All statuses</SelectItem>
              {LEAD_STATUSES.map((s) => (
                <SelectItem key={s} value={s}>
                  {humanize(s)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select
            value={sourceFilter}
            onValueChange={(v) => {
              setSourceFilter(v);
              setCursor(undefined);
            }}
          >
            <SelectTrigger className="w-[170px]">
              <SelectValue placeholder="Source" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>All sources</SelectItem>
              {LEAD_SOURCES.map((s) => (
                <SelectItem key={s} value={s}>
                  {humanize(s)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          {isAdmin && (
            <Select
              value={scope}
              onValueChange={(v) => {
                setScope(v as "mine" | "all");
                setCursor(undefined);
              }}
            >
              <SelectTrigger className="w-[150px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="mine">My leads</SelectItem>
                <SelectItem value="all">All leads (admin)</SelectItem>
              </SelectContent>
            </Select>
          )}

          <Button variant="outline" size="icon" onClick={() => query.refetch()} title="Refresh">
            <RefreshCw className="h-4 w-4" />
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          {query.isLoading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : query.isError ? (
            <div className="p-8 text-center text-sm text-destructive">
              Failed to load leads. Please try again.
            </div>
          ) : leads.length === 0 ? (
            <div className="flex flex-col items-center gap-2 p-12 text-center">
              <Target className="h-8 w-8 text-muted-foreground" />
              <p className="font-medium">No leads found</p>
              <p className="text-sm text-muted-foreground">
                {term || statusFilter !== ALL || sourceFilter !== ALL
                  ? "Try adjusting your filters."
                  : "Create your first lead to get started."}
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Email</TableHead>
                  <TableHead>Company</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Score</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {leads.map((l) => (
                  <TableRow
                    key={l.lead_id}
                    className="cursor-pointer"
                    onClick={() => navigate(`/crm/leads/${l.lead_id}`)}
                  >
                    <TableCell className="font-medium">
                      <Link
                        to={`/crm/leads/${l.lead_id}`}
                        className="hover:underline"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {fullName(l.first_name, l.last_name)}
                      </Link>
                      {l.title && (
                        <div className="text-xs text-muted-foreground">{l.title}</div>
                      )}
                    </TableCell>
                    <TableCell className="text-sm">{l.email}</TableCell>
                    <TableCell className="text-sm">{l.company || "—"}</TableCell>
                    <TableCell className="text-sm">{humanize(l.lead_source)}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={statusVariant(l.status)}>
                        {humanize(l.status)}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{l.score}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {fmtTs(l.created_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {(cursor || query.data?.cursor) && !term && (
        <div className="flex justify-between">
          <Button
            variant="outline"
            disabled={!cursor}
            onClick={() => setCursor(undefined)}
          >
            First page
          </Button>
          <Button
            variant="outline"
            disabled={!query.data?.cursor}
            onClick={() => setCursor(query.data?.cursor ?? undefined)}
          >
            Next page
          </Button>
        </div>
      )}
    </div>
  );
}
