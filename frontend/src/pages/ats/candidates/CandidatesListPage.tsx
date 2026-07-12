import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { Plus, Search, Users, RefreshCw } from "lucide-react";

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
  listCandidates,
  CANDIDATE_STATUSES,
  CANDIDATE_SOURCES,
  type Candidate,
} from "@/api/endpoints/candidates";
import { CandidatesNotEnabled } from "./CandidatesNotEnabled";
import { fmtTs, humanize, statusColor, isNotEnabled, fullName } from "./candidateUtils";

const ALL = "__all__";

export default function CandidatesListPage() {
  const navigate = useNavigate();
  const token = useAuthStore((s) => s.accessToken);
  const currentUserSub = useAuthStore((s) => s.userId);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";

  const [statusFilter, setStatusFilter] = useState<string>(ALL);
  const [sourceFilter, setSourceFilter] = useState<string>(ALL);
  const [scope, setScope] = useState<"mine" | "all">("mine");
  const [search, setSearch] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const effectiveOwner =
    scope === "all" && isAdmin ? undefined : currentUserSub ?? undefined;

  const query = useQuery({
    queryKey: [
      "ats-candidates",
      { statusFilter, sourceFilter, effectiveOwner, cursor },
    ],
    queryFn: () =>
      listCandidates({
        owner_sub: effectiveOwner,
        status: statusFilter === ALL ? undefined : statusFilter,
        source: sourceFilter === ALL ? undefined : sourceFilter,
        cursor,
        limit: 50,
      }),
    retry: false,
  });

  if (query.isError && isNotEnabled(query.error)) {
    return (
      <div className="space-y-6">
        <PageHeader title="Candidates" description="ATS candidate management" />
        <CandidatesNotEnabled />
      </div>
    );
  }

  const allCandidates: Candidate[] = query.data?.candidates ?? [];
  const term = search.trim().toLowerCase();
  const candidates = term
    ? allCandidates.filter(
        (c) =>
          fullName(c.first_name, c.last_name).toLowerCase().includes(term) ||
          c.email.toLowerCase().includes(term) ||
          (c.company ?? "").toLowerCase().includes(term) ||
          (c.title ?? "").toLowerCase().includes(term) ||
          (c.key_skills ?? "").toLowerCase().includes(term),
      )
    : allCandidates;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Candidates"
        description="ATS candidate pipeline management"
        actions={
          <Button onClick={() => navigate("/ats/candidates/new")}>
            <Plus className="mr-2 h-4 w-4" />
            New Candidate
          </Button>
        }
      />

      {/* Filters */}
      <Card>
        <CardContent className="pt-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search name, email, company, skills…"
                className="pl-8"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>

            <Select value={statusFilter} onValueChange={(v) => { setStatusFilter(v); setCursor(undefined); }}>
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="All statuses" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All statuses</SelectItem>
                {CANDIDATE_STATUSES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {humanize(s)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={sourceFilter} onValueChange={(v) => { setSourceFilter(v); setCursor(undefined); }}>
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="All sources" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All sources</SelectItem>
                {CANDIDATE_SOURCES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {humanize(s)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            {isAdmin && (
              <Select value={scope} onValueChange={(v) => { setScope(v as "mine" | "all"); setCursor(undefined); }}>
                <SelectTrigger className="w-[130px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="mine">My candidates</SelectItem>
                  <SelectItem value="all">All candidates</SelectItem>
                </SelectContent>
              </Select>
            )}

            <Button
              variant="ghost"
              size="icon"
              onClick={() => void query.refetch()}
              title="Refresh"
            >
              <RefreshCw className={`h-4 w-4 ${query.isFetching ? "animate-spin" : ""}`} />
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          {query.isPending ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : candidates.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
              <Users className="h-8 w-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">
                {search ? "No candidates match your search." : "No candidates found."}
              </p>
              {!search && (
                <Button variant="outline" size="sm" onClick={() => navigate("/ats/candidates/new")}>
                  <Plus className="mr-2 h-3.5 w-3.5" />
                  Add candidate
                </Button>
              )}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Email</TableHead>
                  <TableHead className="hidden md:table-cell">Company / Title</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="hidden lg:table-cell">Source</TableHead>
                  <TableHead className="hidden xl:table-cell">Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {candidates.map((c) => (
                  <TableRow
                    key={c.candidate_id}
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => navigate(`/ats/candidates/${c.candidate_id}`)}
                  >
                    <TableCell className="font-medium">
                      <Link
                        to={`/ats/candidates/${c.candidate_id}`}
                        className="hover:underline"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {fullName(c.first_name, c.last_name)}
                      </Link>
                      {c.can_relocate && (
                        <span className="ml-2 text-xs text-muted-foreground">relocate</span>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {c.email_raw || c.email}
                    </TableCell>
                    <TableCell className="hidden md:table-cell text-sm text-muted-foreground">
                      {[c.company, c.title].filter(Boolean).join(" · ") || "—"}
                    </TableCell>
                    <TableCell>
                      <Badge className={`text-xs ${statusColor(c.status)}`}>
                        {humanize(c.status)}
                      </Badge>
                    </TableCell>
                    <TableCell className="hidden lg:table-cell text-sm text-muted-foreground">
                      {humanize(c.source)}
                    </TableCell>
                    <TableCell className="hidden xl:table-cell text-sm text-muted-foreground">
                      {fmtTs(c.created_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Pagination */}
      {(cursor || query.data?.cursor) && (
        <div className="flex justify-center gap-2">
          {cursor && (
            <Button variant="outline" size="sm" onClick={() => setCursor(undefined)}>
              First page
            </Button>
          )}
          {query.data?.cursor && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setCursor(query.data!.cursor ?? undefined)}
            >
              Load more
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
