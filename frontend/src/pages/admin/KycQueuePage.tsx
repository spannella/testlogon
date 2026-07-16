import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Eye, ChevronLeft, ChevronRight, BarChart3 } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
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
import { fetchKycQueue, type KycQueueItem } from "@/api/endpoints/kyc-admin";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function statusBadgeVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "submitted":
      return "default";
    case "under_review":
      return "secondary";
    case "needs_more_info":
      return "outline";
    case "approved":
      return "default";
    case "rejected":
      return "destructive";
    default:
      return "secondary";
  }
}

function riskBadgeVariant(risk: string | null): "default" | "secondary" | "destructive" | "outline" {
  switch (risk) {
    case "high":
      return "destructive";
    case "medium":
      return "outline";
    case "low":
      return "secondary";
    default:
      return "secondary";
  }
}

function formatWaitTime(seconds: number | null): string {
  if (seconds == null) return "--";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function KycQueuePage() {
  const navigate = useNavigate();
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [assigneeFilter, setAssigneeFilter] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [prevCursors, setPrevCursors] = useState<string[]>([]);

  const queueQuery = useQuery({
    queryKey: ["kyc-queue", statusFilter, riskFilter, assigneeFilter, cursor],
    queryFn: () =>
      fetchKycQueue({
        status: statusFilter !== "all" ? statusFilter : undefined,
        risk_tier: riskFilter !== "all" ? riskFilter : undefined,
        assignee_admin_sub: assigneeFilter.trim() || undefined,
        cursor,
        limit: 20,
      }),
  });

  const items = queueQuery.data?.items ?? [];
  const nextCursor = queueQuery.data?.next_cursor ?? null;

  function handleNextPage() {
    if (nextCursor) {
      setPrevCursors((prev) => [...prev, cursor ?? ""]);
      setCursor(nextCursor);
    }
  }

  function handlePrevPage() {
    if (prevCursors.length > 0) {
      const prev = [...prevCursors];
      const lastCursor = prev.pop()!;
      setPrevCursors(prev);
      setCursor(lastCursor || undefined);
    }
  }

  function handleRowClick(item: KycQueueItem) {
    navigate(`/admin/kyc/cases/${item.kyc_case_id}`);
  }

  return (
    <div className="container mx-auto max-w-6xl space-y-6 px-4 py-6">
      <div className="flex items-center justify-between">
        <PageHeader
          title="KYC Review Queue"
          description="Review and manage pending KYC verification cases."
        />
        <Button
          variant="outline"
          onClick={() => navigate("/admin/kyc/metrics")}
        >
          <BarChart3 className="mr-2 h-4 w-4" />
          Metrics
        </Button>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Filters</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-end gap-4">
            <div className="min-w-[160px]">
              <Label htmlFor="status-filter">Status</Label>
              <Select
                value={statusFilter}
                onValueChange={(val) => {
                  setStatusFilter(val);
                  setCursor(undefined);
                  setPrevCursors([]);
                }}
              >
                <SelectTrigger id="status-filter">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All</SelectItem>
                  <SelectItem value="submitted">Submitted</SelectItem>
                  <SelectItem value="under_review">Under Review</SelectItem>
                  <SelectItem value="needs_more_info">Needs More Info</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="min-w-[160px]">
              <Label htmlFor="risk-filter">Risk Tier</Label>
              <Select
                value={riskFilter}
                onValueChange={(val) => {
                  setRiskFilter(val);
                  setCursor(undefined);
                  setPrevCursors([]);
                }}
              >
                <SelectTrigger id="risk-filter">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="min-w-[200px]">
              <Label htmlFor="assignee-filter">Assignee</Label>
              <Input
                id="assignee-filter"
                placeholder="admin email..."
                value={assigneeFilter}
                onChange={(e) => {
                  setAssigneeFilter(e.target.value);
                  setCursor(undefined);
                  setPrevCursors([]);
                }}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Queue Table */}
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Case ID</TableHead>
                <TableHead>User</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Risk Tier</TableHead>
                <TableHead>Waiting</TableHead>
                <TableHead>Assigned To</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {queueQuery.isLoading && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                    Loading...
                  </TableCell>
                </TableRow>
              )}
              {!queueQuery.isLoading && items.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                    No cases found
                  </TableCell>
                </TableRow>
              )}
              {items.map((item) => (
                <TableRow
                  key={item.kyc_case_id}
                  className="cursor-pointer hover:bg-muted/50"
                  onClick={() => handleRowClick(item)}
                  data-testid={`kyc-row-${item.kyc_case_id}`}
                >
                  <TableCell className="font-mono text-xs">
                    {item.kyc_case_id}
                  </TableCell>
                  <TableCell className="text-sm">{item.user_sub}</TableCell>
                  <TableCell>
                    <Badge variant={statusBadgeVariant(item.status)} data-testid="status-badge">
                      {item.status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={riskBadgeVariant(item.risk_tier)} data-testid="risk-badge">
                      {item.risk_tier ?? "unknown"}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm">
                    {formatWaitTime(item.waiting_seconds)}
                  </TableCell>
                  <TableCell className="text-sm">
                    {item.assigned_admin_sub ?? "Unassigned"}
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleRowClick(item);
                      }}
                    >
                      <Eye className="mr-1 h-4 w-4" />
                      View
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>

          {/* Pagination */}
          {(prevCursors.length > 0 || nextCursor) && (
            <div className="flex items-center justify-between border-t px-4 py-3">
              <Button
                variant="outline"
                size="sm"
                disabled={prevCursors.length === 0}
                onClick={handlePrevPage}
              >
                <ChevronLeft className="mr-1 h-4 w-4" />
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={!nextCursor}
                onClick={handleNextPage}
              >
                Next
                <ChevronRight className="ml-1 h-4 w-4" />
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
