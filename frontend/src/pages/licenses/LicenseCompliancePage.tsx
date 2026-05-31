import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import {
  COMPLIANCE_STATUSES,
  listMyContentCompliance,
} from "@/api/endpoints/licenseCompliance";
import { ComplianceBadge } from "@/components/shared/ComplianceBadge";
import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
import { FlagContentDialog } from "./FlagContentDialog";
import { LicenseComplianceDetailDialog } from "./LicenseComplianceDetailDialog";

function fmtDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

export default function LicenseCompliancePage() {
  const [status, setStatus] = useState<string>("all");
  const [detailContentId, setDetailContentId] = useState<string | null>(null);
  const [flagOpen, setFlagOpen] = useState(false);

  const query = useQuery({
    queryKey: ["compliance", "my-content", status],
    queryFn: () =>
      listMyContentCompliance({
        status: status === "all" ? undefined : status,
        limit: 100,
      }),
  });

  const items = query.data?.items ?? [];
  const summary = query.data?.summary;

  return (
    <div className="space-y-6">
      <PageHeader
        title="My Compliance"
        description="Licensing health of your content."
        actions={
          <Button variant="outline" onClick={() => setFlagOpen(true)}>
            Report Content
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        {[
          { label: "Tracked", value: summary?.total ?? 0 },
          { label: "Compliant", value: summary?.compliant ?? 0 },
          { label: "Expiring Soon", value: summary?.expiring_soon ?? 0 },
          { label: "Issues", value: summary?.issues ?? 0 },
          { label: "Flagged", value: summary?.flagged ?? 0 },
        ].map((c) => (
          <Card key={c.label}>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                {c.label}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <span className="text-2xl font-semibold">{c.value}</span>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex items-center gap-3">
        <Select value={status} onValueChange={setStatus}>
          <SelectTrigger className="w-56">
            <SelectValue placeholder="Filter by status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            {COMPLIANCE_STATUSES.map((s) => (
              <SelectItem key={s} value={s}>
                {s.replace(/_/g, " ")}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>My Content Compliance</CardTitle>
        </CardHeader>
        <CardContent>
          {query.isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : items.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No tracked content yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Content</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Issues</TableHead>
                  <TableHead>Last Checked</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((it) => (
                  <TableRow key={it.content_id}>
                    <TableCell className="font-mono text-xs">
                      {it.content_id}
                    </TableCell>
                    <TableCell>{it.content_type || "—"}</TableCell>
                    <TableCell>
                      <ComplianceBadge status={it.compliance_status} />
                    </TableCell>
                    <TableCell>{it.issue_count}</TableCell>
                    <TableCell>{fmtDate(it.last_checked_at)}</TableCell>
                    <TableCell>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setDetailContentId(it.content_id)}
                      >
                        View Details
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <LicenseComplianceDetailDialog
        contentId={detailContentId}
        open={!!detailContentId}
        onOpenChange={(v) => !v && setDetailContentId(null)}
      />
      <FlagContentDialog
        open={flagOpen}
        onOpenChange={setFlagOpen}
        reporterType="creator"
        onFlagged={() => query.refetch()}
      />
    </div>
  );
}
