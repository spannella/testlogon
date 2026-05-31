import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  adminListComplianceFlags,
  adminListComplianceIssues,
  adminRunComplianceScan,
  adminUpdateComplianceStatus,
} from "@/api/endpoints/licenseCompliance";
import type { ComplianceFlagOut } from "@/api/types";
import { ComplianceBadge } from "@/components/shared/ComplianceBadge";
import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { AdminFlagResolveDialog } from "./AdminFlagResolveDialog";

function fmtDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

export default function AdminLicenseCompliancePage() {
  const queryClient = useQueryClient();
  const [activeFlag, setActiveFlag] = useState<ComplianceFlagOut | null>(null);

  const issuesQuery = useQuery({
    queryKey: ["admin-compliance", "issues"],
    queryFn: () => adminListComplianceIssues({ limit: 100 }),
  });
  const flagsQuery = useQuery({
    queryKey: ["admin-compliance", "flags"],
    queryFn: () => adminListComplianceFlags({ limit: 100 }),
  });

  const scanMut = useMutation({
    mutationFn: async () => adminRunComplianceScan(),
    onSuccess: (r) => {
      toast.success(
        `Scan complete: ${r.checked} checked, ${r.issues_found} issues, ${r.alerts_sent} alerts`,
      );
      queryClient.invalidateQueries({ queryKey: ["admin-compliance"] });
    },
    onError: (e: Error) => toast.error(e.message || "Scan failed"),
  });

  const statusMut = useMutation({
    mutationFn: async (args: { contentId: string; newStatus: string }) =>
      adminUpdateComplianceStatus(args.contentId, { new_status: args.newStatus }),
    onSuccess: () => {
      toast.success("Status updated");
      queryClient.invalidateQueries({ queryKey: ["admin-compliance"] });
    },
    onError: (e: Error) => toast.error(e.message || "Update failed"),
  });

  const issues = issuesQuery.data?.items ?? [];
  const flags = flagsQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="License Compliance (Admin)"
        description="Platform-wide compliance issues and flag review."
        actions={
          <Button
            onClick={() => scanMut.mutate()}
            disabled={scanMut.isPending}
          >
            {scanMut.isPending ? "Scanning…" : "Run Compliance Scan"}
          </Button>
        }
      />

      <Tabs defaultValue="issues">
        <TabsList>
          <TabsTrigger value="issues">Issues</TabsTrigger>
          <TabsTrigger value="flags">Flags</TabsTrigger>
        </TabsList>

        <TabsContent value="issues">
          <Card>
            <CardContent className="pt-6">
              {issues.length === 0 ? (
                <p className="text-sm text-muted-foreground">No issues.</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Content</TableHead>
                      <TableHead>Creator</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Date</TableHead>
                      <TableHead />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {issues.map((it) => (
                      <TableRow key={`${it.content_id}-${it.created_at}`}>
                        <TableCell className="font-mono text-xs">
                          {it.content_id}
                        </TableCell>
                        <TableCell>
                          {it.creator_display_name || it.creator_id || "—"}
                        </TableCell>
                        <TableCell>
                          <ComplianceBadge status={it.compliance_status} />
                        </TableCell>
                        <TableCell>{it.severity}</TableCell>
                        <TableCell>{fmtDate(it.created_at)}</TableCell>
                        <TableCell className="space-x-1">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() =>
                              statusMut.mutate({
                                contentId: it.content_id,
                                newStatus: "under_review",
                              })
                            }
                          >
                            Review
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() =>
                              statusMut.mutate({
                                contentId: it.content_id,
                                newStatus: "action_required",
                              })
                            }
                          >
                            Action Required
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="flags">
          <Card>
            <CardContent className="pt-6">
              {flags.length === 0 ? (
                <p className="text-sm text-muted-foreground">No flags.</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Content</TableHead>
                      <TableHead>Reporter</TableHead>
                      <TableHead>Reason</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {flags.map((f) => (
                      <TableRow key={f.flag_id}>
                        <TableCell className="font-mono text-xs">
                          {f.content_id}
                        </TableCell>
                        <TableCell>{f.reporter_type}</TableCell>
                        <TableCell>{f.reason.replace(/_/g, " ")}</TableCell>
                        <TableCell>
                          <ComplianceBadge status={f.status} />
                        </TableCell>
                        <TableCell>
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={f.status !== "open"}
                            onClick={() => setActiveFlag(f)}
                          >
                            Resolve
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <AdminFlagResolveDialog
        flag={activeFlag}
        open={!!activeFlag}
        onOpenChange={(v) => !v && setActiveFlag(null)}
      />
    </div>
  );
}
