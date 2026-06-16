import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { BarChart3, FileText, Plus, Trash2 } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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

import {
  createReport,
  deleteReport,
  listReports,
  REPORT_MODULES,
  type ReportModule,
} from "@/api/endpoints/crmReports";
import { ReportsNotEnabled } from "./ReportsNotEnabled";
import {
  fmtTs,
  isNotEnabled,
  moduleLabel,
  MODULE_DEFAULT_FIELDS,
} from "./reportUtils";

export default function ReportsListPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [module, setModule] = useState<ReportModule>("tickets");
  const [fieldsText, setFieldsText] = useState(MODULE_DEFAULT_FIELDS["tickets"]!.join(", "));

  const reportsQuery = useQuery({
    queryKey: ["crm-reports", "list", cursor],
    queryFn: () => listReports({ cursor, limit: 50 }),
    retry: false,
  });

  const createMut = useMutation({
    mutationFn: () => {
      const fields = fieldsText
        .split(",")
        .map((f) => f.trim())
        .filter(Boolean);
      return createReport({
        name: name.trim(),
        description: description.trim() || null,
        module,
        fields,
      });
    },
    onSuccess: (report) => {
      toast.success("Report created");
      setCreateOpen(false);
      setName("");
      setDescription("");
      void qc.invalidateQueries({ queryKey: ["crm-reports", "list"] });
      navigate(`/crm/reports/${encodeURIComponent(report.report_id)}`);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to create report"),
  });

  const deleteMut = useMutation({
    mutationFn: (reportId: string) => deleteReport(reportId),
    onSuccess: () => {
      toast.success("Report deleted");
      void qc.invalidateQueries({ queryKey: ["crm-reports", "list"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to delete report"),
  });

  const reports = reportsQuery.data?.reports ?? [];
  const nextCursor = reportsQuery.data?.next_cursor;

  const onModuleChange = (m: ReportModule) => {
    setModule(m);
    setFieldsText((MODULE_DEFAULT_FIELDS[m] ?? []).join(", "));
  };

  const canSubmit = useMemo(
    () => name.trim().length > 0 && fieldsText.trim().length > 0,
    [name, fieldsText],
  );

  if (reportsQuery.isError && isNotEnabled(reportsQuery.error)) {
    return (
      <div className="space-y-6">
        <PageHeader title="Reports" description="Build, run, and chart custom CRM reports." />
        <ReportsNotEnabled />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Reports"
        description="Build, run, and chart custom CRM reports across your modules."
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" asChild>
              <Link to="/crm/dashboard">
                <BarChart3 className="mr-2 h-4 w-4" />
                Dashboard
              </Link>
            </Button>
            <Button onClick={() => setCreateOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              New Report
            </Button>
          </div>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle>Saved reports</CardTitle>
        </CardHeader>
        <CardContent>
          {reportsQuery.isLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : reportsQuery.isError ? (
            <div className="py-8 text-center text-sm text-destructive">
              Unable to load reports.
            </div>
          ) : reports.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-12 text-center">
              <FileText className="h-10 w-10 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">
                No reports yet. Create your first custom report to get started.
              </p>
              <Button onClick={() => setCreateOpen(true)}>
                <Plus className="mr-2 h-4 w-4" />
                New Report
              </Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Module</TableHead>
                  <TableHead>Fields</TableHead>
                  <TableHead>Chart</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reports.map((r) => (
                  <TableRow key={r.report_id}>
                    <TableCell>
                      <Link
                        to={`/crm/reports/${encodeURIComponent(r.report_id)}`}
                        className="font-medium text-primary hover:underline"
                      >
                        {r.name}
                      </Link>
                      {r.description && (
                        <p className="text-xs text-muted-foreground">{r.description}</p>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">{moduleLabel(r.module)}</Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {r.group_by ? `Grouped by ${r.group_by}` : `${r.fields.length} field(s)`}
                    </TableCell>
                    <TableCell>
                      {r.chart ? (
                        <Badge variant="outline">{r.chart.chart_type}</Badge>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {fmtTs(r.updated_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          if (window.confirm(`Delete report "${r.name}"?`)) {
                            deleteMut.mutate(r.report_id);
                          }
                        }}
                        disabled={deleteMut.isPending}
                      >
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          {(cursor || nextCursor) && (
            <div className="mt-4 flex justify-between">
              <Button
                variant="outline"
                size="sm"
                disabled={!cursor}
                onClick={() => setCursor(undefined)}
              >
                First page
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={!nextCursor}
                onClick={() => setCursor(nextCursor ?? undefined)}
              >
                Next page
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Report</DialogTitle>
            <DialogDescription>
              Choose a module and the fields you want to project. You can add filters,
              grouping, and a chart from the report viewer.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="rpt-name">Name</Label>
              <Input
                id="rpt-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Open tickets this month"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="rpt-desc">Description</Label>
              <Textarea
                id="rpt-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Optional description"
                rows={2}
              />
            </div>
            <div className="space-y-1.5">
              <Label>Module</Label>
              <Select value={module} onValueChange={(v) => onModuleChange(v as ReportModule)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {REPORT_MODULES.map((m) => (
                    <SelectItem key={m} value={m}>
                      {moduleLabel(m)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="rpt-fields">Fields (comma-separated)</Label>
              <Input
                id="rpt-fields"
                value={fieldsText}
                onChange={(e) => setFieldsText(e.target.value)}
                placeholder="field_a, field_b"
              />
              <p className="text-xs text-muted-foreground">
                The columns projected from each {moduleLabel(module)} record.
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => createMut.mutate()} disabled={!canSubmit || createMut.isPending}>
              {createMut.isPending ? "Creating…" : "Create report"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
