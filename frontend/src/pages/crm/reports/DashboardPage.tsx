import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { LayoutDashboard, Plus, FileText } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
  addDashlet,
  DASHLET_TYPES,
  getDashboard,
  listReports,
  removeDashlet,
  type DashletType,
} from "@/api/endpoints/crmReports";
import { DashletCard } from "./DashletCard";
import { ReportsNotEnabled } from "./ReportsNotEnabled";
import { isNotEnabled } from "./reportUtils";

const DASHLET_LABELS: Record<DashletType, string> = {
  recent_tickets: "Recent Tickets",
  calendar_today: "Today's Calendar",
  my_contacts: "My Contacts",
  billing_summary: "Billing Summary",
  report: "Report",
  saved_search: "Saved Search",
};

export default function DashboardPage() {
  const qc = useQueryClient();

  const [addOpen, setAddOpen] = useState(false);
  const [dashletType, setDashletType] = useState<DashletType>("recent_tickets");
  const [title, setTitle] = useState("");
  const [reportId, setReportId] = useState("");
  const [savedSearchId, setSavedSearchId] = useState("");

  const dashboardQuery = useQuery({
    queryKey: ["crm-dashboard"],
    queryFn: () => getDashboard(),
    retry: false,
  });

  // Reports list for the "report" dashlet config picker.
  const reportsQuery = useQuery({
    queryKey: ["crm-reports", "list-for-dashlet"],
    queryFn: () => listReports({ limit: 50 }),
    retry: false,
    enabled: addOpen && dashletType === "report",
  });

  const addMut = useMutation({
    mutationFn: () => {
      const config: Record<string, unknown> = {};
      if (dashletType === "report") config["report_id"] = reportId;
      if (dashletType === "saved_search") config["saved_search_id"] = savedSearchId;
      return addDashlet({
        dashlet_type: dashletType,
        title: title.trim() || DASHLET_LABELS[dashletType],
        config,
      });
    },
    onSuccess: () => {
      toast.success("Dashlet added");
      setAddOpen(false);
      setTitle("");
      setReportId("");
      setSavedSearchId("");
      void qc.invalidateQueries({ queryKey: ["crm-dashboard"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to add dashlet"),
  });

  const removeMut = useMutation({
    mutationFn: (dashletId: string) => removeDashlet(dashletId),
    onSuccess: () => {
      toast.success("Dashlet removed");
      void qc.invalidateQueries({ queryKey: ["crm-dashboard"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to remove dashlet"),
  });

  if (dashboardQuery.isError && isNotEnabled(dashboardQuery.error)) {
    return (
      <div className="space-y-6">
        <PageHeader title="Dashboard" description="Your configurable CRM home." />
        <ReportsNotEnabled feature="Dashboards" />
      </div>
    );
  }

  const dashlets = dashboardQuery.data?.dashlets ?? [];

  const addDisabled =
    addMut.isPending ||
    (dashletType === "report" && !reportId) ||
    (dashletType === "saved_search" && !savedSearchId.trim());

  return (
    <div className="space-y-6">
      <PageHeader
        title={dashboardQuery.data?.name || "Dashboard"}
        description="A configurable home view with live dashlets."
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" asChild>
              <Link to="/crm/reports">
                <FileText className="mr-2 h-4 w-4" />
                Reports
              </Link>
            </Button>
            <Button onClick={() => setAddOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              Add dashlet
            </Button>
          </div>
        }
      />

      {dashboardQuery.isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Skeleton className="h-40 w-full" />
          <Skeleton className="h-40 w-full" />
          <Skeleton className="h-40 w-full" />
        </div>
      ) : dashboardQuery.isError ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-destructive">
            Unable to load the dashboard.
          </CardContent>
        </Card>
      ) : dashlets.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
            <LayoutDashboard className="h-10 w-10 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              Your dashboard is empty. Add a dashlet to surface tickets, contacts, billing, or a report.
            </p>
            <Button onClick={() => setAddOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              Add dashlet
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {dashlets.map((d) => (
            <DashletCard
              key={d.dashlet_id}
              dashlet={d}
              onRemove={(id) => removeMut.mutate(id)}
              removing={removeMut.isPending}
            />
          ))}
        </div>
      )}

      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add dashlet</DialogTitle>
            <DialogDescription>
              Pick a dashlet type to add to your home dashboard.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label>Type</Label>
              <Select value={dashletType} onValueChange={(v) => setDashletType(v as DashletType)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {DASHLET_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {DASHLET_LABELS[t]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="dlt-title">Title</Label>
              <Input
                id="dlt-title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder={DASHLET_LABELS[dashletType]}
              />
            </div>
            {dashletType === "report" && (
              <div className="space-y-1.5">
                <Label>Report</Label>
                <Select value={reportId} onValueChange={setReportId}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select a report" />
                  </SelectTrigger>
                  <SelectContent>
                    {(reportsQuery.data?.reports ?? []).map((r) => (
                      <SelectItem key={r.report_id} value={r.report_id}>
                        {r.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {reportsQuery.data && reportsQuery.data.reports.length === 0 && (
                  <p className="text-xs text-muted-foreground">
                    No reports yet — create one first.
                  </p>
                )}
              </div>
            )}
            {dashletType === "saved_search" && (
              <div className="space-y-1.5">
                <Label htmlFor="dlt-ss">Saved search ID</Label>
                <Input
                  id="dlt-ss"
                  value={savedSearchId}
                  onChange={(e) => setSavedSearchId(e.target.value)}
                  placeholder="SS#..."
                />
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => addMut.mutate()} disabled={addDisabled}>
              {addMut.isPending ? "Adding…" : "Add dashlet"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
