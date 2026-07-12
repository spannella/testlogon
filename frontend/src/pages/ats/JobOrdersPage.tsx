/**
 * ATS — Job Orders list page.
 *
 * Route: /ats/jobs
 * Shows open job orders with status/company filter, hot-jobs tab, and my-jobs tab.
 * Each row links to /ats/jobs/:jobId for the detail view.
 * Create button opens the create dialog.
 */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Briefcase, Flame, User, Plus, RefreshCw } from "lucide-react";
import { toast } from "sonner";

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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ApiError } from "@/api/client";
import {
  listOpenJobOrders,
  listHotJobOrders,
  listMyJobOrders,
  getJobOrderFeatureStatus,
  type JobOrder,
  type JobOrderStatus,
  JOB_ORDER_OPEN_STATUSES,
} from "@/api/endpoints/jobOrders";
import { JobOrderCreateDialog } from "./JobOrderCreateDialog";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatCents(cents: number | null | undefined): string {
  if (cents == null) return "—";
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

function formatTs(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString();
}

function statusVariant(
  status: JobOrderStatus,
): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "active":
      return "default";
    case "full":
      return "secondary";
    case "closed":
    case "canceled":
      return "destructive";
    default:
      return "outline";
  }
}

function typeLabel(type: string): string {
  switch (type) {
    case "hire":
      return "Direct Hire";
    case "contract":
      return "Contract";
    case "contract_to_hire":
      return "Contract-to-Hire";
    case "referral":
      return "Referral";
    default:
      return type;
  }
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function JobOrderRow({ job }: { job: JobOrder }) {
  return (
    <tr className="border-b last:border-0 hover:bg-muted/30 transition-colors">
      <td className="py-3 px-4">
        <Link
          to={`/ats/jobs/${job.job_id}`}
          className="font-medium text-sm hover:underline text-primary"
          data-testid={`job-link-${job.job_id}`}
        >
          {job.title}
        </Link>
        <div className="text-xs text-muted-foreground mt-0.5">
          {typeLabel(job.type)}
          {job.city && ` · ${job.city}`}
          {job.state && `, ${job.state}`}
          {job.duration && ` · ${job.duration}`}
        </div>
      </td>
      <td className="py-3 px-4 text-sm text-muted-foreground">{job.client_company_id}</td>
      <td className="py-3 px-4">
        <Badge variant={statusVariant(job.status)} className="text-xs capitalize">
          {job.status.replace("_", " ")}
        </Badge>
        {job.hot && (
          <Badge variant="destructive" className="ml-1 text-xs">
            <Flame className="h-3 w-3 mr-0.5" />
            Hot
          </Badge>
        )}
      </td>
      <td className="py-3 px-4 text-sm text-right">
        {job.placed_count}/{job.openings}
      </td>
      <td className="py-3 px-4 text-sm text-right">
        {formatCents(job.pay_rate_cents)}
      </td>
      <td className="py-3 px-4 text-xs text-muted-foreground text-right">
        {formatTs(job.created_at)}
      </td>
    </tr>
  );
}

function JobOrderTable({
  jobs,
  isLoading,
  emptyMessage,
}: {
  jobs: JobOrder[];
  isLoading: boolean;
  emptyMessage?: string;
}) {
  if (isLoading) {
    return (
      <div className="py-8 text-center text-sm text-muted-foreground">
        Loading…
      </div>
    );
  }
  if (!jobs.length) {
    return (
      <div className="py-8 text-center text-sm text-muted-foreground">
        {emptyMessage ?? "No job orders found."}
      </div>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm" data-testid="job-orders-table">
        <thead>
          <tr className="border-b text-xs text-muted-foreground">
            <th className="py-2 px-4 text-left font-medium">Title</th>
            <th className="py-2 px-4 text-left font-medium">Company</th>
            <th className="py-2 px-4 text-left font-medium">Status</th>
            <th className="py-2 px-4 text-right font-medium">Placed/Open</th>
            <th className="py-2 px-4 text-right font-medium">Pay Rate</th>
            <th className="py-2 px-4 text-right font-medium">Created</th>
          </tr>
        </thead>
        <tbody>
          {jobs.map((job) => (
            <JobOrderRow key={job.job_id} job={job} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function JobOrdersPage() {
  const [statusFilter, setStatusFilter] = useState<JobOrderStatus | "all">("all");
  const [companyFilter, setCompanyFilter] = useState("");
  const [appliedCompany, setAppliedCompany] = useState("");
  const [openCursor, setOpenCursor] = useState<string | undefined>(undefined);
  const [hotCursor, setHotCursor] = useState<string | undefined>(undefined);
  const [mineCursor, setMineCursor] = useState<string | undefined>(undefined);
  const [createOpen, setCreateOpen] = useState(false);

  // Feature-flag check
  const featureQuery = useQuery({
    queryKey: ["ats", "feature-status"],
    queryFn: getJobOrderFeatureStatus,
    retry: false,
  });

  const isEnabled =
    featureQuery.data?.ats_enabled && featureQuery.data?.job_orders_enabled;

  // Open jobs
  const openQuery = useQuery({
    queryKey: ["ats", "jobs", "open", { statusFilter, appliedCompany, openCursor }],
    queryFn: () =>
      listOpenJobOrders({
        status: statusFilter === "all" ? undefined : statusFilter || undefined,
        company_id: appliedCompany || undefined,
        cursor: openCursor,
        limit: 25,
      }),
    enabled: !!isEnabled,
    retry: false,
  });

  // Hot jobs
  const hotQuery = useQuery({
    queryKey: ["ats", "jobs", "hot", { hotCursor }],
    queryFn: () => listHotJobOrders({ cursor: hotCursor, limit: 25 }),
    enabled: !!isEnabled,
    retry: false,
  });

  // Mine jobs
  const mineQuery = useQuery({
    queryKey: ["ats", "jobs", "mine", { mineCursor }],
    queryFn: () => listMyJobOrders({ cursor: mineCursor, limit: 25 }),
    enabled: !!isEnabled,
    retry: false,
  });

  // Handle feature-disabled state
  if (featureQuery.isLoading) {
    return (
      <div className="p-8 text-center text-sm text-muted-foreground">
        Checking feature availability…
      </div>
    );
  }

  if (
    featureQuery.isError &&
    featureQuery.error instanceof ApiError &&
    featureQuery.error.status >= 400
  ) {
    return (
      <div className="p-8 text-center text-sm text-muted-foreground">
        Unable to load ATS feature status.
      </div>
    );
  }

  if (!isEnabled) {
    return (
      <div className="space-y-6 p-4 md:p-6 lg:p-8">
        <PageHeader
          title="Job Orders"
          description="ATS — Applicant Tracking System"
        />
        <Card>
          <CardContent className="py-10 text-center">
            <Briefcase className="mx-auto h-10 w-10 text-muted-foreground mb-3" />
            <p className="text-sm font-medium">Job Orders are not enabled</p>
            <p className="text-xs text-muted-foreground mt-1">
              Enable <code>ATS_ENABLED=1</code> and <code>JOB_ORDERS_ENABLED=1</code> in the
              server environment to activate this feature.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader
        title="Job Orders"
        description="Manage recruiting requisitions across all client companies."
        actions={
          <Button
            size="sm"
            onClick={() => setCreateOpen(true)}
            data-testid="create-job-btn"
          >
            <Plus className="h-4 w-4 mr-1" />
            New Job Order
          </Button>
        }
      />

      <Tabs defaultValue="open">
        <TabsList>
          <TabsTrigger value="open" data-testid="tab-open">
            <Briefcase className="h-4 w-4 mr-1" />
            Open
          </TabsTrigger>
          <TabsTrigger value="hot" data-testid="tab-hot">
            <Flame className="h-4 w-4 mr-1" />
            Hot
          </TabsTrigger>
          <TabsTrigger value="mine" data-testid="tab-mine">
            <User className="h-4 w-4 mr-1" />
            Mine
          </TabsTrigger>
        </TabsList>

        {/* ── Open Jobs Tab ── */}
        <TabsContent value="open">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Open Job Orders</CardTitle>
              <CardDescription>
                All active, on-hold, full, lead, and upcoming orders.
              </CardDescription>
              <div className="flex flex-wrap gap-2 pt-2">
                <Select
                  value={statusFilter}
                  onValueChange={(v) => {
                    setStatusFilter(v as JobOrderStatus | "all");
                    setOpenCursor(undefined);
                  }}
                >
                  <SelectTrigger className="h-8 w-40 text-xs" data-testid="status-filter">
                    <SelectValue placeholder="All statuses" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All statuses</SelectItem>
                    {JOB_ORDER_OPEN_STATUSES.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s.replace("_", " ")}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  className="h-8 w-52 text-xs"
                  placeholder="Filter by company ID"
                  value={companyFilter}
                  onChange={(e) => setCompanyFilter(e.target.value)}
                  data-testid="company-filter"
                />
                <Button
                  size="sm"
                  variant="secondary"
                  className="h-8 text-xs"
                  onClick={() => {
                    setAppliedCompany(companyFilter.trim());
                    setOpenCursor(undefined);
                  }}
                >
                  Apply
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-8 text-xs"
                  onClick={() => void openQuery.refetch()}
                  disabled={openQuery.isFetching}
                  data-testid="refresh-open"
                >
                  <RefreshCw className="h-3 w-3 mr-1" />
                  Refresh
                </Button>
              </div>
            </CardHeader>
            <CardContent className="pt-0">
              <JobOrderTable
                jobs={openQuery.data?.items ?? []}
                isLoading={openQuery.isLoading}
                emptyMessage="No open job orders found."
              />
              <div className="flex justify-between mt-3">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!openCursor}
                  onClick={() => setOpenCursor(undefined)}
                >
                  First page
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!openQuery.data?.next_cursor}
                  onClick={() =>
                    setOpenCursor(openQuery.data?.next_cursor ?? undefined)
                  }
                  data-testid="open-next-page"
                >
                  Next page
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Hot Jobs Tab ── */}
        <TabsContent value="hot">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Hot Job Orders</CardTitle>
              <CardDescription>
                Flagged as high-priority / urgent fills.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <JobOrderTable
                jobs={hotQuery.data?.items ?? []}
                isLoading={hotQuery.isLoading}
                emptyMessage="No hot job orders at the moment."
              />
              <div className="flex justify-end mt-3">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!hotQuery.data?.next_cursor}
                  onClick={() =>
                    setHotCursor(hotQuery.data?.next_cursor ?? undefined)
                  }
                >
                  Next page
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Mine Tab ── */}
        <TabsContent value="mine">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">My Job Orders</CardTitle>
              <CardDescription>
                Orders where you are listed as a recruiter.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <JobOrderTable
                jobs={mineQuery.data?.items ?? []}
                isLoading={mineQuery.isLoading}
                emptyMessage="No job orders assigned to you."
              />
              <div className="flex justify-end mt-3">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!mineQuery.data?.next_cursor}
                  onClick={() =>
                    setMineCursor(mineQuery.data?.next_cursor ?? undefined)
                  }
                >
                  Next page
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <JobOrderCreateDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={(job) => {
          toast.success(`Job order "${job.title}" created`);
          void openQuery.refetch();
        }}
      />
    </div>
  );
}
