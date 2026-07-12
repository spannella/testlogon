/**
 * ATS — Job Order detail page.
 *
 * Route: /ats/jobs/:jobId
 * Shows full requirements, openings summary, placed count, description,
 * and allows status transitions + edit/delete.
 */
import { useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  Briefcase,
  Flame,
  Globe,
  MapPin,
  Pencil,
  Trash2,
  Users,
} from "lucide-react";
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
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Separator } from "@/components/ui/separator";
import { ApiError } from "@/api/client";
import {
  getJobOrder,
  getJobOrderOpenings,
  setJobOrderStatus,
  deleteJobOrder,
  type JobOrder,
  type JobOrderStatus,
  JOB_ORDER_STATUSES,
  JOB_ORDER_TERMINAL,
} from "@/api/endpoints/jobOrders";
import { JobOrderEditDialog } from "./JobOrderEditDialog";

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
  return new Date(ts * 1000).toLocaleString();
}

function statusBadgeVariant(
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

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between py-1.5 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium text-right max-w-[60%] break-words">{value}</span>
    </div>
  );
}

// ─── Status-transition widget ─────────────────────────────────────────────────

function StatusTransitionPanel({ job }: { job: JobOrder }) {
  const queryClient = useQueryClient();
  const [targetStatus, setTargetStatus] = useState<JobOrderStatus>(job.status);
  const isTerminal = JOB_ORDER_TERMINAL.includes(job.status);

  const statusMut = useMutation({
    mutationFn: () => setJobOrderStatus(job.job_id, targetStatus),
    onSuccess: (updated) => {
      toast.success(`Status changed to "${updated.status}"`);
      void queryClient.invalidateQueries({ queryKey: ["ats", "job", job.job_id] });
      void queryClient.invalidateQueries({ queryKey: ["ats", "jobs"] });
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError && err.status === 409) {
        toast.error("Illegal status transition — check allowed transitions.");
      } else {
        toast.error(
          err instanceof ApiError ? err.detail : "Failed to change status",
        );
      }
    },
  });

  if (isTerminal) {
    return (
      <p className="text-xs text-muted-foreground">
        This job order is in a terminal state ({job.status}) and cannot be transitioned further.
      </p>
    );
  }

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <Select
        value={targetStatus}
        onValueChange={(v) => setTargetStatus(v as JobOrderStatus)}
      >
        <SelectTrigger className="h-8 w-36 text-xs" data-testid="status-select">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {JOB_ORDER_STATUSES.map((s) => (
            <SelectItem key={s} value={s}>
              {s.replace("_", " ")}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Button
        size="sm"
        variant="outline"
        className="h-8 text-xs"
        disabled={targetStatus === job.status || statusMut.isPending}
        onClick={() => statusMut.mutate()}
        data-testid="apply-status-btn"
      >
        {statusMut.isPending ? "Applying…" : "Apply"}
      </Button>
    </div>
  );
}

// ─── Openings summary card ────────────────────────────────────────────────────

function OpeningsSummaryCard({ jobId }: { jobId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["ats", "job", jobId, "openings"],
    queryFn: () => getJobOrderOpenings(jobId),
    refetchInterval: 30_000,
  });

  return (
    <div className="grid grid-cols-3 gap-3">
      <Card>
        <CardHeader className="pb-1 pt-3 px-4">
          <CardDescription className="text-xs">Total Openings</CardDescription>
        </CardHeader>
        <CardContent className="px-4 pb-3">
          <p className="text-2xl font-bold" data-testid="openings-total">
            {isLoading ? "—" : (data?.openings ?? "—")}
          </p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-1 pt-3 px-4">
          <CardDescription className="text-xs">Placed</CardDescription>
        </CardHeader>
        <CardContent className="px-4 pb-3">
          <p className="text-2xl font-bold text-green-600" data-testid="openings-placed">
            {isLoading ? "—" : (data?.placed_count ?? "—")}
          </p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-1 pt-3 px-4">
          <CardDescription className="text-xs">Remaining</CardDescription>
        </CardHeader>
        <CardContent className="px-4 pb-3">
          <p className="text-2xl font-bold text-orange-500" data-testid="openings-remaining">
            {isLoading ? "—" : (data?.openings_remaining ?? "—")}
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function JobOrderDetailPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [editOpen, setEditOpen] = useState(false);

  const jobQuery = useQuery({
    queryKey: ["ats", "job", jobId],
    queryFn: () => getJobOrder(jobId!),
    enabled: !!jobId,
    retry: false,
  });

  const deleteMut = useMutation({
    mutationFn: () => deleteJobOrder(jobId!),
    onSuccess: () => {
      toast.success("Job order deleted");
      void queryClient.invalidateQueries({ queryKey: ["ats", "jobs"] });
      navigate("/ats/jobs");
    },
    onError: (err: unknown) => {
      toast.error(
        err instanceof ApiError ? err.detail : "Failed to delete job order",
      );
    },
  });

  if (jobQuery.isLoading) {
    return (
      <div className="p-8 text-center text-sm text-muted-foreground">
        Loading job order…
      </div>
    );
  }

  if (jobQuery.isError) {
    const err = jobQuery.error;
    const is404 = err instanceof ApiError && err.status === 404;
    const is503 = err instanceof ApiError && err.status === 503;
    return (
      <div className="p-8 text-center space-y-2">
        <p className="text-sm font-medium">
          {is404
            ? "Job order not found or has been deleted."
            : is503
            ? "Job Orders feature is not enabled."
            : "Failed to load job order."}
        </p>
        <Button variant="outline" size="sm" asChild>
          <Link to="/ats/jobs">Back to Job Orders</Link>
        </Button>
      </div>
    );
  }

  const job = jobQuery.data!;

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      {/* Back navigation */}
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Button variant="ghost" size="sm" asChild className="-ml-2">
          <Link to="/ats/jobs">
            <ArrowLeft className="h-4 w-4 mr-1" />
            Job Orders
          </Link>
        </Button>
      </div>

      <PageHeader
        title={job.title}
        description={`${typeLabel(job.type)} · ${job.client_company_id}`}
        actions={
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setEditOpen(true)}
              data-testid="edit-job-btn"
            >
              <Pencil className="h-4 w-4 mr-1" />
              Edit
            </Button>
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="text-destructive hover:text-destructive"
                  data-testid="delete-job-btn"
                >
                  <Trash2 className="h-4 w-4 mr-1" />
                  Delete
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Delete Job Order?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This will soft-delete &ldquo;{job.title}&rdquo;. The record
                    is not permanently removed. This action cannot be undone
                    from the UI.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction
                    onClick={() => deleteMut.mutate()}
                    className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                    data-testid="confirm-delete-btn"
                  >
                    Delete
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
        }
      />

      {/* Status + flags */}
      <div className="flex items-center gap-2 flex-wrap">
        <Badge
          variant={statusBadgeVariant(job.status)}
          className="capitalize text-sm px-3 py-1"
          data-testid="job-status-badge"
        >
          {job.status.replace("_", " ")}
        </Badge>
        {job.hot && (
          <Badge variant="destructive" className="text-sm px-3 py-1">
            <Flame className="h-3 w-3 mr-1" />
            Hot
          </Badge>
        )}
        {job.public && (
          <Badge variant="outline" className="text-sm px-3 py-1">
            <Globe className="h-3 w-3 mr-1" />
            Public
          </Badge>
        )}
      </div>

      {/* Openings summary */}
      <OpeningsSummaryCard jobId={job.job_id} />

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Details card */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Briefcase className="h-4 w-4" />
              Job Details
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-0">
            <InfoRow label="Job ID" value={<code className="text-xs">{job.job_id}</code>} />
            <Separator className="my-0.5" />
            <InfoRow label="Type" value={typeLabel(job.type)} />
            <Separator className="my-0.5" />
            <InfoRow label="Client Company" value={job.client_company_id} />
            <Separator className="my-0.5" />
            <InfoRow
              label="Client Contact"
              value={job.client_contact_id ?? "—"}
            />
            <Separator className="my-0.5" />
            <InfoRow
              label="Duration"
              value={job.duration ?? "—"}
            />
            <Separator className="my-0.5" />
            <InfoRow
              label="Location"
              value={
                job.city || job.state ? (
                  <span className="flex items-center gap-1">
                    <MapPin className="h-3 w-3" />
                    {[job.city, job.state].filter(Boolean).join(", ")}
                  </span>
                ) : (
                  "—"
                )
              }
            />
          </CardContent>
        </Card>

        {/* Compensation + recruiters */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Users className="h-4 w-4" />
              Compensation &amp; Recruiters
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-0">
            <InfoRow
              label="Pay Rate"
              value={formatCents(job.pay_rate_cents)}
            />
            <Separator className="my-0.5" />
            <InfoRow
              label="Bill Rate"
              value={formatCents(job.bill_rate_cents)}
            />
            <Separator className="my-0.5" />
            <InfoRow
              label="Recruiters"
              value={
                job.recruiter_subs.length > 0
                  ? job.recruiter_subs.join(", ")
                  : "—"
              }
            />
            <Separator className="my-0.5" />
            <InfoRow label="Created by" value={job.created_by} />
            <Separator className="my-0.5" />
            <InfoRow label="Created at" value={formatTs(job.created_at)} />
            <Separator className="my-0.5" />
            <InfoRow label="Updated at" value={formatTs(job.updated_at)} />
          </CardContent>
        </Card>
      </div>

      {/* Status transition */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Status Transition</CardTitle>
          <CardDescription>
            Move this job order through the 7-state workflow. Some transitions
            may be restricted (409 = illegal transition).
          </CardDescription>
        </CardHeader>
        <CardContent>
          <StatusTransitionPanel job={job} />
        </CardContent>
      </Card>

      {/* Description */}
      {job.description && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Description</CardTitle>
          </CardHeader>
          <CardContent>
            <pre
              className="text-sm whitespace-pre-wrap font-sans leading-relaxed"
              data-testid="job-description"
            >
              {job.description}
            </pre>
          </CardContent>
        </Card>
      )}

      {/* Edit dialog */}
      <JobOrderEditDialog
        job={job}
        open={editOpen}
        onOpenChange={setEditOpen}
        onUpdated={(updated) => {
          void queryClient.setQueryData(["ats", "job", jobId], updated);
        }}
      />
    </div>
  );
}
