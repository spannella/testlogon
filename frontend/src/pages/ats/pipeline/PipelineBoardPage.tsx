/**
 * ATS Pipeline Board — PIP-001..PIP-005, PIP-009, PIP-010.
 *
 * Route: /ats/pipeline
 *
 * Shows all pipeline entries for a selected job order arranged in Kanban-style
 * columns by pipeline status. Users can:
 *   - Pick a job order to view its pipeline board
 *   - Advance / move a candidate to a different stage
 *   - Set a 0–5 star rating on a pipeline entry
 *   - Add a new candidate to the pipeline (opens AddCandidateToPipelineDialog)
 *   - Remove a candidate from the pipeline
 *   - Navigate to the pipeline detail view for a specific candidate
 */
import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  GitMerge,
  Plus,
  RefreshCw,
  Trash2,
  ChevronRight,
  ChevronLeft,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { ApiError } from "@/api/client";
import {
  listPipelineByJob,
  getPipelineStatuses,
  changePipelineStatus,
  setPipelineRating,
  removePipelineEntry,
  type PipelineEntry,
  type PipelineStatusItem,
} from "@/api/endpoints/atsPipeline";
import { listOpenJobOrders, type JobOrder } from "@/api/endpoints/jobOrders";
import { PipelineNotEnabled } from "./PipelineNotEnabled";
import { AddCandidateToPipelineDialog } from "./AddCandidateToPipelineDialog";
import { statusBadgeClass, fmtTs, isNotEnabled } from "./pipelineUtils";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function statusConfigByKey(
  statuses: PipelineStatusItem[],
  key: string,
): PipelineStatusItem | undefined {
  return statuses.find((s) => s.status_key === key);
}

// ─── Candidate card on the board ─────────────────────────────────────────────

interface CandidateCardProps {
  entry: PipelineEntry;
  statuses: PipelineStatusItem[];
  jobOrderId: string;
  onStatusChange: (entry: PipelineEntry, newStatus: string) => void;
  onRating: (entry: PipelineEntry, rating: number) => void;
  onRemove: (entry: PipelineEntry) => void;
}

function CandidateCard({
  entry,
  statuses,
  jobOrderId,
  onStatusChange,
  onRating,
  onRemove,
}: CandidateCardProps) {
  const currentIdx = statuses.findIndex((s) => s.status_key === entry.status);
  const prevStatus = currentIdx > 0 ? statuses[currentIdx - 1] : null;
  const nextStatus = currentIdx >= 0 && currentIdx < statuses.length - 1 ? statuses[currentIdx + 1] : null;
  const cfg = statusConfigByKey(statuses, entry.status);

  return (
    <Card className="mb-2 shadow-sm hover:shadow-md transition-shadow">
      <CardContent className="p-3">
        {/* Candidate ID link to detail */}
        <div className="flex items-start justify-between gap-2 mb-1">
          <Link
            to={`/ats/pipeline/detail/${jobOrderId}/${entry.candidate_id}`}
            className="text-sm font-medium text-primary hover:underline truncate"
          >
            {entry.candidate_id.slice(0, 12)}…
          </Link>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6 text-destructive hover:text-destructive"
                onClick={() => onRemove(entry)}
              >
                <Trash2 className="h-3 w-3" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Remove from pipeline</TooltipContent>
          </Tooltip>
        </div>

        {/* Status badge */}
        <div className="mb-2">
          <Badge
            className={`text-xs px-1.5 py-0 ${statusBadgeClass(entry.status, cfg)}`}
            style={cfg?.color ? { backgroundColor: cfg.color + "22", color: cfg.color } : {}}
          >
            {cfg?.label ?? entry.status}
          </Badge>
        </div>

        {/* Star rating row */}
        <div className="flex items-center gap-0.5 mb-2">
          {[1, 2, 3, 4, 5].map((star) => (
            <button
              key={star}
              onClick={() => onRating(entry, entry.rating === star ? 0 : star)}
              className={`text-sm transition-colors ${
                star <= entry.rating
                  ? "text-amber-400 hover:text-amber-500"
                  : "text-muted-foreground hover:text-amber-300"
              }`}
              title={`${star} star${star > 1 ? "s" : ""}`}
            >
              ★
            </button>
          ))}
        </div>

        {/* Stage advance / retreat buttons */}
        <div className="flex gap-1 mt-1">
          {prevStatus && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-6 px-1.5 text-xs"
                  onClick={() => onStatusChange(entry, prevStatus.status_key)}
                >
                  <ChevronLeft className="h-3 w-3" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Move to: {prevStatus.label}</TooltipContent>
            </Tooltip>
          )}
          {nextStatus && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-6 px-1.5 text-xs"
                  onClick={() => onStatusChange(entry, nextStatus.status_key)}
                >
                  <ChevronRight className="h-3 w-3" />
                  <span className="ml-0.5">Advance</span>
                </Button>
              </TooltipTrigger>
              <TooltipContent>Move to: {nextStatus.label}</TooltipContent>
            </Tooltip>
          )}
        </div>

        <p className="text-[10px] text-muted-foreground mt-1.5">
          Updated {fmtTs(entry.updated_at)}
        </p>
      </CardContent>
    </Card>
  );
}

// ─── Kanban column ────────────────────────────────────────────────────────────

interface KanbanColumnProps {
  status: PipelineStatusItem;
  entries: PipelineEntry[];
  allStatuses: PipelineStatusItem[];
  jobOrderId: string;
  onStatusChange: (entry: PipelineEntry, newStatus: string) => void;
  onRating: (entry: PipelineEntry, rating: number) => void;
  onRemove: (entry: PipelineEntry) => void;
}

function KanbanColumn({
  status,
  entries,
  allStatuses,
  jobOrderId,
  onStatusChange,
  onRating,
  onRemove,
}: KanbanColumnProps) {
  return (
    <div className="flex-shrink-0 w-56">
      <div
        className="rounded-t-md px-3 py-2 flex items-center justify-between"
        style={{
          backgroundColor: status.color ? status.color + "33" : undefined,
        }}
      >
        <span
          className="text-sm font-semibold truncate"
          style={status.color ? { color: status.color } : {}}
        >
          {status.label}
        </span>
        <Badge variant="secondary" className="text-xs ml-1">
          {entries.length}
        </Badge>
      </div>
      <div className="bg-muted/40 rounded-b-md p-2 min-h-[120px]">
        {entries.length === 0 && (
          <p className="text-xs text-muted-foreground text-center py-4 italic">
            No candidates
          </p>
        )}
        {entries.map((entry) => (
          <CandidateCard
            key={entry.pipeline_id}
            entry={entry}
            statuses={allStatuses}
            jobOrderId={jobOrderId}
            onStatusChange={onStatusChange}
            onRating={onRating}
            onRemove={onRemove}
          />
        ))}
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function PipelineBoardPage() {
  const qc = useQueryClient();
  const [selectedJobId, setSelectedJobId] = useState<string>("");
  const [showAdd, setShowAdd] = useState(false);

  // Load job orders list for the picker
  const jobsQuery = useQuery({
    queryKey: ["ats-job-orders", "open"],
    queryFn: () => listOpenJobOrders({ limit: 100 }),
    retry: false,
  });

  // Load pipeline status config
  const statusQuery = useQuery({
    queryKey: ["ats-pipeline", "statuses"],
    queryFn: getPipelineStatuses,
    retry: false,
  });

  // Load pipeline entries for selected job
  const entriesQuery = useQuery({
    queryKey: ["ats-pipeline", "by-job", selectedJobId],
    queryFn: () => listPipelineByJob(selectedJobId, { limit: 200 }),
    enabled: !!selectedJobId,
    retry: false,
  });

  // Status change mutation
  const statusMut = useMutation({
    mutationFn: ({
      entry,
      newStatus,
      note,
    }: {
      entry: PipelineEntry;
      newStatus: string;
      note?: string;
    }) =>
      changePipelineStatus(entry.job_order_id, entry.candidate_id, {
        new_status: newStatus,
        note: note ?? null,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ats-pipeline", "by-job", selectedJobId] });
      toast.success("Stage updated");
    },
    onError: (err: unknown) => {
      const msg =
        err instanceof ApiError ? err.detail : "Failed to update stage";
      toast.error(msg);
    },
  });

  // Rating mutation
  const ratingMut = useMutation({
    mutationFn: ({
      entry,
      rating,
    }: {
      entry: PipelineEntry;
      rating: number;
    }) => setPipelineRating(entry.job_order_id, entry.candidate_id, { rating }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ats-pipeline", "by-job", selectedJobId] });
    },
    onError: (err: unknown) => {
      const msg = err instanceof ApiError ? err.detail : "Failed to set rating";
      toast.error(msg);
    },
  });

  // Remove mutation
  const removeMut = useMutation({
    mutationFn: (entry: PipelineEntry) =>
      removePipelineEntry(entry.job_order_id, entry.candidate_id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ats-pipeline", "by-job", selectedJobId] });
      toast.success("Candidate removed from pipeline");
    },
    onError: (err: unknown) => {
      const msg =
        err instanceof ApiError ? err.detail : "Failed to remove entry";
      toast.error(msg);
    },
  });

  // Feature not enabled check (503 from status endpoint)
  if (
    isNotEnabled(statusQuery.error) ||
    (statusQuery.isError &&
      (statusQuery.error as ApiError)?.status === 503)
  ) {
    return <PipelineNotEnabled />;
  }

  const statuses: PipelineStatusItem[] = statusQuery.data?.statuses ?? [];

  // Group entries by status
  const entriesByStatus = useMemo<Record<string, PipelineEntry[]>>(() => {
    const map: Record<string, PipelineEntry[]> = {};
    for (const s of statuses) {
      map[s.status_key] = [];
    }
    for (const entry of entriesQuery.data?.entries ?? []) {
      if (map[entry.status] !== undefined) {
        map[entry.status]!.push(entry);
      } else {
        // Unknown status — put in first column
        const firstKey = statuses[0]?.status_key;
        if (firstKey) {
          (map[firstKey] = map[firstKey] ?? []).push(entry);
        }
      }
    }
    return map;
  }, [statuses, entriesQuery.data]);

  const jobs: JobOrder[] = jobsQuery.data?.items ?? [];
  const selectedJob = jobs.find((j) => j.job_id === selectedJobId);

  return (
    <div className="p-6 space-y-4">
      <PageHeader
        title="Pipeline Board"
        description="Candidate progress board — advance candidates across recruiting stages"
      />

      {/* Job picker + controls */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-[280px]">
          <Select
            value={selectedJobId}
            onValueChange={(v) => {
              setSelectedJobId(v);
            }}
          >
            <SelectTrigger>
              <SelectValue placeholder="Select a job order to view pipeline…" />
            </SelectTrigger>
            <SelectContent>
              {jobsQuery.isLoading && (
                <SelectItem value="__loading__" disabled>
                  Loading jobs…
                </SelectItem>
              )}
              {jobs.map((j) => (
                <SelectItem key={j.job_id} value={j.job_id}>
                  {j.title} — {j.status}
                </SelectItem>
              ))}
              {!jobsQuery.isLoading && jobs.length === 0 && (
                <SelectItem value="__empty__" disabled>
                  No open job orders found
                </SelectItem>
              )}
            </SelectContent>
          </Select>
        </div>

        {selectedJobId && (
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                qc.invalidateQueries({
                  queryKey: ["ats-pipeline", "by-job", selectedJobId],
                })
              }
            >
              <RefreshCw className="h-3.5 w-3.5 mr-1" />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setShowAdd(true)}>
              <Plus className="h-3.5 w-3.5 mr-1" />
              Add Candidate
            </Button>
          </>
        )}

        {selectedJob && (
          <Link
            to={`/ats/jobs/${selectedJob.job_id}`}
            className="text-xs text-muted-foreground hover:text-primary underline-offset-2 hover:underline"
          >
            View job order
          </Link>
        )}
      </div>

      {/* Board area */}
      {!selectedJobId && (
        <Card>
          <CardContent className="py-16 text-center text-muted-foreground">
            <GitMerge className="h-10 w-10 mx-auto mb-3 opacity-30" />
            <p className="text-sm">Select a job order above to view its pipeline board.</p>
          </CardContent>
        </Card>
      )}

      {selectedJobId && statusQuery.isLoading && (
        <div className="flex gap-3">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-48 w-56" />
          ))}
        </div>
      )}

      {selectedJobId && !statusQuery.isLoading && statuses.length > 0 && (
        <>
          {entriesQuery.isLoading && (
            <div className="flex gap-3">
              {statuses.map((s) => (
                <Skeleton key={s.status_key} className="h-32 w-56" />
              ))}
            </div>
          )}

          {!entriesQuery.isLoading && (
            <div className="overflow-x-auto pb-4">
              <div className="flex gap-3 min-w-max">
                {statuses
                  .slice()
                  .sort((a, b) => a.order - b.order)
                  .map((status) => (
                    <KanbanColumn
                      key={status.status_key}
                      status={status}
                      entries={entriesByStatus[status.status_key] ?? []}
                      allStatuses={statuses}
                      jobOrderId={selectedJobId}
                      onStatusChange={(entry, newStatus) =>
                        statusMut.mutate({ entry, newStatus })
                      }
                      onRating={(entry, rating) => ratingMut.mutate({ entry, rating })}
                      onRemove={(entry) => removeMut.mutate(entry)}
                    />
                  ))}
              </div>
            </div>
          )}
        </>
      )}

      {/* Summary counts */}
      {selectedJobId && !entriesQuery.isLoading && entriesQuery.data && (
        <div className="text-xs text-muted-foreground">
          {entriesQuery.data.entries.length} candidate
          {entriesQuery.data.entries.length !== 1 ? "s" : ""} in pipeline
          {entriesQuery.data.cursor && " (more available — scroll or load more)"}
        </div>
      )}

      {/* Add candidate dialog */}
      {showAdd && selectedJobId && (
        <AddCandidateToPipelineDialog
          jobOrderId={selectedJobId}
          statuses={statuses}
          onClose={() => setShowAdd(false)}
          onAdded={() => {
            setShowAdd(false);
            qc.invalidateQueries({
              queryKey: ["ats-pipeline", "by-job", selectedJobId],
            });
          }}
        />
      )}
    </div>
  );
}
