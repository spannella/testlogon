/**
 * ATS Candidate Pipeline — PIP-001, PIP-003, PIP-004.
 *
 * Route: /ats/pipeline/candidate/:candidateId
 *
 * Shows all job orders a candidate is in (across the pipeline),
 * with current stage, rating, and quick-advance controls.
 */
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  GitMerge,
  ArrowLeft,
  ChevronRight,
  ChevronLeft,
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import {
  listPipelineByCandidate,
  getPipelineStatuses,
  changePipelineStatus,
  setPipelineRating,
  type PipelineEntry,
  type PipelineStatusItem,
} from "@/api/endpoints/atsPipeline";
import { PipelineNotEnabled } from "./PipelineNotEnabled";
import { statusBadgeClass, fmtTs, isNotEnabled } from "./pipelineUtils";

// ─── Row ─────────────────────────────────────────────────────────────────────

function PipelineRow({
  entry,
  statuses,
  onStatusChange,
  onRating,
}: {
  entry: PipelineEntry;
  statuses: PipelineStatusItem[];
  onStatusChange: (ns: string) => void;
  onRating: (r: number) => void;
}) {
  const cfg = statuses.find((s) => s.status_key === entry.status);
  const currentIdx = statuses.findIndex((s) => s.status_key === entry.status);
  const prev = currentIdx > 0 ? statuses[currentIdx - 1] : null;
  const next =
    currentIdx >= 0 && currentIdx < statuses.length - 1
      ? statuses[currentIdx + 1]
      : null;

  return (
    <TableRow>
      <TableCell className="font-mono text-xs">
        <Link
          to={`/ats/jobs/${entry.job_order_id}`}
          className="text-primary hover:underline flex items-center gap-1"
        >
          {entry.job_order_id.slice(0, 12)}…
        </Link>
      </TableCell>
      <TableCell>
        <Badge
          className={`text-xs ${statusBadgeClass(entry.status, cfg)}`}
          style={
            cfg?.color
              ? { backgroundColor: cfg.color + "22", color: cfg.color }
              : {}
          }
        >
          {cfg?.label ?? entry.status}
        </Badge>
      </TableCell>
      <TableCell>
        <div className="flex gap-0.5">
          {[1, 2, 3, 4, 5].map((star) => (
            <button
              key={star}
              onClick={() => onRating(entry.rating === star ? 0 : star)}
              className={`text-sm ${
                star <= entry.rating
                  ? "text-amber-400"
                  : "text-muted-foreground"
              }`}
            >
              ★
            </button>
          ))}
        </div>
      </TableCell>
      <TableCell className="text-xs text-muted-foreground">
        {fmtTs(entry.updated_at)}
      </TableCell>
      <TableCell>
        <div className="flex gap-1">
          {prev && (
            <Button
              variant="outline"
              size="icon"
              className="h-6 w-6"
              title={`Back to ${prev.label}`}
              onClick={() => onStatusChange(prev.status_key)}
            >
              <ChevronLeft className="h-3 w-3" />
            </Button>
          )}
          {next && (
            <Button
              size="sm"
              variant="outline"
              className="h-6 text-xs px-1.5"
              title={`Advance to ${next.label}`}
              onClick={() => onStatusChange(next.status_key)}
            >
              <ChevronRight className="h-3 w-3 mr-0.5" />
              {next.label}
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            className="h-6 text-xs px-1.5"
            asChild
          >
            <Link
              to={`/ats/pipeline/detail/${entry.job_order_id}/${entry.candidate_id}`}
            >
              Detail
            </Link>
          </Button>
        </div>
      </TableCell>
    </TableRow>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function CandidatePipelinePage() {
  const { candidateId = "" } = useParams<{ candidateId: string }>();
  const qc = useQueryClient();

  const statusQuery = useQuery({
    queryKey: ["ats-pipeline", "statuses"],
    queryFn: getPipelineStatuses,
    retry: false,
  });

  const entriesQuery = useQuery({
    queryKey: ["ats-pipeline", "by-candidate", candidateId],
    queryFn: () => listPipelineByCandidate(candidateId, { limit: 100 }),
    enabled: !!candidateId,
    retry: false,
  });

  const statusMut = useMutation({
    mutationFn: ({
      entry,
      ns,
    }: {
      entry: PipelineEntry;
      ns: string;
    }) =>
      changePipelineStatus(entry.job_order_id, entry.candidate_id, {
        new_status: ns,
      }),
    onSuccess: (_, vars) => {
      qc.invalidateQueries({
        queryKey: ["ats-pipeline", "by-candidate", candidateId],
      });
      qc.invalidateQueries({
        queryKey: ["ats-pipeline", "by-job", vars.entry.job_order_id],
      });
      toast.success("Stage updated");
    },
    onError: (err: unknown) => {
      toast.error(err instanceof ApiError ? err.detail : "Failed to update stage");
    },
  });

  const ratingMut = useMutation({
    mutationFn: ({
      entry,
      rating,
    }: {
      entry: PipelineEntry;
      rating: number;
    }) => setPipelineRating(entry.job_order_id, entry.candidate_id, { rating }),
    onSuccess: (_, vars) => {
      qc.invalidateQueries({
        queryKey: ["ats-pipeline", "by-candidate", candidateId],
      });
      qc.invalidateQueries({
        queryKey: ["ats-pipeline", "by-job", vars.entry.job_order_id],
      });
    },
    onError: (err: unknown) => {
      toast.error(err instanceof ApiError ? err.detail : "Failed to set rating");
    },
  });

  if (isNotEnabled(statusQuery.error)) {
    return <PipelineNotEnabled />;
  }

  const statuses = statusQuery.data?.statuses ?? [];
  const entries = entriesQuery.data?.entries ?? [];
  const isLoading = statusQuery.isLoading || entriesQuery.isLoading;

  return (
    <div className="p-6 space-y-5 max-w-4xl">
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" asChild>
          <Link to={`/ats/candidates/${candidateId}`}>
            <ArrowLeft className="h-4 w-4 mr-1" />
            Back to Candidate
          </Link>
        </Button>
      </div>

      <PageHeader
        title="Candidate Pipeline"
        description={`All job orders for candidate ${candidateId}`}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Active Pipeline Entries</CardTitle>
          <CardDescription>
            Each row is a job order this candidate is actively being considered for.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading && (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          )}

          {!isLoading && entries.length === 0 && (
            <div className="text-center py-8 text-muted-foreground">
              <GitMerge className="h-8 w-8 mx-auto mb-2 opacity-30" />
              <p className="text-sm">
                This candidate is not in any pipeline yet.
              </p>
            </div>
          )}

          {!isLoading && entries.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Job Order</TableHead>
                  <TableHead>Stage</TableHead>
                  <TableHead>Rating</TableHead>
                  <TableHead>Last Updated</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((entry) => (
                  <PipelineRow
                    key={entry.pipeline_id}
                    entry={entry}
                    statuses={statuses}
                    onStatusChange={(ns) =>
                      statusMut.mutate({ entry, ns })
                    }
                    onRating={(r) => ratingMut.mutate({ entry, rating: r })}
                  />
                ))}
              </TableBody>
            </Table>
          )}

          {entriesQuery.data?.cursor && (
            <p className="text-xs text-muted-foreground mt-2">
              More entries available — pagination not yet implemented.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
