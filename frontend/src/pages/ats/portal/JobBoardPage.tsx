/**
 * Public career portal — job board listing page.
 * Route: /ats/portal/jobs  (public, no auth required)
 *
 * Displays a paginated list of open job postings from the public
 * /public/careers/jobs endpoint. Works even without a logged-in session.
 *
 * Feature flag: when CAREER_PORTAL_ENABLED=0 the backend returns 404;
 * we show a friendly "Job board not available" state instead of an error.
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Briefcase, MapPin, Clock, ChevronRight, AlertCircle, Loader2, Users } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

import {
  getPublicPortalConfig,
  listPublicJobs,
  isCareerPortalNotEnabled,
  type CareerJobSummaryOut,
} from "@/api/endpoints/careerPortal";

// ─── Helpers ─────────────────────────────────────────────────────

function formatEmploymentType(t: string | null): string {
  if (!t) return "";
  return {
    full_time: "Full-time",
    part_time: "Part-time",
    contract: "Contract",
    temp: "Temporary",
    referral: "Referral",
  }[t] ?? t;
}

function formatPostedAt(ts: number): string {
  if (!ts) return "";
  const diff = Math.floor((Date.now() - ts * 1000) / 1000);
  if (diff < 60) return "Just posted";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 86400 * 30) return `${Math.floor(diff / 86400)}d ago`;
  return new Date(ts * 1000).toLocaleDateString();
}

// ─── Job card ────────────────────────────────────────────────────

function JobCard({ job }: { job: CareerJobSummaryOut }) {
  const empType = formatEmploymentType(job.employment_type);
  return (
    <Card className="hover:shadow-md transition-shadow">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <CardTitle className="text-base font-semibold leading-tight">
              <Link
                to={`/ats/portal/jobs/${job.slug}`}
                className="hover:underline text-primary"
              >
                {job.title}
              </Link>
            </CardTitle>
            <div className="flex flex-wrap gap-2 mt-1.5">
              {job.location && (
                <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                  <MapPin className="h-3 w-3" />
                  {job.location}
                </span>
              )}
              {empType && (
                <Badge variant="secondary" className="text-xs px-2 py-0.5">
                  {empType}
                </Badge>
              )}
              {job.openings > 1 && (
                <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                  <Users className="h-3 w-3" />
                  {job.openings} openings
                </span>
              )}
            </div>
          </div>
          <ChevronRight className="h-4 w-4 text-muted-foreground mt-1 shrink-0" />
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground inline-flex items-center gap-1">
            <Clock className="h-3 w-3" />
            {formatPostedAt(job.posted_at)}
          </span>
          <Button asChild size="sm" variant="outline">
            <Link to={`/ats/portal/jobs/${job.slug}`}>View &amp; Apply</Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Page ─────────────────────────────────────────────────────────

export default function JobBoardPage() {
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [cursorStack, setCursorStack] = useState<string[]>([]);

  const configQuery = useQuery({
    queryKey: ["career-portal", "config"],
    queryFn: getPublicPortalConfig,
    retry: (count, err) => !isCareerPortalNotEnabled(err) && count < 2,
    staleTime: 5 * 60 * 1000,
  });

  const jobsQuery = useQuery({
    queryKey: ["career-portal", "jobs", cursor],
    queryFn: () => listPublicJobs({ limit: 25, cursor }),
    retry: (count, err) => !isCareerPortalNotEnabled(err) && count < 2,
    staleTime: 60_000,
  });

  const isDisabled =
    isCareerPortalNotEnabled(configQuery.error) ||
    isCareerPortalNotEnabled(jobsQuery.error);

  const config = configQuery.data;
  const listing = jobsQuery.data;

  if (isDisabled) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center gap-4 px-4">
        <Briefcase className="h-12 w-12 text-muted-foreground/40" />
        <div>
          <h2 className="text-xl font-semibold">Job Board Not Available</h2>
          <p className="text-sm text-muted-foreground mt-1">
            The public career portal is not currently enabled.
          </p>
        </div>
      </div>
    );
  }

  const isLoading = configQuery.isLoading || jobsQuery.isLoading;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (jobsQuery.isError && !isDisabled) {
    return (
      <div className="flex flex-col items-center justify-center py-24 gap-3">
        <AlertCircle className="h-8 w-8 text-destructive" />
        <p className="text-sm text-muted-foreground">
          {(jobsQuery.error as Error)?.message ?? "Failed to load jobs."}
        </p>
        <Button variant="outline" onClick={() => void jobsQuery.refetch()}>
          Retry
        </Button>
      </div>
    );
  }

  const jobs = listing?.items ?? [];

  const handleNextPage = () => {
    if (!listing?.cursor) return;
    setCursorStack((s) => [...s, cursor ?? ""]);
    setCursor(listing.cursor ?? undefined);
  };

  const handlePrevPage = () => {
    const prev = cursorStack[cursorStack.length - 1];
    setCursorStack((s) => s.slice(0, -1));
    setCursor(prev || undefined);
  };

  return (
    <div className="max-w-3xl mx-auto px-4 py-10 space-y-8">
      {/* Portal header */}
      <div className="space-y-2">
        {config?.logo_url && (
          <img
            src={config.logo_url}
            alt={config.portal_name}
            className="h-12 w-auto mb-2"
          />
        )}
        <h1 className="text-3xl font-bold tracking-tight">
          {config?.portal_name ?? "Open Positions"}
        </h1>
        {config?.intro_copy && (
          <p className="text-muted-foreground text-sm leading-relaxed">
            {config.intro_copy}
          </p>
        )}
      </div>

      {/* Job list */}
      {jobs.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 gap-3 border rounded-lg">
          <Briefcase className="h-10 w-10 text-muted-foreground/40" />
          <p className="text-sm text-muted-foreground">No open positions at this time.</p>
          {config?.support_email && (
            <p className="text-xs text-muted-foreground">
              Questions?{" "}
              <a href={`mailto:${config.support_email}`} className="underline">
                {config.support_email}
              </a>
            </p>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {jobs.map((job) => (
            <JobCard key={job.job_order_id} job={job} />
          ))}
        </div>
      )}

      {/* Pagination */}
      {(cursorStack.length > 0 || listing?.cursor) && (
        <div className="flex justify-between items-center pt-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handlePrevPage}
            disabled={cursorStack.length === 0}
          >
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleNextPage}
            disabled={!listing?.cursor}
          >
            Next
          </Button>
        </div>
      )}
    </div>
  );
}
