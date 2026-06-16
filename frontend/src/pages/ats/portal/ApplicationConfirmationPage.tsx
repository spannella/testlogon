/**
 * Public career portal — application confirmation page.
 * Route: /ats/portal/confirmation/:applicationId  (public, no auth required)
 *
 * Shown after a successful application submission.
 * Accepts state from JobDetailPage navigation (jobTitle, firstName, applicationId).
 * Falls back gracefully when navigated to directly.
 */

import { useLocation, useParams, Link } from "react-router-dom";
import { CheckCircle2, Briefcase } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

interface ConfirmationState {
  jobTitle?: string;
  applicationId?: string;
  firstName?: string;
}

export default function ApplicationConfirmationPage() {
  const { applicationId } = useParams<{ applicationId: string }>();
  const location = useLocation();
  const state = (location.state ?? {}) as ConfirmationState;

  const jobTitle = state.jobTitle ?? "this position";
  const displayId = state.applicationId ?? applicationId ?? "";
  const firstName = state.firstName;

  return (
    <div className="max-w-lg mx-auto px-4 py-16 flex flex-col items-center gap-8">
      <div className="flex flex-col items-center gap-3 text-center">
        <div className="rounded-full bg-green-100 dark:bg-green-900/30 p-4">
          <CheckCircle2 className="h-12 w-12 text-green-600 dark:text-green-400" />
        </div>
        <h1 className="text-2xl font-bold tracking-tight">
          Application Received!
        </h1>
        <p className="text-muted-foreground text-sm leading-relaxed">
          {firstName ? `Thank you, ${firstName}! Your application` : "Your application"} for{" "}
          <span className="font-medium text-foreground">{jobTitle}</span> has
          been submitted successfully. We&apos;ll be in touch if your
          qualifications match what we&apos;re looking for.
        </p>
      </div>

      {displayId && (
        <Card className="w-full">
          <CardContent className="pt-4 pb-4">
            <div className="flex flex-col gap-1">
              <p className="text-xs text-muted-foreground">Application reference</p>
              <p className="font-mono text-sm select-all break-all">{displayId}</p>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="flex flex-col sm:flex-row gap-3 w-full">
        <Button asChild variant="default" className="flex-1">
          <Link to="/ats/portal/jobs">
            <Briefcase className="h-4 w-4 mr-2" />
            View More Positions
          </Link>
        </Button>
        <Button asChild variant="outline" className="flex-1">
          <Link to="/">Back to Home</Link>
        </Button>
      </div>
    </div>
  );
}
