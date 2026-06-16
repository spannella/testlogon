/**
 * Shown when the ATS pipeline feature flag is off (ATS_PIPELINE_ENABLED=false).
 * Backend returns 503 {code: "ats_pipeline_disabled"} or the router is not
 * mounted at all (404). Either case renders this component.
 */
import { GitMerge } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

export function PipelineNotEnabled() {
  return (
    <div className="flex items-center justify-center min-h-[40vh] p-8">
      <Card className="max-w-md w-full text-center">
        <CardContent className="pt-10 pb-10 flex flex-col items-center gap-4">
          <GitMerge className="h-12 w-12 text-muted-foreground opacity-40" />
          <div>
            <h2 className="text-lg font-semibold mb-1">Pipeline Not Enabled</h2>
            <p className="text-sm text-muted-foreground">
              The ATS recruiting pipeline feature is not enabled on this deployment.
              Contact your administrator to enable <code>ATS_PIPELINE_ENABLED</code>.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
