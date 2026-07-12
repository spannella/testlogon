import { MailWarning } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

/**
 * Rendered when the marketing-campaigns / email feature flag is OFF
 * (backend returns 404/503). Shared by the SuiteCRM email pages.
 */
export function NotEnabledState({ feature }: { feature?: string }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
        <MailWarning className="h-10 w-10 text-muted-foreground" />
        <div className="space-y-1">
          <p className="text-base font-medium">
            {feature ?? "Email marketing"} is not enabled
          </p>
          <p className="max-w-md text-sm text-muted-foreground">
            This feature is currently disabled for your workspace. Ask an
            administrator to enable the CRM marketing campaigns feature flag to
            start building email templates and campaigns.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

/** True when an error from the API means "feature flag OFF". */
export function isNotEnabledError(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "status" in err &&
    ((err as { status?: number }).status === 404 ||
      (err as { status?: number }).status === 503)
  );
}
