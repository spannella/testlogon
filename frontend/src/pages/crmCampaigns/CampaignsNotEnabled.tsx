import { Megaphone } from "lucide-react";
import { ApiError } from "@/api/client";
import { Card, CardContent } from "@/components/ui/card";

/** True when an error indicates the feature flag is off (404 / 503). */
export function isCampaignsDisabled(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 503);
}

export function CampaignsNotEnabled({
  feature = "Marketing campaigns",
  status,
}: {
  feature?: string;
  status?: number;
}) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
        <Megaphone className="h-10 w-10 text-muted-foreground" />
        <h2 className="text-lg font-semibold">{feature} is not enabled</h2>
        <p className="max-w-md text-sm text-muted-foreground">
          {status === 403
            ? "You don't have permission to access this area. Ask an admin or root operator for access."
            : "This feature is turned off for your environment. An administrator can enable it by setting the relevant feature flag (e.g. CRM_CAMPAIGNS_ENABLED)."}
        </p>
      </CardContent>
    </Card>
  );
}
