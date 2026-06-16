import { Building2 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * Shown when a Party-CRM feature flag is OFF (backend returns 503 / 404).
 * The CCT routers are gated on party_crm_enabled / party_crm_org_accounts_enabled
 * which default OFF.
 */
export function NotEnabledCard({
  feature,
  detail,
}: {
  feature: string;
  detail?: string;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Building2 className="h-5 w-5 text-muted-foreground" />
          {feature} is not enabled
        </CardTitle>
        <CardDescription>
          This Party-CRM feature is gated behind a feature flag that is currently off.
          Ask a platform operator to enable it.
        </CardDescription>
      </CardHeader>
      {detail && (
        <CardContent>
          <p className="text-sm text-muted-foreground">{detail}</p>
        </CardContent>
      )}
    </Card>
  );
}

/** True when an error is an ApiError-style 503/404 "feature off" response. */
export function isFeatureOff(err: unknown): boolean {
  const status = (err as { status?: number } | null)?.status;
  return status === 503 || status === 404;
}
