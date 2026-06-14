import { BarChart3 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * Rendered when the `crm_reports_enabled` backend flag is OFF and the RPT
 * endpoints return 404/503. Gives the operator a clear, non-error state.
 */
export function ReportsNotEnabled({ feature = "Reports & Dashboards" }: { feature?: string }) {
  return (
    <Card className="mx-auto max-w-xl">
      <CardHeader className="items-center text-center">
        <div className="mb-2 flex h-12 w-12 items-center justify-center rounded-full bg-muted">
          <BarChart3 className="h-6 w-6 text-muted-foreground" />
        </div>
        <CardTitle>{feature} are not enabled</CardTitle>
        <CardDescription>
          This workspace does not have the CRM reporting module turned on.
        </CardDescription>
      </CardHeader>
      <CardContent className="text-center text-sm text-muted-foreground">
        Ask a platform administrator to enable the <code>CRM_REPORTS_ENABLED</code> feature
        flag to build custom reports, charts, and dashboards.
      </CardContent>
    </Card>
  );
}
