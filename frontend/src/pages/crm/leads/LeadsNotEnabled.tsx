import { Target } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

export function LeadsNotEnabled() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
        <Target className="h-10 w-10 text-muted-foreground" />
        <div className="space-y-1">
          <p className="text-lg font-semibold">Leads module not enabled</p>
          <p className="max-w-md text-sm text-muted-foreground">
            The SuiteCRM Leads module is currently turned off. An administrator must enable
            the <code className="rounded bg-muted px-1 py-0.5 text-xs">LEADS_ENABLED</code> feature
            flag before lead management is available.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
