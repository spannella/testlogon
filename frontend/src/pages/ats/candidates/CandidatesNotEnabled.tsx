import { Users } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

export function CandidatesNotEnabled() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
        <Users className="h-10 w-10 text-muted-foreground" />
        <div className="space-y-1">
          <p className="text-lg font-semibold">Candidates module not enabled</p>
          <p className="max-w-md text-sm text-muted-foreground">
            The ATS Candidates module is currently turned off. An administrator must enable
            the{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">CANDIDATES_ENABLED</code>{" "}
            feature flag before candidate management is available.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
