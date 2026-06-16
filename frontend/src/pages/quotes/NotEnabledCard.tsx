import { FileWarning } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

export function NotEnabledCard({ feature }: { feature: string }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
        <FileWarning className="h-10 w-10 text-muted-foreground" />
        <div className="text-lg font-medium">{feature} is not enabled</div>
        <p className="max-w-md text-sm text-muted-foreground">
          This feature is currently disabled on the platform. An administrator can
          enable it in the platform settings. Once enabled, your quotes and
          contracts will appear here.
        </p>
      </CardContent>
    </Card>
  );
}
