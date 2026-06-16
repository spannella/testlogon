import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Target } from "lucide-react";

export function FeatureDisabledState({
  title = "Sales Pipeline not enabled",
  message = "The opportunities & sales pipeline feature is currently disabled for this workspace. Ask an administrator to enable it.",
}: {
  title?: string;
  message?: string;
}) {
  return (
    <Card className="mx-auto max-w-lg">
      <CardHeader className="flex flex-row items-center gap-3">
        <Target className="h-6 w-6 text-muted-foreground" />
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">{message}</p>
      </CardContent>
    </Card>
  );
}
