import { CalendarOff } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

interface Props {
  title?: string;
  message?: string;
}

export function EventsFeatureDisabled({ title, message }: Props) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
        <div className="flex h-16 w-16 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <CalendarOff className="h-7 w-7" />
        </div>
        <h3 className="text-lg font-semibold">{title ?? "Events not enabled"}</h3>
        <p className="max-w-sm text-sm text-muted-foreground">
          {message ??
            "The SuiteCRM Events feature is currently disabled. Ask an administrator to enable CRM_EVENTS_ENABLED."}
        </p>
      </CardContent>
    </Card>
  );
}
