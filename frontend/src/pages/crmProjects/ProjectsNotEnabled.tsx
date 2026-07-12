import { FolderKanban } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

export function ProjectsNotEnabled() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
        <FolderKanban className="h-10 w-10 text-muted-foreground" />
        <div>
          <p className="text-lg font-medium">CRM Projects is not enabled</p>
          <p className="mx-auto mt-1 max-w-md text-sm text-muted-foreground">
            This feature is gated behind a backend feature flag that is currently
            turned off. Ask an administrator to enable CRM Projects to manage
            projects, tasks, milestones, and team assignments.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
