/**
 * Shared helpers + small presentational components for the SuiteCRM Workflow
 * (WFL) cluster pages. Cluster-local; not imported by anything outside crmWorkflow/.
 */
import { AlertTriangle } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError } from "@/api/client";

export function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export function operatorLabel(op: string): string {
  switch (op) {
    case "eq":
      return "equals";
    case "neq":
      return "not equal";
    case "contains":
      return "contains";
    case "gt":
      return "greater than";
    case "lt":
      return "less than";
    case "is_empty":
      return "is empty";
    case "is_not_empty":
      return "is not empty";
    default:
      return op;
  }
}

export function actionTypeLabel(t: string): string {
  switch (t) {
    case "modify_field":
      return "Modify field";
    case "create_record":
      return "Create record";
    case "send_email":
      return "Send email";
    case "drip_sequence":
      return "Enroll in drip sequence";
    default:
      return t;
  }
}

export function triggerLabel(t: string): string {
  switch (t) {
    case "on_save":
      return "On save";
    case "on_schedule":
      return "On schedule";
    case "on_time_elapsed":
      return "On time elapsed";
    default:
      return t;
  }
}

export function moduleLabel(m: string): string {
  if (!m) return "—";
  return m.charAt(0).toUpperCase() + m.slice(1);
}

const VALUELESS_OPERATORS = new Set(["is_empty", "is_not_empty"]);

export function operatorNeedsValue(op: string): boolean {
  return !VALUELESS_OPERATORS.has(op);
}

export function OutcomeBadge({ outcome }: { outcome: string }) {
  const variant: "default" | "secondary" | "destructive" | "outline" =
    outcome === "matched"
      ? "default"
      : outcome === "error"
        ? "destructive"
        : "secondary";
  return <Badge variant={variant}>{outcome || "—"}</Badge>;
}

export function ActionResultBadge({ result }: { result: string }) {
  const isError = result.startsWith("error");
  const isSkip = result.startsWith("skipped");
  const variant: "default" | "secondary" | "destructive" = isError
    ? "destructive"
    : isSkip
      ? "secondary"
      : "default";
  return <Badge variant={variant}>{result}</Badge>;
}

/**
 * Renders a clear "feature not enabled" panel when the backend returns 404/503
 * (flag CRM_WORKFLOW_ENABLED is OFF by default).
 */
export function NotEnabledCard({
  error,
  title = "Workflow automation is not enabled",
}: {
  error: unknown;
  title?: string;
}) {
  const status = error instanceof ApiError ? error.status : undefined;
  const isFlagOff = status === 404 || status === 503;
  return (
    <Card className="border-amber-300/60">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-amber-600">
          <AlertTriangle className="h-5 w-5" />
          {isFlagOff ? title : "Unable to load workflows"}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm text-muted-foreground">
        {isFlagOff ? (
          <>
            <p>
              The CRM Workflow engine is currently disabled on this deployment.
              Ask an operator to set <code className="rounded bg-muted px-1">CRM_WORKFLOW_ENABLED=1</code>{" "}
              to use workflow rules, drip sequences, and run history.
            </p>
          </>
        ) : (
          <p>
            {error instanceof Error
              ? error.message
              : "An unexpected error occurred while contacting the workflow service."}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

/** True when the error is a flag-off (404/503) — used to suppress retries. */
export function isFlagOffError(error: unknown): boolean {
  if (!(error instanceof ApiError)) return false;
  return error.status === 404 || error.status === 503;
}
