// Shared helpers for the OFBiz Core ERP admin cluster (OFB).
// Self-contained — does NOT import from sibling clusters (shared-tree safety).

import { ApiError } from "@/api/client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

/** A flag-gated ERP endpoint returns 404 (off) or 503 (provider disabled). */
export function isNotEnabledError(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 503);
}

export function errMessage(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

/** Card shown when a flag-gated ERP module is disabled on the platform. */
export function NotEnabledCard({
  module,
  flag,
}: {
  module: string;
  flag: string;
}) {
  return (
    <Card className="border-dashed">
      <CardHeader>
        <CardTitle className="text-base">{module} is not enabled</CardTitle>
        <CardDescription>
          This module is gated behind a backend feature flag and is currently
          disabled on this platform.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">
          Ask an operator to set{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-xs">{flag}=true</code>{" "}
          and restart the backend to enable {module.toLowerCase()}.
        </p>
      </CardContent>
    </Card>
  );
}

/** Unix-seconds timestamp → locale string ("—" when missing). */
export function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}
