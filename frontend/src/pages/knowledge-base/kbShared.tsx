// Shared helpers for the SuiteCRM Knowledge Base (KB) cluster.
// Self-contained — does NOT import from sibling clusters (shared-tree safety).

import { ApiError } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { KbArticleStatus } from "@/api/endpoints/knowledgeBase";

/** A flag-gated KB endpoint returns 404 (off) or 503 (provider disabled). */
export function isNotEnabledError(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 503);
}

export function errMessage(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

/** Unix-seconds timestamp → locale string ("—" when missing). */
export function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

/** Unix-seconds timestamp → date-only string ("—" when missing). */
export function fmtDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

/** Card shown when the KB feature flag is disabled on the platform. */
export function KbNotEnabledCard() {
  return (
    <Card className="border-dashed">
      <CardHeader>
        <CardTitle className="text-base">Knowledge Base is not enabled</CardTitle>
        <CardDescription>
          The Knowledge Base is gated behind a backend feature flag and is
          currently disabled on this platform.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">
          Ask an operator to set{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-xs">
            KNOWLEDGE_BASE_ENABLED=true
          </code>{" "}
          and restart the backend to enable the knowledge base.
        </p>
      </CardContent>
    </Card>
  );
}

const STATUS_VARIANT: Record<KbArticleStatus, "default" | "secondary" | "outline"> = {
  published: "default",
  draft: "secondary",
  expired: "outline",
};

const STATUS_LABEL: Record<KbArticleStatus, string> = {
  published: "Published",
  draft: "Draft",
  expired: "Expired",
};

export function StatusBadge({ status }: { status: KbArticleStatus }) {
  const variant = STATUS_VARIANT[status] ?? "secondary";
  const label = STATUS_LABEL[status] ?? status;
  return <Badge variant={variant}>{label}</Badge>;
}
