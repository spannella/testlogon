import { ApiError } from "@/api/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle } from "lucide-react";

// ─── Formatting helpers ──────────────────────────────────────────────────────

export function fmtCents(cents?: number | null): string {
  const v = typeof cents === "number" ? cents : 0;
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: "USD",
  }).format(v / 100);
}

export function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export function fmtDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

export function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

// ─── Status badge ────────────────────────────────────────────────────────────

const STATUS_VARIANT: Record<
  string,
  "default" | "secondary" | "outline" | "destructive"
> = {
  draft: "outline",
  scheduled: "secondary",
  active: "default",
  paused: "secondary",
  completed: "secondary",
  archived: "destructive",
};

export function CampaignStatusBadge({ status }: { status: string }) {
  return <Badge variant={STATUS_VARIANT[status] ?? "outline"}>{status}</Badge>;
}

// ─── "Module not enabled" state ──────────────────────────────────────────────

export function isNotEnabledError(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 503);
}

export function NotEnabledCard({ what = "Marketing" }: { what?: string }) {
  return (
    <Card className="border-dashed">
      <CardHeader className="flex flex-row items-center gap-2">
        <AlertTriangle className="h-5 w-5 text-muted-foreground" />
        <CardTitle className="text-base">{what} module is not enabled</CardTitle>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">
        This feature is gated behind the{" "}
        <code className="rounded bg-muted px-1 py-0.5">MARKETING_CAMPAIGNS_ENABLED</code>{" "}
        backend flag, which is currently off. Ask an operator to enable it to manage
        campaigns, contact lists, segments and tracking codes.
      </CardContent>
    </Card>
  );
}

// ─── Empty state ─────────────────────────────────────────────────────────────

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-12 text-center">
      <p className="text-sm font-medium">{title}</p>
      {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

export function errMsg(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}
