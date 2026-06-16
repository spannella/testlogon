import { ApiError } from "@/api/client";
import { Card, CardContent } from "@/components/ui/card";
import { PackageX } from "lucide-react";

/** Integer cents → "$1,234.56". */
export function formatCents(cents?: number | null): string {
  const v = typeof cents === "number" ? cents : 0;
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: "USD",
  }).format(v / 100);
}

/** Unix seconds → locale string. */
export function formatTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

/** True when an error indicates the FAC backend flag is OFF (404/503). */
export function isFeatureDisabled(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 503);
}

/** React Query retry predicate: never retry a disabled-feature error. */
export function retryUnlessDisabled(failureCount: number, err: unknown): boolean {
  if (isFeatureDisabled(err)) return false;
  return failureCount < 2;
}

/** Rendered when the FAC cluster flag is off (endpoints return 404/503). */
export function FeatureDisabledCard({
  feature = "Facility & Fulfillment",
}: {
  feature?: string;
}) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
        <PackageX className="h-10 w-10 text-muted-foreground" />
        <div className="space-y-1">
          <p className="text-base font-medium">{feature} is not enabled</p>
          <p className="max-w-md text-sm text-muted-foreground">
            This feature is gated behind the{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">
              FACILITY_FULFILLMENT_ENABLED
            </code>{" "}
            backend flag. Ask a platform operator to enable it for your
            environment.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

const STATUS_STYLES: Record<string, string> = {
  active: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
  archived: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  requested: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  in_transit: "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300",
  completed: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
  cancelled: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  pending: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  picking: "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300",
  picked: "bg-indigo-100 text-indigo-800 dark:bg-indigo-950 dark:text-indigo-300",
  packed: "bg-violet-100 text-violet-800 dark:bg-violet-950 dark:text-violet-300",
  shipped: "bg-cyan-100 text-cyan-800 dark:bg-cyan-950 dark:text-cyan-300",
  delivered: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
  received: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
  partial: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  over: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
  draft: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
};

export function statusBadgeClass(status?: string | null): string {
  return STATUS_STYLES[status ?? ""] ?? "bg-muted text-muted-foreground";
}
