import { Badge } from "@/components/ui/badge";

export function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

const WO_VARIANTS: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  draft: "outline",
  released: "secondary",
  in_progress: "default",
  completed: "default",
  cancelled: "destructive",
  active: "default",
  inactive: "outline",
};

export function StatusBadge({ status }: { status: string }) {
  const variant = WO_VARIANTS[status] ?? "secondary";
  return <Badge variant={variant}>{status.replace(/_/g, " ")}</Badge>;
}

/** True if the manufacturing feature flag is off (router 404s on every call). */
export function isFeatureDisabled(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "status" in err &&
    (err as { status?: number }).status === 404
  );
}
