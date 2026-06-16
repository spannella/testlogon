import { Badge } from "@/components/ui/badge";

type BadgeVariant = "default" | "secondary" | "destructive" | "success" | "warning" | "outline";

const PO_STATUS_VARIANT: Record<string, BadgeVariant> = {
  draft: "secondary",
  submitted: "warning",
  approved: "default",
  ordered: "default",
  partially_received: "warning",
  received: "success",
  closed: "success",
  rejected: "destructive",
  cancelled: "destructive",
};

export function PoStatusBadge({ status }: { status: string }) {
  const variant = PO_STATUS_VARIANT[status] ?? "outline";
  const label = status.replace(/_/g, " ");
  return (
    <Badge variant={variant} className="capitalize whitespace-nowrap">
      {label}
    </Badge>
  );
}

export function SupplierStatusBadge({ status }: { status: string }) {
  return (
    <Badge variant={status === "active" ? "success" : "secondary"} className="capitalize">
      {status}
    </Badge>
  );
}

export function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}
