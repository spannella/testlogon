import { Badge, type BadgeProps } from "@/components/ui/badge";
import { prettyStatus } from "@/api/endpoints/orderLifecycle";

// Map each lifecycle (and legacy mirror) status to a badge variant.
const VARIANT_BY_STATUS: Record<string, BadgeProps["variant"]> = {
  // lifecycle statuses
  created: "secondary",
  approved: "default",
  allocated: "default",
  picking: "default",
  packed: "default",
  shipped: "default",
  completed: "success",
  held: "warning",
  backorder: "warning",
  cancelled: "destructive",
  returned: "destructive",
  // legacy mirror statuses (status field)
  pending_payment: "secondary",
  processing: "default",
  on_hold: "warning",
  backordered: "warning",
};

export function OrderStatusBadge({
  status,
  className,
}: {
  status: string | null | undefined;
  className?: string;
}) {
  const key = (status ?? "").toLowerCase();
  const variant = VARIANT_BY_STATUS[key] ?? "outline";
  return (
    <Badge variant={variant} className={className}>
      {prettyStatus(status)}
    </Badge>
  );
}
