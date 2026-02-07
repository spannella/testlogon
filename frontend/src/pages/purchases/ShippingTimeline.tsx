import { Check, Clock, Package, Truck, XCircle, RotateCcw } from "lucide-react";
import { cn } from "@/lib/utils";

type StepStatus = "complete" | "current" | "upcoming" | "skipped";

interface Step {
  label: string;
  icon: React.ReactNode;
  status: StepStatus;
  date?: string;
}

function formatTs(ts?: number): string | undefined {
  if (!ts) return undefined;
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

interface ShippingTimelineProps {
  txnStatus: string;
  createdAt: number;
  shippedAt?: number;
  deliveredAt?: number;
  completedAt?: number;
  revertedAt?: number;
  cancelledAt?: number;
}

function resolveStep(
  label: string,
  icon: React.ReactNode,
  isComplete: boolean,
  isCurrent: boolean,
  date?: string,
): Step {
  if (isComplete) return { label, icon, status: "complete", date };
  if (isCurrent) return { label, icon, status: "current", date };
  return { label, icon, status: "upcoming" };
}

export function ShippingTimeline({
  txnStatus,
  createdAt,
  shippedAt,
  deliveredAt,
  completedAt,
  revertedAt,
  cancelledAt,
}: ShippingTimelineProps) {
  const isCancelled = txnStatus === "CANCELLED" || txnStatus === "CANCEL_REQUESTED";
  const isReverted = txnStatus === "REVERTED";
  const isCompleted = txnStatus === "COMPLETED" || txnStatus === "CANCEL_DENIED";

  const steps: Step[] = [];

  // Step 1: Created (always complete)
  steps.push({
    label: "Ordered",
    icon: <Package className="h-4 w-4" />,
    status: "complete",
    date: formatTs(createdAt),
  });

  // Step 2: Shipped
  steps.push(
    resolveStep(
      "Shipped",
      <Truck className="h-4 w-4" />,
      !!shippedAt,
      !shippedAt && !isCancelled && !isReverted && txnStatus === "PENDING",
      formatTs(shippedAt),
    ),
  );

  // Step 3: Delivered
  steps.push(
    resolveStep(
      "Delivered",
      <Check className="h-4 w-4" />,
      !!deliveredAt,
      !!shippedAt && !deliveredAt && !isCancelled && !isReverted,
      formatTs(deliveredAt),
    ),
  );

  // Step 4: Completed — or branching for cancelled/reverted
  if (isCancelled) {
    steps.push({
      label: txnStatus === "CANCEL_REQUESTED" ? "Cancel Pending" : "Cancelled",
      icon: <XCircle className="h-4 w-4" />,
      status: "current",
      date: formatTs(cancelledAt),
    });
  } else if (isReverted) {
    steps.push({
      label: "Reverted",
      icon: <RotateCcw className="h-4 w-4" />,
      status: "current",
      date: formatTs(revertedAt),
    });
  } else {
    steps.push(
      resolveStep(
        "Completed",
        <Check className="h-4 w-4" />,
        isCompleted,
        false,
        formatTs(completedAt),
      ),
    );
  }

  return (
    <div className="flex items-start gap-0">
      {steps.map((step, i) => (
        <div key={step.label} className="flex flex-1 flex-col items-center">
          {/* Connector + Circle row */}
          <div className="flex w-full items-center">
            {/* Left connector */}
            {i > 0 ? (
              <div
                className={cn(
                  "h-0.5 flex-1",
                  step.status === "complete" || step.status === "current"
                    ? "bg-primary"
                    : "bg-muted",
                )}
              />
            ) : (
              <div className="flex-1" />
            )}

            {/* Circle */}
            <div
              className={cn(
                "flex h-9 w-9 shrink-0 items-center justify-center rounded-full border-2 transition-colors",
                step.status === "complete" && "border-primary bg-primary text-primary-foreground",
                step.status === "current" && isCancelled && "border-destructive bg-destructive/10 text-destructive",
                step.status === "current" && isReverted && "border-orange-500 bg-orange-50 text-orange-600 dark:bg-orange-950 dark:text-orange-400",
                step.status === "current" && !isCancelled && !isReverted && "border-primary bg-primary/10 text-primary",
                step.status === "upcoming" && "border-muted bg-muted text-muted-foreground",
              )}
            >
              {step.status === "upcoming" ? (
                <Clock className="h-4 w-4" />
              ) : (
                step.icon
              )}
            </div>

            {/* Right connector */}
            {i < steps.length - 1 ? (
              <div
                className={cn(
                  "h-0.5 flex-1",
                  steps[i + 1]!.status === "complete" || steps[i + 1]!.status === "current"
                    ? "bg-primary"
                    : "bg-muted",
                )}
              />
            ) : (
              <div className="flex-1" />
            )}
          </div>

          {/* Label + Date */}
          <p
            className={cn(
              "mt-2 text-center text-xs font-medium",
              step.status === "upcoming" ? "text-muted-foreground" : "text-foreground",
            )}
          >
            {step.label}
          </p>
          {step.date && (
            <p className="mt-0.5 text-center text-[10px] text-muted-foreground">
              {step.date}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}
