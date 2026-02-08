import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

// ─── Card Skeleton ──────────────────────────────────────────────

interface CardSkeletonProps {
  className?: string;
}

export function CardSkeleton({ className }: CardSkeletonProps) {
  return (
    <div className={cn("rounded-xl border border-border p-4 space-y-3", className)}>
      <Skeleton className="h-4 w-3/5" />
      <Skeleton className="h-3 w-full" />
      <Skeleton className="h-3 w-4/5" />
    </div>
  );
}

// ─── List Skeleton ──────────────────────────────────────────────

interface ListSkeletonProps {
  rows?: number;
  className?: string;
}

export function ListSkeleton({ rows = 5, className }: ListSkeletonProps) {
  return (
    <div className={cn("divide-y rounded-lg border", className)}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-3 px-4 py-3">
          <Skeleton className="h-8 w-8 shrink-0 rounded-full" />
          <div className="flex-1 space-y-1.5">
            <Skeleton className="h-3.5 w-2/5" />
            <Skeleton className="h-3 w-3/5" />
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Table Skeleton ─────────────────────────────────────────────

interface TableSkeletonProps {
  columns?: number;
  rows?: number;
  className?: string;
}

export function TableSkeleton({ columns = 4, rows = 5, className }: TableSkeletonProps) {
  return (
    <div className={cn("rounded-lg border", className)}>
      {/* Header */}
      <div className="flex gap-4 border-b bg-muted/50 px-4 py-3">
        {Array.from({ length: columns }).map((_, i) => (
          <Skeleton key={i} className="h-3.5 flex-1" />
        ))}
      </div>
      {/* Rows */}
      {Array.from({ length: rows }).map((_, ri) => (
        <div key={ri} className="flex gap-4 border-b px-4 py-3 last:border-b-0">
          {Array.from({ length: columns }).map((_, ci) => (
            <Skeleton key={ci} className="h-3 flex-1" />
          ))}
        </div>
      ))}
    </div>
  );
}

// ─── Form Skeleton ──────────────────────────────────────────────

interface FormSkeletonProps {
  fields?: number;
  className?: string;
}

export function FormSkeleton({ fields = 4, className }: FormSkeletonProps) {
  return (
    <div className={cn("space-y-6", className)}>
      {Array.from({ length: fields }).map((_, i) => (
        <div key={i} className="space-y-2">
          <Skeleton className="h-3.5 w-24" />
          <Skeleton className="h-9 w-full rounded-lg" />
        </div>
      ))}
      <Skeleton className="h-9 w-28 rounded-lg" />
    </div>
  );
}
