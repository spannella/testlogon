import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface KpiCardProps {
  label: string;
  value: string;
  trend?: "up" | "down" | "flat";
  delta?: string;
  className?: string;
}

export default function KpiCard({ label, value, trend, delta, className }: KpiCardProps) {
  return (
    <Card className={cn("flex flex-col justify-between", className)}>
      <CardContent className="p-4">
        <p className="text-sm text-muted-foreground">{label}</p>
        <p className="text-2xl font-bold mt-1">{value}</p>
        {delta && (
          <p
            className={cn(
              "text-xs mt-1",
              trend === "up" && "text-green-600",
              trend === "down" && "text-red-600",
              trend === "flat" && "text-muted-foreground"
            )}
          >
            {trend === "up" ? "+" : trend === "down" ? "-" : ""}
            {delta}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
