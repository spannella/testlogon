import { Activity, AlertTriangle, XCircle } from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

type Quality = "excellent" | "good" | "fair" | "poor" | "critical";

const QUALITY_CONFIG: Record<
  Quality,
  { color: string; icon: typeof Activity; label: string }
> = {
  excellent: { color: "text-green-500", icon: Activity, label: "Excellent" },
  good: { color: "text-green-400", icon: Activity, label: "Good" },
  fair: { color: "text-yellow-500", icon: AlertTriangle, label: "Fair" },
  poor: { color: "text-orange-500", icon: AlertTriangle, label: "Poor" },
  critical: { color: "text-red-500", icon: XCircle, label: "Critical" },
};

interface StreamHealthIndicatorProps {
  quality: Quality;
  bitrateKbps: number;
  droppedFramesPct: number;
  className?: string;
}

export function StreamHealthIndicator({
  quality,
  bitrateKbps,
  droppedFramesPct,
  className,
}: StreamHealthIndicatorProps) {
  const config = QUALITY_CONFIG[quality];
  const Icon = config.icon;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div className={`flex items-center gap-1 ${className ?? ""}`}>
          <Icon className={`h-4 w-4 ${config.color}`} />
          <span className={`text-sm font-medium ${config.color}`}>
            {config.label}
          </span>
        </div>
      </TooltipTrigger>
      <TooltipContent>
        <div className="text-xs space-y-1">
          <div>Bitrate: {bitrateKbps.toLocaleString()} kbps</div>
          <div>Dropped frames: {droppedFramesPct.toFixed(1)}%</div>
          <div>Quality: {quality}</div>
        </div>
      </TooltipContent>
    </Tooltip>
  );
}
