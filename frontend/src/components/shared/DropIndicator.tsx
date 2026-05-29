import { Upload } from "lucide-react";
import { cn } from "@/lib/utils";

interface DropIndicatorProps {
  text: string;
  icon?: React.ComponentType<{ className?: string }>;
  variant?: "upload" | "move" | "invalid";
}

export function DropIndicator({ text, icon: Icon = Upload, variant = "upload" }: DropIndicatorProps) {
  const colors = {
    upload: "border-primary bg-primary/5 text-primary",
    move: "border-blue-500 bg-blue-500/5 text-blue-500",
    invalid: "border-destructive bg-destructive/5 text-destructive",
  };

  return (
    <div
      data-testid="drop-indicator"
      className={cn(
        "absolute inset-0 z-20 flex items-center justify-center rounded-lg border-2 border-dashed backdrop-blur-sm",
        colors[variant],
      )}
    >
      <div className="flex flex-col items-center gap-2">
        <Icon className="h-10 w-10" />
        <p className="text-sm font-medium">{text}</p>
      </div>
    </div>
  );
}
