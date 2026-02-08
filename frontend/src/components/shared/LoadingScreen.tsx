import { Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

interface LoadingScreenProps {
  className?: string;
  message?: string;
}

export function LoadingScreen({ className, message }: LoadingScreenProps) {
  return (
    <div className={cn("flex flex-1 flex-col items-center justify-center gap-3 py-16", className)}>
      <Loader2 className="h-8 w-8 animate-spin text-primary" />
      {message && (
        <p className="text-sm text-muted-foreground">{message}</p>
      )}
    </div>
  );
}
