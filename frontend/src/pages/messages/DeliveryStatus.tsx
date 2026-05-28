import { Check, CheckCheck, Clock } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Message } from "@/api/types";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

interface DeliveryStatusProps {
  message: Message;
  isOwn: boolean;
}

export function DeliveryStatus({ message, isOwn }: DeliveryStatusProps) {
  if (!isOwn) return null;
  if (message.message_id.startsWith("optimistic-")) return null;
  if (message.scheduled) return null;

  const readCount = message.read_by_count ?? 0;
  const deliveredCount = message.delivered_to_count ?? 0;

  if (readCount > 0) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <CheckCheck className={cn("inline-block h-3.5 w-3.5 shrink-0 text-blue-400")} />
          </TooltipTrigger>
          <TooltipContent side="top" className="text-xs">
            Read{readCount > 1 ? ` by ${readCount}` : ""}
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  if (deliveredCount > 0) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <Check className="inline-block h-3.5 w-3.5 shrink-0 text-muted-foreground/60" />
          </TooltipTrigger>
          <TooltipContent side="top" className="text-xs">
            Delivered
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Clock className="inline-block h-3 w-3 shrink-0 text-muted-foreground/40" />
        </TooltipTrigger>
        <TooltipContent side="top" className="text-xs">
          Sending
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
