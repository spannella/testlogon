import { Users } from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface ViewerCountBadgeProps {
  count: number;
  className?: string;
}

export function ViewerCountBadge({ count, className }: ViewerCountBadgeProps) {
  return (
    <Badge variant="secondary" className={className}>
      <Users className="h-3 w-3 mr-1" />
      {count.toLocaleString()} {count === 1 ? "viewer" : "viewers"}
    </Badge>
  );
}
