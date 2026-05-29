import {
  FileText,
  MessageSquare,
  UserPlus,
  Ticket,
  Bell,
  Heart,
  MessageCircle,
  DollarSign,
  Share,
  CheckCheck,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { ActivityGroupItem } from "@/api/types";

interface ActivityGroupCardProps {
  item: ActivityGroupItem;
  onClick: () => void;
  onMarkRead: () => void;
}

export function ActivityGroupCard({ item, onClick, onMarkRead }: ActivityGroupCardProps) {
  const aggs = item.aggregations;

  return (
    <Card
      className={cn(
        "cursor-pointer hover:bg-accent/50 transition-colors",
        item.unread && "border-l-4 border-l-primary",
      )}
      onClick={onClick}
    >
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <ActivityIcon type={item.source_type} className="h-8 w-8 text-muted-foreground mt-0.5 shrink-0" />
          <div className="flex-1 min-w-0">
            <p className={cn("text-sm", item.unread && "font-semibold")}>{item.title}</p>
            <p className="text-xs text-muted-foreground mt-1">
              {formatRelativeTime(item.latest_ts)}
            </p>
            {/* Aggregation badges */}
            <div className="flex flex-wrap gap-2 mt-2">
              {aggs.post_liked && (
                <Badge variant="secondary" className="text-xs gap-1">
                  <Heart className="h-3 w-3" /> {aggs.post_liked.count}
                </Badge>
              )}
              {aggs.post_reaction && (
                <Badge variant="secondary" className="text-xs gap-1">
                  <Heart className="h-3 w-3" /> {aggs.post_reaction.count}
                </Badge>
              )}
              {aggs.post_comment && (
                <Badge variant="secondary" className="text-xs gap-1">
                  <MessageCircle className="h-3 w-3" /> {aggs.post_comment.count}
                </Badge>
              )}
              {aggs.post_tip && (
                <Badge variant="secondary" className="text-xs gap-1">
                  <DollarSign className="h-3 w-3" />
                  ${(aggs.post_tip.total_cents / 100).toFixed(2)}
                </Badge>
              )}
              {aggs.post_shared && (
                <Badge variant="secondary" className="text-xs gap-1">
                  <Share className="h-3 w-3" /> {aggs.post_shared.count}
                </Badge>
              )}
              {aggs.message_tip && (
                <Badge variant="secondary" className="text-xs gap-1">
                  <DollarSign className="h-3 w-3" />
                  ${(aggs.message_tip.total_cents / 100).toFixed(2)}
                </Badge>
              )}
              {aggs.new_follower && (
                <Badge variant="secondary" className="text-xs gap-1">
                  <UserPlus className="h-3 w-3" /> {aggs.new_follower.count}
                </Badge>
              )}
            </div>
          </div>
          {item.unread && (
            <Button
              variant="ghost"
              size="sm"
              className="shrink-0"
              onClick={(e) => {
                e.stopPropagation();
                onMarkRead();
              }}
            >
              <CheckCheck className="h-4 w-4" />
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function ActivityIcon({ type, className }: { type: string; className?: string }) {
  switch (type) {
    case "post":
      return <FileText className={className} />;
    case "message":
      return <MessageSquare className={className} />;
    case "follower":
      return <UserPlus className={className} />;
    case "ticket":
      return <Ticket className={className} />;
    default:
      return <Bell className={className} />;
  }
}

function formatRelativeTime(ts: number): string {
  const date = new Date(ts * 1000);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMin = Math.floor(diffMs / 60_000);

  if (diffMin < 1) return "Just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHrs = Math.floor(diffMin / 60);
  if (diffHrs < 24) return `${diffHrs}h ago`;
  const diffDays = Math.floor(diffHrs / 24);
  if (diffDays === 1) return "Yesterday";
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
